package listeners

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
	"golang.org/x/crypto/ssh"
)

// SFTPServerListener provides an in-memory SFTP server over SSH-2.
// Uploaded files are buffered in memory, parsed for 32-byte ChunkHeader, and assembled into ledger with zero disk writes.
type SFTPServerListener struct {
	mu          sync.Mutex
	bindAddr    string
	port        int
	boundPort   int
	hostKey     *certgen.SSHHostKey
	ledger      server.Ledger
	listener    net.Listener
	cancel      context.CancelFunc
	closed      bool
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewSFTPServerListener creates a new in-memory SFTP server listener.
func NewSFTPServerListener(bindAddr string, port int, hostKey *certgen.SSHHostKey) *SFTPServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	return &SFTPServerListener{
		bindAddr:    bindAddr,
		port:        port,
		hostKey:     hostKey,
		activeConns: make(map[net.Conn]struct{}),
	}
}

func (l *SFTPServerListener) Name() string {
	return "in_memory_sftp"
}

func (l *SFTPServerListener) Protocol() string {
	return common.ProtoSFTP
}

func (l *SFTPServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.boundPort > 0 {
		return []int{l.boundPort}
	}
	if l.port > 0 {
		return []int{l.port}
	}
	return nil
}

// BoundPort returns the actual bound port.
func (l *SFTPServerListener) BoundPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPort
}

// Start begins serving SFTP over SSH.
func (l *SFTPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("sftp server listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	// Ensure SSH host key
	if l.hostKey == nil {
		hk, err := certgen.GenerateSSHHostKey()
		if err != nil {
			return fmt.Errorf("failed to generate ssh host key: %w", err)
		}
		l.hostKey = hk
	}

	sshConfig := certgen.NewSSHServerConfig(l.hostKey, func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if l.ledger != nil {
			remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			_ = l.ledger.RecordCredential(common.CapturedCredential{
				Protocol:  common.ProtoSFTP,
				Timestamp: time.Now().UTC(),
				ClientIP:  remoteIP,
				Username:  conn.User(),
				HashType:  "plaintext",
				Hash:      string(password),
			})
		}
		if conn.User() == "reject" {
			return nil, errors.New("authentication rejected")
		}
		// Accept all credentials for assessment harvesting
		return nil, nil
	})

	addr := fmt.Sprintf("%s:%d", l.bindAddr, l.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		l.stopInternal()
		return fmt.Errorf("failed to bind sftp port %d: %w", l.port, err)
	}
	l.listener = ln
	l.boundPort = ln.Addr().(*net.TCPAddr).Port

	go l.serve(ln, sshConfig)
	return nil
}

func (l *SFTPServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *SFTPServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true

	if l.cancel != nil {
		l.cancel()
	}
	if l.listener != nil {
		_ = l.listener.Close()
	}

	l.connsMu.Lock()
	for c := range l.activeConns {
		_ = c.Close()
	}
	l.activeConns = make(map[net.Conn]struct{})
	l.connsMu.Unlock()

	return nil
}

func (l *SFTPServerListener) trackConn(c net.Conn) {
	l.connsMu.Lock()
	l.activeConns[c] = struct{}{}
	l.connsMu.Unlock()
}

func (l *SFTPServerListener) untrackConn(c net.Conn) {
	l.connsMu.Lock()
	delete(l.activeConns, c)
	l.connsMu.Unlock()
}

func (l *SFTPServerListener) serve(ln net.Listener, sshConfig *ssh.ServerConfig) {
	for {
		rawConn, err := ln.Accept()
		if err != nil {
			return
		}
		l.trackConn(rawConn)

		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				l.untrackConn(c)
			}()

			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			sshConn, chans, reqs, err := ssh.NewServerConn(c, sshConfig)
			_ = c.SetDeadline(time.Time{})
			if err != nil {
				return
			}
			defer sshConn.Close()

			go ssh.DiscardRequests(reqs)

			for newChan := range chans {
				if newChan.ChannelType() != "session" {
					_ = newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
					continue
				}

				ch, requests, err := newChan.Accept()
				if err != nil {
					continue
				}

				go func(in <-chan *ssh.Request, channel ssh.Channel) {
					for req := range in {
						if req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp" {
							_ = req.Reply(true, nil)

							clientIP := ""
							if rawConn != nil && rawConn.RemoteAddr() != nil {
								if host, _, err := net.SplitHostPort(rawConn.RemoteAddr().String()); err == nil {
									clientIP = host
								} else {
									clientIP = rawConn.RemoteAddr().String()
								}
							}
							handlers := sftp.InMemHandler()
							handlers.FilePut = &sftpLedgerWriter{ledger: l.ledger, clientIP: clientIP}

							server := sftp.NewRequestServer(channel, handlers)
							if err := server.Serve(); err == io.EOF {
								_ = server.Close()
							}
							return
						}
						_ = req.Reply(false, nil)
					}
				}(requests, ch)
			}
		}(rawConn)
	}
}

type sftpLedgerWriter struct {
	ledger   server.Ledger
	clientIP string
}

func (w *sftpLedgerWriter) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	return &inMemChunkWriter{ledger: w.ledger, clientIP: w.clientIP}, nil
}

type inMemChunkWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	ledger   server.Ledger
	clientIP string
}

func (cw *inMemChunkWriter) WriteAt(p []byte, off int64) (int, error) {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	needed := int(off) + len(p)
	if cw.buf.Len() < needed {
		diff := needed - cw.buf.Len()
		cw.buf.Write(make([]byte, diff))
	}
	b := cw.buf.Bytes()
	copy(b[off:], p)
	return len(p), nil
}

func (cw *inMemChunkWriter) Close() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	data := cw.buf.Bytes()
	if len(data) >= common.ChunkHeaderSize && cw.ledger != nil {
		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(data[:common.ChunkHeaderSize]); err == nil {
			payload := data[common.ChunkHeaderSize:]
			if int(hdr.PayloadLen) <= len(payload) {
				payload = payload[:hdr.PayloadLen]
			}
			_, _, _ = cw.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", cw.clientIP, common.ProtoSFTP, 22, cw.clientIP, "")
		}
	}
	return nil
}
