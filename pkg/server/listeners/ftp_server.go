package listeners

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// FTPServerListener provides a pure-Go in-memory RFC 959 and RFC 4217 FTP/FTPS server.
// Uploaded file streams are buffered in-memory, unpacked, and passed to ledger.AssembleChunk with zero disk writes.
type FTPServerListener struct {
	mu            sync.Mutex
	bindAddr      string
	plainPort     int
	implicitPort  int
	boundPlain    int
	boundImplicit int
	tlsConfig     *tls.Config
	ledger        server.Ledger

	plainLn     net.Listener
	implicitLn  net.Listener
	cancel      context.CancelFunc
	closed      bool
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewFTPServerListener creates a new in-memory FTP and FTPS server listener.
func NewFTPServerListener(bindAddr string, plainPort, implicitPort int, tlsConfig *tls.Config) *FTPServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	return &FTPServerListener{
		bindAddr:     bindAddr,
		plainPort:    plainPort,
		implicitPort: implicitPort,
		tlsConfig:    tlsConfig,
		activeConns:  make(map[net.Conn]struct{}),
	}
}

func (l *FTPServerListener) Name() string {
	return "in_memory_ftp"
}

func (l *FTPServerListener) Protocol() string {
	return common.ProtoFTP
}

func (l *FTPServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ports []int
	if l.boundPlain > 0 {
		ports = append(ports, l.boundPlain)
	} else if l.plainPort > 0 {
		ports = append(ports, l.plainPort)
	}
	if l.boundImplicit > 0 {
		ports = append(ports, l.boundImplicit)
	} else if l.implicitPort > 0 {
		ports = append(ports, l.implicitPort)
	}
	return ports
}

// BoundPorts returns bound plain and implicit FTPS ports.
func (l *FTPServerListener) BoundPorts() (plain, implicit int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPlain, l.boundImplicit
}

// Start initiates the FTP and FTPS listeners.
func (l *FTPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("ftp server listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	if (l.plainPort >= 0 || l.implicitPort >= 0) && l.tlsConfig == nil {
		tlsCfg, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1", l.bindAddr}, nil)
		if err != nil {
			return fmt.Errorf("failed to generate tls config for ftp: %w", err)
		}
		l.tlsConfig = tlsCfg
	}

	// 1. Plain/Explicit FTP listener
	if l.plainPort >= 0 {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, l.plainPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind plain ftp port %d: %w", l.plainPort, err)
		}
		l.plainLn = ln
		l.boundPlain = ln.Addr().(*net.TCPAddr).Port

		go l.serve(ln, false)
	}

	// 2. Implicit FTPS listener (port 990)
	if l.implicitPort >= 0 && l.tlsConfig != nil {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, l.implicitPort)
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind implicit ftps port %d: %w", l.implicitPort, err)
		}
		tlsLn := tls.NewListener(rawLn, l.tlsConfig)
		l.implicitLn = tlsLn
		l.boundImplicit = rawLn.Addr().(*net.TCPAddr).Port

		go l.serve(tlsLn, true)
	}

	return nil
}

func (l *FTPServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *FTPServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true

	if l.cancel != nil {
		l.cancel()
	}
	if l.plainLn != nil {
		_ = l.plainLn.Close()
	}
	if l.implicitLn != nil {
		_ = l.implicitLn.Close()
	}

	l.connsMu.Lock()
	for c := range l.activeConns {
		_ = c.Close()
	}
	l.activeConns = make(map[net.Conn]struct{})
	l.connsMu.Unlock()

	return nil
}

func (l *FTPServerListener) trackConn(c net.Conn) {
	l.connsMu.Lock()
	l.activeConns[c] = struct{}{}
	l.connsMu.Unlock()
}

func (l *FTPServerListener) untrackConn(c net.Conn) {
	l.connsMu.Lock()
	delete(l.activeConns, c)
	l.connsMu.Unlock()
}

func (l *FTPServerListener) serve(ln net.Listener, isImplicitTLS bool) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		l.trackConn(conn)
		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				l.untrackConn(c)
			}()
			l.handleSession(c, isImplicitTLS)
		}(conn)
	}
}

type ftpSession struct {
	username      string
	authenticated bool
	dataProtected bool
	isTLS         bool
	pasvListener  net.Listener
	pasvMu        sync.Mutex
	clientIP      string
}

func (l *FTPServerListener) handleSession(conn net.Conn, isImplicitTLS bool) {
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sess := &ftpSession{
		isTLS:    isImplicitTLS,
		clientIP: remoteIP,
	}
	defer func() {
		sess.pasvMu.Lock()
		if sess.pasvListener != nil {
			_ = sess.pasvListener.Close()
			sess.pasvListener = nil
		}
		sess.pasvMu.Unlock()
	}()

	currentConn := conn
	reader := bufio.NewReader(currentConn)

	// Send initial greeting
	_, _ = fmt.Fprintf(currentConn, "220 Contraband In-Memory FTP Server Ready\r\n")

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimRight(line, "\r\n")
		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}

		switch cmd {
		case "AUTH":
			if strings.EqualFold(arg, "TLS") || strings.EqualFold(arg, "SSL") {
				if l.tlsConfig != nil {
					_, _ = fmt.Fprintf(currentConn, "234 Enabling TLS Connection\r\n")
					tlsConn := tls.Server(currentConn, l.tlsConfig)
					if err := tlsConn.Handshake(); err != nil {
						return
					}
					currentConn = tlsConn
					reader = bufio.NewReader(currentConn)
					sess.isTLS = true
				} else {
					_, _ = fmt.Fprintf(currentConn, "502 TLS not supported\r\n")
				}
			} else {
				_, _ = fmt.Fprintf(currentConn, "504 Unknown AUTH type\r\n")
			}

		case "PBSZ":
			_, _ = fmt.Fprintf(currentConn, "200 PBSZ=0 successful\r\n")

		case "PROT":
			if strings.EqualFold(arg, "P") {
				sess.dataProtected = true
				_, _ = fmt.Fprintf(currentConn, "200 Protection level set to P\r\n")
			} else {
				sess.dataProtected = false
				_, _ = fmt.Fprintf(currentConn, "200 Protection level set to C\r\n")
			}

		case "USER":
			sess.username = arg
			_, _ = fmt.Fprintf(currentConn, "331 User name okay, need password\r\n")

		case "PASS":
			if l.ledger != nil {
				_ = l.ledger.RecordCredential(common.CapturedCredential{
					Protocol:  common.ProtoFTP,
					Timestamp: time.Now().UTC(),
					ClientIP:  sess.clientIP,
					Username:  sess.username,
					HashType:  "plaintext",
					Hash:      arg,
				})
			}
			if sess.username == "reject" {
				sess.authenticated = false
				_, _ = fmt.Fprintf(currentConn, "530 User cannot log in\r\n")
			} else {
				sess.authenticated = true
				_, _ = fmt.Fprintf(currentConn, "230 User logged in, proceed\r\n")
			}

		case "TYPE":
			_, _ = fmt.Fprintf(currentConn, "200 Type set to %s\r\n", arg)

		case "FEAT":
			_, _ = fmt.Fprintf(currentConn, "211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n EPSV\r\n PASV\r\n211 End\r\n")

		case "SYST":
			_, _ = fmt.Fprintf(currentConn, "215 UNIX Type: L8\r\n")

		case "PWD":
			_, _ = fmt.Fprintf(currentConn, "257 \"/\"\r\n")

		case "CWD":
			_, _ = fmt.Fprintf(currentConn, "250 Directory changed\r\n")

		case "NOOP":
			_, _ = fmt.Fprintf(currentConn, "200 OK\r\n")

		case "PASV":
			sess.pasvMu.Lock()
			if sess.pasvListener != nil {
				_ = sess.pasvListener.Close()
			}
			pasvLn, err := net.Listen("tcp", fmt.Sprintf("%s:0", l.bindAddr))
			if err != nil {
				sess.pasvMu.Unlock()
				_, _ = fmt.Fprintf(currentConn, "425 Cannot open data connection\r\n")
				continue
			}
			sess.pasvListener = pasvLn
			sess.pasvMu.Unlock()

			port := pasvLn.Addr().(*net.TCPAddr).Port
			p1 := port / 256
			p2 := port % 256

			// Use 127,0,0,1 or listener bind IP
			listenIP := l.bindAddr
			if listenIP == "0.0.0.0" || listenIP == "" {
				listenIP = "127.0.0.1"
			}
			ipParts := strings.ReplaceAll(listenIP, ".", ",")
			_, _ = fmt.Fprintf(currentConn, "227 Entering Passive Mode (%s,%d,%d)\r\n", ipParts, p1, p2)

		case "EPSV":
			sess.pasvMu.Lock()
			if sess.pasvListener != nil {
				_ = sess.pasvListener.Close()
			}
			pasvLn, err := net.Listen("tcp", fmt.Sprintf("%s:0", l.bindAddr))
			if err != nil {
				sess.pasvMu.Unlock()
				_, _ = fmt.Fprintf(currentConn, "425 Cannot open data connection\r\n")
				continue
			}
			sess.pasvListener = pasvLn
			sess.pasvMu.Unlock()

			port := pasvLn.Addr().(*net.TCPAddr).Port
			_, _ = fmt.Fprintf(currentConn, "229 Entering Extended Passive Mode (|||%d|)\r\n", port)

		case "STOR":
			sess.pasvMu.Lock()
			pasvLn := sess.pasvListener
			sess.pasvListener = nil
			sess.pasvMu.Unlock()

			if pasvLn == nil {
				_, _ = fmt.Fprintf(currentConn, "425 Use PASV or EPSV first\r\n")
				continue
			}

			_, _ = fmt.Fprintf(currentConn, "150 Opening BINARY mode data connection for %s\r\n", arg)

			// Accept data connection
			dataConn, err := pasvLn.Accept()
			_ = pasvLn.Close()
			if err != nil {
				_, _ = fmt.Fprintf(currentConn, "425 Failed to accept data connection: %v\r\n", err)
				continue
			}

			// If data connection is protected with TLS, wrap it
			var dataReader io.Reader = dataConn
			if sess.dataProtected && l.tlsConfig != nil {
				tlsDataConn := tls.Server(dataConn, l.tlsConfig)
				if err := tlsDataConn.Handshake(); err == nil {
					dataReader = tlsDataConn
				}
			}

			// Read incoming file chunk bounded to 4MB ceiling
			const maxFTPChunk = 4 * 1024 * 1024
			buf, readErr := io.ReadAll(io.LimitReader(dataReader, maxFTPChunk+1))
			_ = dataConn.Close()

			if readErr != nil || len(buf) > maxFTPChunk {
				_, _ = fmt.Fprintf(currentConn, "426 Connection closed; transfer aborted\r\n")
				continue
			}

			// Unmarshal 32-byte ChunkHeader and dispatch directly to ledger
			if len(buf) >= common.ChunkHeaderSize && l.ledger != nil {
				var hdr common.ChunkHeader
				if err := hdr.UnmarshalBinary(buf[:common.ChunkHeaderSize]); err == nil {
					payload := buf[common.ChunkHeaderSize:]
					if int(hdr.PayloadLen) <= len(payload) {
						payload = payload[:hdr.PayloadLen]
					}
					clientIP := ""
					port := 21
					protoName := common.ProtoFTP
					if sess.isTLS {
						port = 990
						protoName = common.ProtoFTPS
					}
					if currentConn != nil && currentConn.RemoteAddr() != nil {
						if host, _, err := net.SplitHostPort(currentConn.RemoteAddr().String()); err == nil {
							clientIP = host
						} else {
							clientIP = currentConn.RemoteAddr().String()
						}
					}
					_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, protoName, port, clientIP, "")
				}
			}

			_, _ = fmt.Fprintf(currentConn, "226 Transfer complete\r\n")

		case "QUIT":
			_, _ = fmt.Fprintf(currentConn, "221 Goodbye\r\n")
			return

		default:
			_, _ = fmt.Fprintf(currentConn, "500 Unknown command\r\n")
		}
	}
}
