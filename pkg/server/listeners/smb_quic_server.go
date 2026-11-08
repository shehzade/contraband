package listeners

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// SMBQUICServerListener implements an in-memory MS-SMB2 over QUIC server listener (UDP 443 with ALPN "smb").
// In file transfer mode, chunks streamed over QUIC streams are processed in memory and passed
// directly to ledger.AssembleChunk with ZERO disk writes.
type SMBQUICServerListener struct {
	mu        sync.Mutex
	bindAddr  string
	port      int
	boundPort int
	tlsConfig *tls.Config
	ledger    server.Ledger
	listener  *quic.Listener
	cancel    context.CancelFunc
	closed    bool
}

// NewSMBQUICServerListener constructs a new SMB over QUIC server listener.
func NewSMBQUICServerListener(bindAddr string, port int, tlsConfig *tls.Config) *SMBQUICServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if port < 0 {
		port = 443
	}
	return &SMBQUICServerListener{
		bindAddr:  bindAddr,
		port:      port,
		tlsConfig: tlsConfig,
	}
}

func (l *SMBQUICServerListener) Name() string {
	return "smb_quic"
}

func (l *SMBQUICServerListener) Protocol() string {
	return common.ProtoSMBQUIC
}

func (l *SMBQUICServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.boundPort > 0 {
		return []int{l.boundPort}
	}
	return []int{l.port}
}

// BoundPort returns the actual bound UDP port.
func (l *SMBQUICServerListener) BoundPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPort
}

// Start begins listening for QUIC connections with ALPN "smb".
func (l *SMBQUICServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.listener != nil {
		return errors.New("smb_quic listener already started")
	}

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	tlsConf := l.tlsConfig
	if tlsConf == nil {
		genConf, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1", l.bindAddr}, nil)
		if err != nil {
			return fmt.Errorf("failed to generate TLS config for smb_quic: %w", err)
		}
		tlsConf = genConf
	}
	// Ensure ALPN includes "smb"
	tlsConf.NextProtos = []string{"smb"}

	quicConf := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}

	addrStr := fmt.Sprintf("%s:%d", l.bindAddr, l.port)
	ln, err := quic.ListenAddr(addrStr, tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to listen quic on %s: %w", addrStr, err)
	}

	l.listener = ln
	l.boundPort = ln.Addr().(*net.UDPAddr).Port

	go l.acceptLoop(ctx, ln)
	return nil
}

// Stop cleanly terminates the SMB over QUIC server listener.
func (l *SMBQUICServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}

func (l *SMBQUICServerListener) acceptLoop(ctx context.Context, ln *quic.Listener) {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if l.closed {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		go l.handleConn(ctx, conn)
	}
}

func (l *SMBQUICServerListener) handleConn(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		go l.handleStream(conn, stream)
	}
}

func (l *SMBQUICServerListener) handleStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()

	buf := make([]byte, 65536)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		data := buf[:n]

		// Check if it's raw SMB2 Negotiate Request (command 0x0000, len >= 64, magic 0xFE 'S' 'M' 'B')
		if len(data) >= 64 && data[0] == 0xFE && data[1] == 'S' && data[2] == 'M' && data[3] == 'B' {
			command := binary.LittleEndian.Uint16(data[12:14])
			messageID := binary.LittleEndian.Uint64(data[24:32])

			if command == 0x0000 { // Negotiate
				resp := l.buildNegotiateResponse(messageID)
				if _, err := stream.Write(resp); err != nil {
					return
				}

				if l.ledger != nil {
					clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
					res, _ := common.NewProbeResult("server", common.ProtoSMBQUIC, clientIP, l.boundPort)
					res.Verdict = common.VerdictSuccess
					_ = l.ledger.RecordProbe(res)
				}
				continue
			}
		}

		// Check if it's a chunk stream carrying 32-byte ChunkHeader (ZERO DISK WRITES)
		if len(data) >= common.ChunkHeaderSize && l.ledger != nil {
			var hdr common.ChunkHeader
			if err := hdr.UnmarshalBinary(data[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
				payload := data[common.ChunkHeaderSize:]
				if int(hdr.PayloadLen) <= len(payload) {
					payload = payload[:hdr.PayloadLen]
				}
				clientIP := ""
				if conn != nil && conn.RemoteAddr() != nil {
					if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
						clientIP = host
					} else {
						clientIP = conn.RemoteAddr().String()
					}
				}
				_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, common.ProtoSMBQUIC, 4430, clientIP, "")
				_, _ = stream.Write([]byte{0x06})
			}
		}
	}
}

func (l *SMBQUICServerListener) buildNegotiateResponse(messageID uint64) []byte {
	hdr := make([]byte, 64)
	hdr[0] = 0xFE
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)           // Status SUCCESS
	binary.LittleEndian.PutUint16(hdr[12:14], 0x0000)     // SMB2_NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[14:16], 1)          // CreditResponse
	binary.LittleEndian.PutUint32(hdr[16:20], 0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint64(hdr[24:32], messageID)

	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)
	binary.LittleEndian.PutUint16(body[2:4], 0x01)   // SecurityMode (Signing enabled)
	binary.LittleEndian.PutUint16(body[4:6], 0x0210) // DialectRevision (SMB 2.1)
	binary.LittleEndian.PutUint16(body[6:8], 1)
	copy(body[8:24], []byte("CONTRABANDSERVER"))
	binary.LittleEndian.PutUint32(body[24:28], 0x01)
	binary.LittleEndian.PutUint32(body[28:32], 65536)
	binary.LittleEndian.PutUint32(body[32:36], 65536)
	binary.LittleEndian.PutUint32(body[36:40], 65536)
	binary.LittleEndian.PutUint64(body[40:48], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(body[48:56], 0)
	binary.LittleEndian.PutUint16(body[56:58], 128)
	binary.LittleEndian.PutUint16(body[58:60], 0)
	binary.LittleEndian.PutUint32(body[60:64], 0)
	body[64] = 0

	return append(hdr, body...)
}
