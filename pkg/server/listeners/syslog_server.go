package listeners

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// SyslogServerListener implements an in-memory RFC 5424 / RFC 6587 syslog server listener
// supporting UDP 514, TCP 514, and TLS 6514.
// Incoming log messages carrying base64-encoded chunks are parsed in memory and passed directly
// to ledger.AssembleChunk with ZERO disk writes.
type SyslogServerListener struct {
	mu        sync.Mutex
	bindAddr  string
	udpPort   int
	tcpPort   int
	tlsPort   int
	boundUDP  int
	boundTCP  int
	boundTLS  int
	tlsConfig *tls.Config
	ledger    server.Ledger

	udpConn net.PacketConn
	tcpLn   net.Listener
	tlsLn   net.Listener
	cancel  context.CancelFunc
	closed  bool

	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewSyslogServerListener constructs a multi-transport Syslog server listener.
func NewSyslogServerListener(bindAddr string, udpPort, tcpPort, tlsPort int, tlsConfig *tls.Config) *SyslogServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if udpPort < 0 && tcpPort < 0 && tlsPort < 0 {
		udpPort = 514
		tcpPort = 514
		tlsPort = 6514
	}
	return &SyslogServerListener{
		bindAddr:    bindAddr,
		udpPort:     udpPort,
		tcpPort:     tcpPort,
		tlsPort:     tlsPort,
		tlsConfig:   tlsConfig,
		activeConns: make(map[net.Conn]struct{}),
	}
}

func (l *SyslogServerListener) Name() string {
	return "syslog"
}

func (l *SyslogServerListener) Protocol() string {
	return common.ProtoSyslog
}

func (l *SyslogServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ports []int
	if l.boundUDP > 0 {
		ports = append(ports, l.boundUDP)
	} else if l.udpPort > 0 {
		ports = append(ports, l.udpPort)
	}
	if l.boundTCP > 0 {
		ports = append(ports, l.boundTCP)
	} else if l.tcpPort > 0 {
		ports = append(ports, l.tcpPort)
	}
	if l.boundTLS > 0 {
		ports = append(ports, l.boundTLS)
	} else if l.tlsPort > 0 {
		ports = append(ports, l.tlsPort)
	}
	return ports
}

// BoundPorts returns the actual bound UDP, TCP, and TLS ports.
func (l *SyslogServerListener) BoundPorts() (udp, tcp, tlsPort int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundUDP, l.boundTCP, l.boundTLS
}

// Start launches the UDP, TCP, and TLS syslog listeners.
func (l *SyslogServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.udpConn != nil || l.tcpLn != nil || l.tlsLn != nil {
		return errors.New("syslog listener already started")
	}

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	// Start UDP
	if l.udpPort >= 0 {
		uConn, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", l.bindAddr, l.udpPort))
		if err == nil {
			l.udpConn = uConn
			l.boundUDP = uConn.LocalAddr().(*net.UDPAddr).Port
			go l.listenUDP(ctx, uConn)
		}
	}

	// Start TCP
	if l.tcpPort >= 0 {
		tLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", l.bindAddr, l.tcpPort))
		if err == nil {
			l.tcpLn = tLn
			l.boundTCP = tLn.Addr().(*net.TCPAddr).Port
			go l.listenTCP(ctx, tLn)
		}
	}

	// Start TLS
	if l.tlsPort >= 0 {
		tlsConf := l.tlsConfig
		if tlsConf == nil {
			genConf, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1", l.bindAddr}, nil)
			if err == nil {
				tlsConf = genConf
			}
		}
		if tlsConf != nil {
			tlsLn, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", l.bindAddr, l.tlsPort), tlsConf)
			if err == nil {
				l.tlsLn = tlsLn
				l.boundTLS = tlsLn.Addr().(*net.TCPAddr).Port
				go l.listenTCP(ctx, tlsLn)
			}
		}
	}

	return nil
}

// Stop cleanly terminates all syslog transport listeners.
func (l *SyslogServerListener) Stop() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}

	var errs []string
	if l.udpConn != nil {
		if err := l.udpConn.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if l.tcpLn != nil {
		if err := l.tcpLn.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if l.tlsLn != nil {
		if err := l.tlsLn.Close(); err != nil {
			errs = append(errs, err.Error())
		}
	}
	l.mu.Unlock()

	l.connsMu.Lock()
	for c := range l.activeConns {
		_ = c.Close()
	}
	l.activeConns = make(map[net.Conn]struct{})
	l.connsMu.Unlock()

	if len(errs) > 0 {
		return fmt.Errorf("errors closing syslog listeners: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (l *SyslogServerListener) listenUDP(ctx context.Context, uConn net.PacketConn) {
	buf := make([]byte, 65536)
	for {
		_ = uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, src, err := uConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if l.closed {
					return
				}
				continue
			}
		}

		if n > 0 {
			clientIP := ""
			if src != nil {
				if host, _, err := net.SplitHostPort(src.String()); err == nil {
					clientIP = host
				} else {
					clientIP = src.String()
				}
			}
			l.parseMessage(string(buf[:n]), clientIP)
		}
	}
}

func (l *SyslogServerListener) listenTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
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

		l.connsMu.Lock()
		l.activeConns[conn] = struct{}{}
		l.connsMu.Unlock()

		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				l.connsMu.Lock()
				delete(l.activeConns, c)
				l.connsMu.Unlock()
			}()
			l.handleTCPConn(c)
		}(conn)
	}
}

func (l *SyslogServerListener) handleTCPConn(conn net.Conn) {
	clientIP := ""
	if conn != nil && conn.RemoteAddr() != nil {
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
			clientIP = host
		} else {
			clientIP = conn.RemoteAddr().String()
		}
	}

	reader := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Check for RFC 6587 octet counting: <length> <message>
		prefix, err := reader.Peek(10)
		if err != nil && err != io.EOF && len(prefix) == 0 {
			return
		}

		prefixStr := string(prefix)
		spaceIdx := strings.IndexByte(prefixStr, ' ')
		if spaceIdx > 0 {
			msgLen, parseErr := strconv.Atoi(prefixStr[:spaceIdx])
			if parseErr == nil && msgLen > 0 && msgLen < 1048576 {
				// Discard length and space
				_, _ = reader.Discard(spaceIdx + 1)
				msgBuf := make([]byte, msgLen)
				if _, readErr := io.ReadFull(reader, msgBuf); readErr != nil {
					return
				}
				l.parseMessage(string(msgBuf), clientIP)
				continue
			}
		}

		// Fallback: Read line-by-line
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			l.parseMessage(strings.TrimRight(line, "\r\n"), clientIP)
		}
		if readErr != nil {
			return
		}
	}
}

func (l *SyslogServerListener) parseMessage(msg, clientIP string) {
	msg = strings.TrimSpace(msg)
	if len(msg) == 0 {
		return
	}

	// Look for structured data closing bracket ']'
	bracketIdx := strings.Index(msg, "]")
	if bracketIdx == -1 {
		return
	}

	// The remainder after ']' is the base64 encoded chunk payload
	b64Payload := strings.TrimSpace(msg[bracketIdx+1:])
	if len(b64Payload) == 0 {
		return
	}

	chunkBytes, err := base64.StdEncoding.DecodeString(b64Payload)
	if err != nil || len(chunkBytes) < common.ChunkHeaderSize {
		return
	}

	// ZERO DISK WRITES: Process directly in memory
	var hdr common.ChunkHeader
	if err := hdr.UnmarshalBinary(chunkBytes[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
		payload := chunkBytes[common.ChunkHeaderSize:]
		if int(hdr.PayloadLen) <= len(payload) {
			payload = payload[:hdr.PayloadLen]
		}
		if l.ledger != nil {
			_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, common.ProtoSyslog, 514, clientIP, "")
		}
	}
}
