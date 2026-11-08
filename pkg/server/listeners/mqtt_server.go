package listeners

import (
	"context"
	"crypto/tls"
	"encoding/binary"
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

// MQTTServerListener implements an in-memory MQTT v3.1.1 broker listener
// supporting cleartext TCP (1883) and TLS (8883).
// Incoming chunks transported in PUBLISH payloads are processed in memory and passed directly
// to ledger.AssembleChunk with ZERO disk writes.
type MQTTServerListener struct {
	mu        sync.Mutex
	bindAddr  string
	tcpPort   int
	tlsPort   int
	boundTCP  int
	boundTLS  int
	tlsConfig *tls.Config
	ledger    server.Ledger

	tcpLn  net.Listener
	tlsLn  net.Listener
	cancel context.CancelFunc
	closed bool

	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewMQTTServerListener creates a new MQTT server listener instance.
func NewMQTTServerListener(bindAddr string, tcpPort, tlsPort int, tlsConfig *tls.Config) *MQTTServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if tcpPort < 0 && tlsPort < 0 {
		tcpPort = 1883
		tlsPort = 8883
	}
	return &MQTTServerListener{
		bindAddr:    bindAddr,
		tcpPort:     tcpPort,
		tlsPort:     tlsPort,
		tlsConfig:   tlsConfig,
		activeConns: make(map[net.Conn]struct{}),
	}
}

func (l *MQTTServerListener) Name() string {
	return "mqtt"
}

func (l *MQTTServerListener) Protocol() string {
	return common.ProtoMQTT
}

func (l *MQTTServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ports []int
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

// BoundPorts returns the actual bound TCP and TLS ports.
func (l *MQTTServerListener) BoundPorts() (tcp, tlsPort int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundTCP, l.boundTLS
}

// Start launches the TCP and TLS MQTT broker listeners.
func (l *MQTTServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.tcpLn != nil || l.tlsLn != nil {
		return errors.New("mqtt listener already started")
	}

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	if l.tcpPort >= 0 {
		tLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", l.bindAddr, l.tcpPort))
		if err == nil {
			l.tcpLn = tLn
			l.boundTCP = tLn.Addr().(*net.TCPAddr).Port
			go l.listenLoop(ctx, tLn)
		}
	}

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
				go l.listenLoop(ctx, tlsLn)
			}
		}
	}

	return nil
}

// Stop cleanly terminates all MQTT listeners.
func (l *MQTTServerListener) Stop() error {
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
		return fmt.Errorf("errors closing mqtt listeners: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (l *MQTTServerListener) listenLoop(ctx context.Context, ln net.Listener) {
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
			l.handleConn(c)
		}(conn)
	}
}

func (l *MQTTServerListener) handleConn(conn net.Conn) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var header [1]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}

		packetType := header[0] >> 4
		flags := header[0] & 0x0F

		// Read variable length remaining bytes
		remLen, err := decodeMQTTLength(conn)
		if err != nil || remLen < 0 || remLen > 1048576 {
			return
		}

		body := make([]byte, remLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}

		switch packetType {
		case 1: // CONNECT
			// Send CONNACK: 0x20, 0x02, 0x00, 0x00
			connack := []byte{0x20, 0x02, 0x00, 0x00}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(connack); err != nil {
				return
			}

		case 3: // PUBLISH
			qos := (flags >> 1) & 0x03
			offset := 0
			if len(body) < 2 {
				return
			}

			topicLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
			offset += 2
			if offset+topicLen > len(body) {
				return
			}
			offset += topicLen

			var packetID uint16
			if qos > 0 {
				if offset+2 > len(body) {
					return
				}
				packetID = binary.BigEndian.Uint16(body[offset : offset+2])
				offset += 2
			}

			payload := body[offset:]

			// ZERO DISK WRITES: Process payload in memory
			if len(payload) >= common.ChunkHeaderSize && l.ledger != nil {
				var hdr common.ChunkHeader
				if err := hdr.UnmarshalBinary(payload[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
					chunkPayload := payload[common.ChunkHeaderSize:]
					if int(hdr.PayloadLen) <= len(chunkPayload) {
						chunkPayload = chunkPayload[:hdr.PayloadLen]
					}
					clientIP := ""
					if conn != nil && conn.RemoteAddr() != nil {
						if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
							clientIP = host
						} else {
							clientIP = conn.RemoteAddr().String()
						}
					}
					_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, chunkPayload, "", clientIP, common.ProtoMQTT, 1883, clientIP, "")
				}
			}

			// If QoS == 1, send PUBACK
			if qos == 1 {
				puback := make([]byte, 4)
				puback[0] = 0x40 // PUBACK
				puback[1] = 0x02 // Remaining length
				binary.BigEndian.PutUint16(puback[2:4], packetID)
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := conn.Write(puback); err != nil {
					return
				}
			}

		case 12: // PINGREQ
			pingresp := []byte{0xD0, 0x00}
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write(pingresp); err != nil {
				return
			}

		case 14: // DISCONNECT
			return

		default:
			return
		}
	}
}

func decodeMQTTLength(r io.Reader) (int, error) {
	multiplier := 1
	value := 0
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return 0, err
		}
		digit := buf[0]
		value += int(digit&0x7F) * multiplier
		if (digit & 0x80) == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return 0, fmt.Errorf("malformed MQTT remaining length")
		}
	}
	return value, nil
}
