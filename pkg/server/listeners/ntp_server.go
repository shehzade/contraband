package listeners

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
)

// NTPServerListener implements an in-memory RFC 5905 and RFC 7822 NTP server listener.
// Smuggled chunks are extracted from RFC 7822 extension fields (Type 0x4354) and passed directly
// to ledger.AssembleChunk with ZERO disk writes.
type NTPServerListener struct {
	mu        sync.Mutex
	bindAddr  string
	port      int
	boundPort int
	ledger    server.Ledger
	conn      net.PacketConn
	cancel    context.CancelFunc
	closed    bool
}

// NewNTPServerListener constructs a new NTP server listener.
func NewNTPServerListener(bindAddr string, port int) *NTPServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if port < 0 {
		port = 123
	}
	return &NTPServerListener{
		bindAddr: bindAddr,
		port:     port,
	}
}

func (l *NTPServerListener) Name() string {
	return "ntp"
}

func (l *NTPServerListener) Protocol() string {
	return common.ProtoNTPTime
}

func (l *NTPServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.boundPort > 0 {
		return []int{l.boundPort}
	}
	return []int{l.port}
}

// BoundPort returns the actual bound UDP port.
func (l *NTPServerListener) BoundPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPort
}

// Start begins listening for NTP requests on UDP.
func (l *NTPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.conn != nil {
		return errors.New("ntp listener already started")
	}

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	pConn, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", l.bindAddr, l.port))
	if err != nil {
		return fmt.Errorf("failed to bind ntp listener on %s:%d: %w", l.bindAddr, l.port, err)
	}

	l.conn = pConn
	l.boundPort = pConn.LocalAddr().(*net.UDPAddr).Port

	go l.listenLoop(ctx, pConn)
	return nil
}

// Stop cleanly terminates the NTP server listener.
func (l *NTPServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *NTPServerListener) listenLoop(ctx context.Context, pConn net.PacketConn) {
	buf := make([]byte, 2048)
	for {
		_ = pConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, src, err := pConn.ReadFrom(buf)
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

		if n < 48 {
			continue
		}

		data := buf[:n]

		// Inspect for RFC 7822 Extension Field (offset >= 48)
		if n >= 52 {
			offset := 48
			for offset+4 <= n {
				extType := binary.BigEndian.Uint16(data[offset : offset+2])
				extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
				if extLen < 4 || offset+extLen > n {
					break
				}

				if extType == 0x4354 { // CTRB extension field
					extValue := data[offset+4 : offset+extLen]
					if len(extValue) >= common.ChunkHeaderSize && l.ledger != nil {
						var hdr common.ChunkHeader
						if err := hdr.UnmarshalBinary(extValue[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
							payload := extValue[common.ChunkHeaderSize:]
							if int(hdr.PayloadLen) <= len(payload) {
								payload = payload[:hdr.PayloadLen]
							}
							clientIP := ""
							if src != nil {
								if host, _, err := net.SplitHostPort(src.String()); err == nil {
									clientIP = host
								} else {
									clientIP = src.String()
								}
							}
							_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, common.ProtoNTP, 123, clientIP, "")
						}
					}
				}
				offset += extLen
			}
		}

		// Build and send RFC 5905 Mode 4 Server reply
		reply := make([]byte, 48)
		reply[0] = 0x24 // LI=0, VN=4, Mode=4 (Server)
		reply[1] = 2    // Stratum 2
		reply[2] = 4    // Poll 16s
		reply[3] = 0xFA // Precision

		now := time.Now().UTC()
		secs := uint32(now.Unix() + 2208988800)
		frac := uint32(now.Nanosecond())

		// Reference Timestamp
		binary.BigEndian.PutUint32(reply[16:20], secs)
		binary.BigEndian.PutUint32(reply[20:24], frac)

		// Origin Timestamp: client's transmit timestamp (offset 40-48)
		copy(reply[24:32], data[40:48])

		// Receive Timestamp
		binary.BigEndian.PutUint32(reply[32:36], secs)
		binary.BigEndian.PutUint32(reply[36:40], frac)

		// Transmit Timestamp
		binary.BigEndian.PutUint32(reply[40:44], secs)
		binary.BigEndian.PutUint32(reply[44:48], frac)

		if src != nil {
			_, _ = pConn.WriteTo(reply, src)
		}
	}
}
