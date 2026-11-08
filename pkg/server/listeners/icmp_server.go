package listeners

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
)

// ICMPServerListener provides an RFC 792 ICMP Echo Smuggling responder (Type 8 -> Type 0).
// Ingested chunk payloads are parsed in-memory and passed directly to ledger.AssembleChunk
// with ZERO disk writes.
type ICMPServerListener struct {
	mu       sync.Mutex
	bindAddr string
	ledger   server.Ledger
	conn     net.PacketConn
	cancel   context.CancelFunc
	closed   bool
	err      error
}

// NewICMPServerListener creates a new ICMP server listener instance.
func NewICMPServerListener(bindAddr string) *ICMPServerListener {
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	return &ICMPServerListener{
		bindAddr: bindAddr,
	}
}

func (l *ICMPServerListener) Name() string {
	return "icmp"
}

func (l *ICMPServerListener) Protocol() string {
	return common.ProtoICMPEcho
}

func (l *ICMPServerListener) Ports() []int {
	return []int{0}
}

// Start begins listening for ICMP Echo Requests on raw socket ip4:icmp.
// If raw socket access is denied (e.g. unprivileged user in containers/tests),
// it gracefully records the error without panicking, allowing in-process testing via ProcessPacket.
func (l *ICMPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	pConn, err := net.ListenPacket("ip4:icmp", l.bindAddr)
	if err != nil {
		// Detect permission errors cleanly
		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
			l.err = err
			return nil // Graceful: permit testing via ProcessPacket without root
		}
		return fmt.Errorf("failed to bind raw ICMP socket on %s: %w", l.bindAddr, err)
	}

	l.conn = pConn
	go l.listenLoop(ctx, pConn)
	return nil
}

// Stop cleanly terminates the ICMP server listener.
func (l *ICMPServerListener) Stop() error {
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

func (l *ICMPServerListener) listenLoop(ctx context.Context, pConn net.PacketConn) {
	buf := make([]byte, 65535)
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

		if n < 8 {
			continue
		}

		reply, procErr := l.ProcessPacket(buf[:n], src)
		if procErr == nil && len(reply) > 0 && src != nil {
			_, _ = pConn.WriteTo(reply, src)
		}
	}
}

// ProcessPacket unpacks an ICMP Echo Request, verifies CTRB Magic, dispatches payload to
// ledger.AssembleChunk (ZERO disk writes), and returns an RFC 792 Type 0 Echo Reply.
func (l *ICMPServerListener) ProcessPacket(pkt []byte, src net.Addr) ([]byte, error) {
	if len(pkt) < 8 {
		return nil, errors.New("packet too short for ICMP header")
	}

	pktType := pkt[0]
	if pktType != 8 { // Must be ICMP Echo Request
		return nil, fmt.Errorf("unexpected ICMP type %d (expected 8)", pktType)
	}

	payload := pkt[8:]

	// Extract and assemble chunk if ChunkHeader is present
	if len(payload) >= common.ChunkHeaderSize {
		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(payload[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
			chunkPayload := payload[common.ChunkHeaderSize:]
			if int(hdr.PayloadLen) <= len(chunkPayload) {
				chunkPayload = chunkPayload[:hdr.PayloadLen]
			}

			if l.ledger != nil {
				clientIP := ""
				if src != nil {
					if host, _, err := net.SplitHostPort(src.String()); err == nil {
						clientIP = host
					} else {
						clientIP = src.String()
					}
				}
				_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, chunkPayload, "", clientIP, common.ProtoICMPEcho, 0, clientIP, "")
			}
		}
	}

	// Construct matching ICMP Echo Reply (Type 0, Code 0, same ID and Sequence)
	reply := make([]byte, len(pkt))
	copy(reply, pkt)
	reply[0] = 0 // Type 0: Echo Reply
	reply[1] = 0 // Code 0
	reply[2] = 0 // Checksum high
	reply[3] = 0 // Checksum low

	cs := computeICMPChecksum(reply)
	binary.BigEndian.PutUint16(reply[2:4], cs)

	return reply, nil
}

func computeICMPChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i < length-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
