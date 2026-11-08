package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

type HTTP1Exfiltrator struct{}

func NewHTTP1Exfiltrator() *HTTP1Exfiltrator {
	return &HTTP1Exfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoHTTP1, NewHTTP1Exfiltrator())
	exfil.RegisterExfiltrator("http1", NewHTTP1Exfiltrator())
}

func (e *HTTP1Exfiltrator) Protocol() string {
	return common.ProtoHTTP1
}

func (e *HTTP1Exfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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
	targetURL := fmt.Sprintf("%s://%s:%d/upload", scheme, opts.TargetHost, opts.TargetPort)

	// Configure client and transport
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

	result.Timestamps.FirstByteSent = time.Now().UTC()
	var lastRespBody []byte
	var headEvidence []byte
	var tailEvidence []byte
	var totalPayloadBytes int64

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

		if len(chunkFrame) > common.ChunkHeaderSize {
			p := chunkFrame[common.ChunkHeaderSize:]
			totalPayloadBytes += int64(len(p))

			if len(headEvidence) < 768 {
				needed := 768 - len(headEvidence)
				if needed > len(p) {
					needed = len(p)
				}
				headEvidence = append(headEvidence, p[:needed]...)
			}

			if len(p) >= 256 {
				tailEvidence = append(tailEvidence[:0], p[len(p)-256:]...)
			} else {
				tailEvidence = append(tailEvidence, p...)
				if len(tailEvidence) > 256 {
					tailEvidence = tailEvidence[len(tailEvidence)-256:]
				}
			}
		}

		// Shaper pacing
		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
				result.Verdict = common.ClassifyError(err)
				result.ErrorMessage = err.Error()
				result.Timestamps.TeardownDone = time.Now().UTC()
				e.calculateDurations(&result)
				return &result, err
			}
		}

		// Cadence jitter
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

		var req *http.Request
		if opts.HTTPMode == "multipart" {
			req, err = e.createMultipartRequest(ctx, targetURL, opts, int(seq), totalChunks, chunkFrame)
		} else {
			req, err = e.createBinaryRequest(ctx, targetURL, opts, int(seq), totalChunks, chunkFrame)
		}
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = err.Error()
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}

		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = err.Error()
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}

		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		lastRespBody = respBody
		result.BytesSent += int64(len(chunkFrame))
		result.BytesRecv += int64(len(respBody))

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)

			var ack common.VerificationACK
			if jsonErr := json.Unmarshal(respBody, &ack); jsonErr == nil && ack.Verdict != "" {
				result.Verdict = ack.Verdict
				result.ErrorMessage = ack.ErrorMessage
			} else {
				result.Verdict = common.VerdictBlockedL7
				result.ErrorMessage = fmt.Sprintf("server returned status %d: %s", resp.StatusCode, string(respBody))
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
		result.ErrorMessage = fmt.Sprintf("failed to parse verification ACK: %v", err)
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

	result.RawEvidence = common.FormatBoundedRawEvidenceStream(headEvidence, tailEvidence, totalPayloadBytes)
	e.calculateDurations(&result)
	return &result, nil
}

func (e *HTTP1Exfiltrator) createBinaryRequest(ctx context.Context, url string, opts exfil.ExfilOptions, seq, total int, chunkFrame []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(chunkFrame))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(common.HeaderSessionID, opts.SessionToken.String())
	req.Header.Set(common.HeaderSequence, fmt.Sprintf("%d", seq))
	req.Header.Set(common.HeaderTotalChunks, fmt.Sprintf("%d", total))
	req.Header.Set(common.HeaderPayloadLength, fmt.Sprintf("%d", len(chunkFrame)-common.ChunkHeaderSize))
	req.Header.Set(common.HeaderPayloadHash, opts.ExpectedHash)
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (e *HTTP1Exfiltrator) createMultipartRequest(ctx context.Context, url string, opts exfil.ExfilOptions, seq, total int, chunkFrame []byte) (*http.Request, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("session_id", opts.SessionToken.String())
	_ = writer.WriteField("sequence", fmt.Sprintf("%d", seq))
	_ = writer.WriteField("total_chunks", fmt.Sprintf("%d", total))
	_ = writer.WriteField("payload_hash", opts.ExpectedHash)

	part, err := writer.CreateFormFile("file", "chunk.bin")
	if err != nil {
		return nil, err
	}

	payload := chunkFrame
	if len(chunkFrame) >= common.ChunkHeaderSize {
		payload = chunkFrame[common.ChunkHeaderSize:]
	}
	if _, err := part.Write(payload); err != nil {
		return nil, err
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	for k, v := range opts.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (e *HTTP1Exfiltrator) calculateDurations(r *common.ProbeResult) {
	t := &r.Timestamps
	if t.TeardownDone.IsZero() {
		t.TeardownDone = time.Now().UTC()
	}
	t.ComputeDurations()
	if t.TransferDuration > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(t.TransferDuration) / float64(time.Second)) / 1000.0
	}
}

// Ensure net import is retained
var _ net.Conn
