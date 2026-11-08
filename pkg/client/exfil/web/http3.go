package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

type HTTP3Exfiltrator struct{}

func NewHTTP3Exfiltrator() *HTTP3Exfiltrator {
	return &HTTP3Exfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoHTTP3, NewHTTP3Exfiltrator())
	exfil.RegisterExfiltrator("http3", NewHTTP3Exfiltrator())
}

func (e *HTTP3Exfiltrator) Protocol() string {
	return common.ProtoHTTP3
}

func (e *HTTP3Exfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.InsecureTLS,
			ServerName:         opts.TargetHost,
		},
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: opts.Timeout}
	targetURL := fmt.Sprintf("https://%s:%d/upload", opts.TargetHost, opts.TargetPort)

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.HandshakeTLS = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

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

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(chunkFrame))
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = err.Error()
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set(common.HeaderSessionID, opts.SessionToken.String())
		req.Header.Set(common.HeaderSequence, fmt.Sprintf("%d", seq))
		req.Header.Set(common.HeaderTotalChunks, fmt.Sprintf("%d", totalChunks))
		req.Header.Set(common.HeaderPayloadLength, fmt.Sprintf("%d", len(chunkFrame)-common.ChunkHeaderSize))
		req.Header.Set(common.HeaderPayloadHash, opts.ExpectedHash)

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

	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	e.calculateDurations(&result)
	return &result, nil
}

func (e *HTTP3Exfiltrator) calculateDurations(r *common.ProbeResult) {
	t := &r.Timestamps
	if t.TeardownDone.IsZero() {
		t.TeardownDone = time.Now().UTC()
	}
	t.ComputeDurations()
	if t.TransferDuration > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(t.TransferDuration) / float64(time.Second)) / 1000.0
	}
}
