package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

var (
	ntlmSignature = []byte("NTLMSSP\x00")

	ErrInvalidNTLMSignature   = errors.New("invalid NTLMSSP signature")
	ErrInvalidNTLMMessageType = errors.New("invalid NTLM message type")
	ErrNTLMPayloadTruncated   = errors.New("truncated NTLM message payload")
)

const (
	NTLMType1MessageType = 1
	NTLMType2MessageType = 2
	NTLMType3MessageType = 3

	// Negotiate Flags
	NegotiateUnicode                 uint32 = 0x00000001
	NegotiateOEM                     uint32 = 0x00000002
	RequestTarget                    uint32 = 0x00000004
	NegotiateNTLM                    uint32 = 0x00000200
	NegotiateAlwaysSign              uint32 = 0x00008000
	NegotiateExtendedSessionSecurity uint32 = 0x00080000
	NegotiateTargetInfo              uint32 = 0x00800000
	Negotiate128                     uint32 = 0x20000000
	NegotiateKeyExch                 uint32 = 0x40000000
	Negotiate56                      uint32 = 0x80000000
)

// NTLMType2 represents a parsed Type 2 Challenge message.
type NTLMType2 struct {
	Flags           uint32
	ServerChallenge [8]byte
	TargetName      string
	TargetInfo      []byte
	Timestamp       uint64
	HasTimestamp    bool
}

// encodeUTF16LE converts a string to a UTF-16LE byte slice.
func encodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// decodeUTF16LE converts a UTF-16LE byte slice to string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

// BuildNTLMType1 generates a base64-encoded NTLM Type 1 Negotiate payload.
func BuildNTLMType1(domain, workstation string) string {
	// Standard 32-byte header with optional flags
	flags := NegotiateUnicode | RequestTarget | NegotiateNTLM |
		NegotiateExtendedSessionSecurity | NegotiateTargetInfo | Negotiate128

	var buf bytes.Buffer
	buf.Write(ntlmSignature)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(NTLMType1MessageType))
	_ = binary.Write(&buf, binary.LittleEndian, flags)

	// Supplied Domain security buffer: Len=0, Alloc=0, Offset=32
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(32))

	// Supplied Workstation security buffer: Len=0, Alloc=0, Offset=32
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(32))

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// ParseNTLMType2 decodes and parses an NTLM Type 2 Challenge from base64.
func ParseNTLMType2(rawB64 string) (*NTLMType2, error) {
	rawB64 = strings.TrimSpace(rawB64)
	if strings.HasPrefix(strings.ToLower(rawB64), "ntlm ") {
		rawB64 = strings.TrimSpace(rawB64[5:])
	}

	data, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NTLM Type 2 base64: %w", err)
	}

	if len(data) < 32 {
		return nil, ErrNTLMPayloadTruncated
	}

	if !bytes.Equal(data[:8], ntlmSignature) {
		return nil, ErrInvalidNTLMSignature
	}

	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != NTLMType2MessageType {
		return nil, fmt.Errorf("%w: expected 2, got %d", ErrInvalidNTLMMessageType, msgType)
	}

	t2 := &NTLMType2{}

	targetNameLen := binary.LittleEndian.Uint16(data[12:14])
	targetNameOffset := binary.LittleEndian.Uint32(data[16:20])

	t2.Flags = binary.LittleEndian.Uint32(data[20:24])
	copy(t2.ServerChallenge[:], data[24:32])

	if targetNameLen > 0 && int(targetNameOffset)+int(targetNameLen) <= len(data) {
		nameBytes := data[targetNameOffset : targetNameOffset+uint32(targetNameLen)]
		if t2.Flags&NegotiateUnicode != 0 {
			t2.TargetName = decodeUTF16LE(nameBytes)
		} else {
			t2.TargetName = string(nameBytes)
		}
	}

	// TargetInfo SecurityBuffer is at offset 40 (if message is at least 48 bytes)
	if len(data) >= 48 {
		targetInfoLen := binary.LittleEndian.Uint16(data[40:42])
		targetInfoOffset := binary.LittleEndian.Uint32(data[44:48])

		if targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(data) {
			t2.TargetInfo = make([]byte, targetInfoLen)
			copy(t2.TargetInfo, data[targetInfoOffset:targetInfoOffset+uint32(targetInfoLen)])

			// Scan AV_PAIRS for timestamp (0x0007)
			pos := 0
			for pos+4 <= len(t2.TargetInfo) {
				avID := binary.LittleEndian.Uint16(t2.TargetInfo[pos : pos+2])
				avLen := binary.LittleEndian.Uint16(t2.TargetInfo[pos+2 : pos+4])
				pos += 4
				if avID == 0 { // MsvAvEOL
					break
				}
				if avID == 0x0007 && avLen == 8 && pos+8 <= len(t2.TargetInfo) {
					t2.Timestamp = binary.LittleEndian.Uint64(t2.TargetInfo[pos : pos+8])
					t2.HasTimestamp = true
				}
				pos += int(avLen)
			}
		}
	}

	return t2, nil
}

// ComputeNTHash computes MD4(UTF16LE(password)).
func ComputeNTHash(password string) []byte {
	h := md4.New()
	h.Write(encodeUTF16LE(password))
	return h.Sum(nil)
}

// ComputeNTLMv2Hash computes HMAC-MD5(NT_Hash, UTF16LE(ToUpper(username)) + UTF16LE(domain)).
func ComputeNTLMv2Hash(username, password, domain string) []byte {
	ntHash := ComputeNTHash(password)
	mac := hmac.New(md5.New, ntHash)
	mac.Write(encodeUTF16LE(strings.ToUpper(username)))
	mac.Write(encodeUTF16LE(domain))
	return mac.Sum(nil)
}

// ComputeClientBlob creates the client blob (temp structure) for NTLMv2.
func ComputeClientBlob(timestamp uint64, clientNonce []byte, targetInfo []byte) []byte {
	var buf bytes.Buffer
	// Header: 0x01010000 (RespType: uint8=1, HiRespType: uint8=1, Reserved: uint16=0)
	buf.Write([]byte{0x01, 0x01, 0x00, 0x00})
	// Reserved: 4 bytes zeros
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// Timestamp: uint64 little endian
	_ = binary.Write(&buf, binary.LittleEndian, timestamp)
	// Client Nonce: 8 bytes
	if len(clientNonce) >= 8 {
		buf.Write(clientNonce[:8])
	} else {
		padded := make([]byte, 8)
		copy(padded, clientNonce)
		buf.Write(padded)
	}
	// Reserved: 4 bytes zeros
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})
	// TargetInfo (from Type 2)
	if len(targetInfo) > 0 {
		buf.Write(targetInfo)
	}
	// Final Reserved: 4 bytes zeros
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00})

	return buf.Bytes()
}

// ComputeNTProof computes HMAC-MD5(NTLMv2_Hash, ServerChallenge + ClientBlob).
func ComputeNTProof(ntlmv2Hash, serverChallenge, clientBlob []byte) []byte {
	mac := hmac.New(md5.New, ntlmv2Hash)
	mac.Write(serverChallenge)
	mac.Write(clientBlob)
	return mac.Sum(nil)
}

// ComputeLMv2Response computes HMAC-MD5(NTLMv2_Hash, ServerChallenge + ClientNonce) + ClientNonce.
func ComputeLMv2Response(ntlmv2Hash, serverChallenge, clientNonce []byte) []byte {
	nonce := make([]byte, 8)
	if len(clientNonce) >= 8 {
		copy(nonce, clientNonce[:8])
	}
	mac := hmac.New(md5.New, ntlmv2Hash)
	mac.Write(serverChallenge)
	mac.Write(nonce)
	proof := mac.Sum(nil)
	return append(proof, nonce...)
}

// BuildNTLMType3 constructs the base64-encoded NTLM Type 3 Authenticate message.
func BuildNTLMType3(username, password, domain, workstation string, challenge *NTLMType2, clientNonce []byte) (string, error) {
	if challenge == nil {
		return "", errors.New("nil NTLM Type 2 challenge")
	}

	if len(clientNonce) < 8 {
		clientNonce = make([]byte, 8)
		if _, err := rand.Read(clientNonce); err != nil {
			return "", fmt.Errorf("failed to generate random client nonce: %w", err)
		}
	}

	timestamp := challenge.Timestamp
	if !challenge.HasTimestamp || timestamp == 0 {
		// Windows FILETIME: 100ns increments since Jan 1, 1601
		timestamp = uint64((time.Now().UnixNano() / 100) + 116444736000000000)
	}

	ntlmv2Hash := ComputeNTLMv2Hash(username, password, domain)
	clientBlob := ComputeClientBlob(timestamp, clientNonce, challenge.TargetInfo)
	ntProof := ComputeNTProof(ntlmv2Hash, challenge.ServerChallenge[:], clientBlob)
	ntChallengeResponse := append(ntProof, clientBlob...)
	lmChallengeResponse := ComputeLMv2Response(ntlmv2Hash, challenge.ServerChallenge[:], clientNonce)

	domainBytes := encodeUTF16LE(domain)
	userBytes := encodeUTF16LE(username)
	workstationBytes := encodeUTF16LE(workstation)

	// Fixed header length is 64 bytes (excluding SessionKey payload and OS Version)
	headerLen := uint32(64)
	offset := headerLen

	lmOffset := offset
	offset += uint32(len(lmChallengeResponse))

	ntOffset := offset
	offset += uint32(len(ntChallengeResponse))

	domainOffset := offset
	offset += uint32(len(domainBytes))

	userOffset := offset
	offset += uint32(len(userBytes))

	workstationOffset := offset
	offset += uint32(len(workstationBytes))

	sessionKeyOffset := offset

	flags := NegotiateUnicode | RequestTarget | NegotiateNTLM |
		NegotiateExtendedSessionSecurity | NegotiateTargetInfo | Negotiate128

	var buf bytes.Buffer
	buf.Write(ntlmSignature)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(NTLMType3MessageType))

	// LM Response SecurityBuffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(lmChallengeResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(lmChallengeResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, lmOffset)

	// NT Response SecurityBuffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(ntChallengeResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(ntChallengeResponse)))
	_ = binary.Write(&buf, binary.LittleEndian, ntOffset)

	// Domain SecurityBuffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(domainBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, domainOffset)

	// User SecurityBuffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(userBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, userOffset)

	// Workstation SecurityBuffer
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(workstationBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(len(workstationBytes)))
	_ = binary.Write(&buf, binary.LittleEndian, workstationOffset)

	// Encrypted Session Key SecurityBuffer (empty)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0))
	_ = binary.Write(&buf, binary.LittleEndian, sessionKeyOffset)

	// Flags
	_ = binary.Write(&buf, binary.LittleEndian, flags)

	// Write payload data
	buf.Write(lmChallengeResponse)
	buf.Write(ntChallengeResponse)
	buf.Write(domainBytes)
	buf.Write(userBytes)
	buf.Write(workstationBytes)

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}
