package smb

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

func EncodeUTF16LE(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func DecodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u16s))
}

func ComputeNTHash(password string) []byte {
	h := md4.New()
	h.Write(EncodeUTF16LE(password))
	return h.Sum(nil)
}

func ComputeNTLMv2Hash(username, password, domain string) []byte {
	ntHash := ComputeNTHash(password)
	mac := hmac.New(md5.New, ntHash)
	mac.Write(EncodeUTF16LE(strings.ToUpper(username)))
	mac.Write(EncodeUTF16LE(domain))
	return mac.Sum(nil)
}

func BuildNTLMSSPType1() []byte {
	b := make([]byte, 32)
	copy(b[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:12], 1) // Type 1 Negotiate
	// Negotiate flags: Unicode, OEM, Request Target, NTLM, Extended Security, Negotiate 128
	flags := uint32(0x00000001 | 0x00000002 | 0x00000004 | 0x00000200 | 0x00080000 | 0x20000000)
	binary.LittleEndian.PutUint32(b[12:16], flags)
	return b
}

func BuildNTLMSSPType2(serverChallenge [8]byte, targetName string) []byte {
	targetBytes := EncodeUTF16LE(targetName)
	b := make([]byte, 48+len(targetBytes))
	copy(b[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:12], 2) // Type 2 Challenge
	binary.LittleEndian.PutUint16(b[12:14], uint16(len(targetBytes)))
	binary.LittleEndian.PutUint16(b[14:16], uint16(len(targetBytes)))
	binary.LittleEndian.PutUint32(b[16:20], 48)
	// Flags
	flags := uint32(0x00000001 | 0x00000004 | 0x00000200 | 0x00080000)
	binary.LittleEndian.PutUint32(b[20:24], flags)
	copy(b[24:32], serverChallenge[:])
	copy(b[48:], targetBytes)
	return b
}

func BuildNTLMSSPType3(username, domain, password string, serverChallenge [8]byte) []byte {
	userBytes := EncodeUTF16LE(username)
	domainBytes := EncodeUTF16LE(domain)

	// Client challenge (8 bytes random)
	var clientChallenge [8]byte
	_, _ = rand.Read(clientChallenge[:])

	// Time (8 bytes)
	timeNow := timeToWindowsFileTime()

	// Target info / AV pairs
	avPairs := make([]byte, 0)
	// MsvAvNbDomainName (type 2)
	avPairs = append(avPairs, 2, 0)
	avPairs = binary.LittleEndian.AppendUint16(avPairs, uint16(len(domainBytes)))
	avPairs = append(avPairs, domainBytes...)
	// MsvAvEOL (type 0)
	avPairs = append(avPairs, 0, 0, 0, 0)

	// NT Response / NetNTLMv2 blob
	// Blob: 0x01010000, 0x00000000, timestamp(8), clientChallenge(8), 0x00000000, avPairs, 0x00000000
	blob := make([]byte, 0, 32+len(avPairs))
	blob = append(blob, 1, 1, 0, 0)
	blob = append(blob, 0, 0, 0, 0)
	blob = binary.LittleEndian.AppendUint64(blob, timeNow)
	blob = append(blob, clientChallenge[:]...)
	blob = append(blob, 0, 0, 0, 0)
	blob = append(blob, avPairs...)
	blob = append(blob, 0, 0, 0, 0)

	// Compute HMAC-MD5 of serverChallenge + blob using NTLMv2Hash
	ntlmv2Hash := ComputeNTLMv2Hash(username, password, domain)
	mac := hmac.New(md5.New, ntlmv2Hash)
	mac.Write(serverChallenge[:])
	mac.Write(blob)
	ntProof := mac.Sum(nil)

	ntResponse := append(ntProof, blob...)
	lmResponse := make([]byte, 24) // Empty/zeroed LM response

	hdrLen := uint32(64)
	domainOffset := hdrLen
	userOffset := domainOffset + uint32(len(domainBytes))
	lmOffset := userOffset + uint32(len(userBytes))
	ntOffset := lmOffset + uint32(len(lmResponse))
	totalLen := ntOffset + uint32(len(ntResponse))

	b := make([]byte, totalLen)
	copy(b[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(b[8:12], 3) // Type 3 Authenticate

	// LM Response fields
	binary.LittleEndian.PutUint16(b[12:14], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint16(b[14:16], uint16(len(lmResponse)))
	binary.LittleEndian.PutUint32(b[16:20], lmOffset)

	// NT Response fields
	binary.LittleEndian.PutUint16(b[20:22], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(b[22:24], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(b[24:28], ntOffset)

	// Domain fields
	binary.LittleEndian.PutUint16(b[28:30], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(b[30:32], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(b[32:36], domainOffset)

	// User fields
	binary.LittleEndian.PutUint16(b[36:38], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(b[38:40], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(b[40:44], userOffset)

	// Session key (empty)
	binary.LittleEndian.PutUint16(b[52:54], 0)
	binary.LittleEndian.PutUint16(b[54:56], 0)
	binary.LittleEndian.PutUint32(b[56:60], totalLen)

	// Flags
	flags := uint32(0x00000001 | 0x00000004 | 0x00000200 | 0x00080000)
	binary.LittleEndian.PutUint32(b[60:64], flags)

	copy(b[domainOffset:], domainBytes)
	copy(b[userOffset:], userBytes)
	copy(b[lmOffset:], lmResponse)
	copy(b[ntOffset:], ntResponse)

	return b
}

func timeToWindowsFileTime() uint64 {
	// Windows file time is 100ns intervals since Jan 1, 1601 UTC
	// Standard constant: 116444736000000000 100-ns intervals between 1601 and 1970
	const intervalsTo1970 = 116444736000000000
	return intervalsTo1970 + 10000000
}

func ParseNTLMSSPType2Challenge(data []byte) ([8]byte, string, error) {
	var challenge [8]byte
	if len(data) < 32 || string(data[:8]) != "NTLMSSP\x00" {
		return challenge, "", fmt.Errorf("invalid NTLMSSP Type 2")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 2 {
		return challenge, "", fmt.Errorf("expected NTLMSSP Type 2, got %d", msgType)
	}
	targetLen := binary.LittleEndian.Uint16(data[12:14])
	targetOffset := binary.LittleEndian.Uint32(data[16:20])
	copy(challenge[:], data[24:32])

	targetName := ""
	if targetLen > 0 && int(targetOffset+uint32(targetLen)) <= len(data) {
		targetName = DecodeUTF16LE(data[targetOffset : targetOffset+uint32(targetLen)])
	}
	return challenge, targetName, nil
}

func ParseNTLMSSPType3(data []byte, serverChallenge [8]byte) (string, string, string, string, error) {
	if len(data) < 64 || string(data[:8]) != "NTLMSSP\x00" {
		return "", "", "", "", fmt.Errorf("invalid NTLMSSP Type 3")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 3 {
		return "", "", "", "", fmt.Errorf("expected NTLMSSP Type 3, got %d", msgType)
	}

	ntLen := binary.LittleEndian.Uint16(data[20:22])
	ntOffset := binary.LittleEndian.Uint32(data[24:28])

	domainLen := binary.LittleEndian.Uint16(data[28:30])
	domainOffset := binary.LittleEndian.Uint32(data[32:36])

	userLen := binary.LittleEndian.Uint16(data[36:38])
	userOffset := binary.LittleEndian.Uint32(data[40:44])

	if int(userOffset+uint32(userLen)) > len(data) || int(ntOffset+uint32(ntLen)) > len(data) {
		return "", "", "", "", fmt.Errorf("out of bounds offset in Type 3")
	}

	user := DecodeUTF16LE(data[userOffset : userOffset+uint32(userLen)])
	domain := ""
	if domainLen > 0 && int(domainOffset+uint32(domainLen)) <= len(data) {
		domain = DecodeUTF16LE(data[domainOffset : domainOffset+uint32(domainLen)])
	}

	ntResponse := data[ntOffset : ntOffset+uint32(ntLen)]
	if len(ntResponse) < 16 {
		return "", "", "", "", fmt.Errorf("NT response too short: %d", len(ntResponse))
	}

	ntProof := ntResponse[:16]
	blob := ntResponse[16:]

	challengeHex := hex.EncodeToString(serverChallenge[:])
	proofHex := hex.EncodeToString(ntProof)
	blobHex := hex.EncodeToString(blob)

	hashcatFormat := fmt.Sprintf("%s::%s:%s:%s:%s", user, domain, challengeHex, proofHex, blobHex)
	return user, domain, hashcatFormat, challengeHex, nil
}
