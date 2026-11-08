package smb

import (
	"encoding/binary"
)

// Build SMB2 Negotiate Request
func BuildSMB2NegotiateRequest(messageID uint64) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0000, // SMB2_NEGOTIATE
		CreditReqResp: 1,
		MessageID:     messageID,
	}
	body := make([]byte, 36+8) // 36 fixed + 4 dialects (2 bytes each)
	binary.LittleEndian.PutUint16(body[0:2], 36)
	binary.LittleEndian.PutUint16(body[2:4], 4) // 4 dialects
	binary.LittleEndian.PutUint16(body[4:6], 1) // SecurityMode
	// Dialects: 0x0202 (SMB 2.0.2), 0x0210 (SMB 2.1), 0x0300 (SMB 3.0), 0x0311 (SMB 3.1.1)
	binary.LittleEndian.PutUint16(body[36:38], 0x0202)
	binary.LittleEndian.PutUint16(body[38:40], 0x0210)
	binary.LittleEndian.PutUint16(body[40:42], 0x0300)
	binary.LittleEndian.PutUint16(body[42:44], 0x0311)

	packet := append(hdr.Encode(), body...)
	return packet
}

// Build SMB2 Session Setup Request
func BuildSMB2SessionSetupRequest(messageID uint64, sessionID uint64, ntlmsspPayload []byte) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0001, // SMB2_SESSION_SETUP
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
	}
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 25)
	body[2] = 0 // Flags
	body[3] = 1 // SecurityMode
	binary.LittleEndian.PutUint32(body[4:8], 0)
	binary.LittleEndian.PutUint32(body[8:12], 0)
	secBufOffset := uint16(64 + 24)
	binary.LittleEndian.PutUint16(body[12:14], secBufOffset)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(ntlmsspPayload)))
	binary.LittleEndian.PutUint64(body[16:24], 0)

	packet := append(hdr.Encode(), body...)
	packet = append(packet, ntlmsspPayload...)
	return packet
}

// Build SMB2 Tree Connect Request
func BuildSMB2TreeConnectRequest(messageID uint64, sessionID uint64, sharePath string) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0003, // SMB2_TREE_CONNECT
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
	}
	pathBytes := EncodeUTF16LE(sharePath)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:2], 9)
	binary.LittleEndian.PutUint16(body[2:4], 0)
	binary.LittleEndian.PutUint16(body[4:6], uint16(64+8))
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(pathBytes)))

	packet := append(hdr.Encode(), body...)
	packet = append(packet, pathBytes...)
	return packet
}

// Build SMB2 Create Request
func BuildSMB2CreateRequest(messageID uint64, sessionID uint64, treeID uint32, fileName string) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0005, // SMB2_CREATE
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}
	nameBytes := EncodeUTF16LE(fileName)
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:2], 57)
	body[2] = 0 // SecurityFlags
	body[3] = 0 // RequestedOplockLevel
	binary.LittleEndian.PutUint32(body[4:8], 2)
	binary.LittleEndian.PutUint32(body[24:28], 0x00120116) // DesiredAccess
	binary.LittleEndian.PutUint32(body[28:32], 0x80)       // FileAttributes
	binary.LittleEndian.PutUint32(body[32:36], 7)          // ShareAccess
	binary.LittleEndian.PutUint32(body[36:40], 2)          // CreateDisposition
	binary.LittleEndian.PutUint16(body[44:46], uint16(64+56))
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(nameBytes)))

	packet := append(hdr.Encode(), body...)
	packet = append(packet, nameBytes...)
	return packet
}

// Build SMB2 Write Request
func BuildSMB2WriteRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte, fileOffset uint64, data []byte) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0009, // SMB2_WRITE
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}
	body := make([]byte, 48)
	binary.LittleEndian.PutUint16(body[0:2], 49)
	binary.LittleEndian.PutUint16(body[2:4], uint16(64+48))
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint64(body[8:16], fileOffset)
	copy(body[16:32], fileID[:])

	packet := append(hdr.Encode(), body...)
	packet = append(packet, data...)
	return packet
}

// Build SMB2 Close Request
func BuildSMB2CloseRequest(messageID uint64, sessionID uint64, treeID uint32, fileID [16]byte) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0006, // SMB2_CLOSE
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:2], 24)
	copy(body[8:24], fileID[:])

	return append(hdr.Encode(), body...)
}

// Build SMB2 Tree Disconnect Request
func BuildSMB2TreeDisconnectRequest(messageID uint64, sessionID uint64, treeID uint32) []byte {
	hdr := SMB2Header{
		ProtocolID:    [4]byte{0xFE, 'S', 'M', 'B'},
		StructureSize: 64,
		Command:       0x0004, // SMB2_TREE_DISCONNECT
		CreditReqResp: 1,
		MessageID:     messageID,
		SessionID:     sessionID,
		TreeID:        treeID,
	}
	body := make([]byte, 4)
	binary.LittleEndian.PutUint16(body[0:2], 4)
	return append(hdr.Encode(), body...)
}
