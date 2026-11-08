package smb

import (
	"encoding/binary"
	"fmt"
	"io"
)

// NetBIOS Session Service framing (RFC 1002)
func PackNetBIOS(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = 0x00
	l := len(payload)
	out[1] = byte(l >> 16)
	out[2] = byte(l >> 8)
	out[3] = byte(l)
	copy(out[4:], payload)
	return out
}

func ReadNetBIOSMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	l := (int(hdr[1]) << 16) | (int(hdr[2]) << 8) | int(hdr[3])
	if l <= 0 || l > 16*1024*1024 {
		return nil, fmt.Errorf("invalid NetBIOS packet length: %d", l)
	}
	payload := make([]byte, l)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// SMB2 Header
type SMB2Header struct {
	ProtocolID    [4]byte // \xFESMB
	StructureSize uint16  // 64
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	CreditReqResp uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

func (h *SMB2Header) Encode() []byte {
	buf := make([]byte, 64)
	copy(buf[0:4], h.ProtocolID[:])
	binary.LittleEndian.PutUint16(buf[4:6], 64)
	binary.LittleEndian.PutUint16(buf[6:8], h.CreditCharge)
	binary.LittleEndian.PutUint32(buf[8:12], h.Status)
	binary.LittleEndian.PutUint16(buf[12:14], h.Command)
	binary.LittleEndian.PutUint16(buf[14:16], h.CreditReqResp)
	binary.LittleEndian.PutUint32(buf[16:20], h.Flags)
	binary.LittleEndian.PutUint32(buf[20:24], h.NextCommand)
	binary.LittleEndian.PutUint64(buf[24:32], h.MessageID)
	binary.LittleEndian.PutUint32(buf[32:36], h.Reserved)
	binary.LittleEndian.PutUint32(buf[36:40], h.TreeID)
	binary.LittleEndian.PutUint64(buf[40:48], h.SessionID)
	copy(buf[48:64], h.Signature[:])
	return buf
}

func DecodeSMB2Header(data []byte) (*SMB2Header, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("data too short for SMB2 header: %d", len(data))
	}
	if data[0] != 0xFE || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, fmt.Errorf("invalid SMB2 magic: %x", data[0:4])
	}
	h := &SMB2Header{}
	copy(h.ProtocolID[:], data[0:4])
	h.StructureSize = binary.LittleEndian.Uint16(data[4:6])
	h.CreditCharge = binary.LittleEndian.Uint16(data[6:8])
	h.Status = binary.LittleEndian.Uint32(data[8:12])
	h.Command = binary.LittleEndian.Uint16(data[12:14])
	h.CreditReqResp = binary.LittleEndian.Uint16(data[14:16])
	h.Flags = binary.LittleEndian.Uint32(data[16:20])
	h.NextCommand = binary.LittleEndian.Uint32(data[20:24])
	h.MessageID = binary.LittleEndian.Uint64(data[24:32])
	h.Reserved = binary.LittleEndian.Uint32(data[32:36])
	h.TreeID = binary.LittleEndian.Uint32(data[36:40])
	h.SessionID = binary.LittleEndian.Uint64(data[40:48])
	copy(h.Signature[:], data[48:64])
	return h, nil
}
