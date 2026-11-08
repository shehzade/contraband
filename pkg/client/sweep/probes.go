package sweep

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// BuildProbeForPort dispatches to the port-specific binary probe builder.
func BuildProbeForPort(port int) []byte {
	switch port {
	case 53:
		return BuildDNSProbe(0x1337)
	case 123:
		return BuildNTPProbe(time.Now().UTC())
	case 161:
		return BuildSNMPProbe("public", 0x1337)
	case 514:
		return BuildSyslogProbe("contraband", common.UDPProbeToken)
	case 443, 8443:
		return BuildQUICProbe()
	default:
		return BuildGenericUDPProbe(common.UDPProbeToken)
	}
}

// BuildDNSProbe crafts an RFC 1035 root query packet (. IN NS) (17 bytes).
func BuildDNSProbe(queryID uint16) []byte {
	buf := make([]byte, 17)
	binary.BigEndian.PutUint16(buf[0:2], queryID)  // ID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)   // Flags: Standard query, Recursion Desired
	binary.BigEndian.PutUint16(buf[4:6], 0x0001)   // QDCOUNT: 1
	binary.BigEndian.PutUint16(buf[6:8], 0x0000)   // ANCOUNT: 0
	binary.BigEndian.PutUint16(buf[8:10], 0x0000)  // NSCOUNT: 0
	binary.BigEndian.PutUint16(buf[10:12], 0x0000) // ARCOUNT: 0
	buf[12] = 0x00                                 // QNAME: root "."
	binary.BigEndian.PutUint16(buf[13:15], 0x0002) // QTYPE: NS (type 2)
	binary.BigEndian.PutUint16(buf[15:17], 0x0001) // QCLASS: IN (class 1)
	return buf
}

// BuildNTPProbe crafts an RFC 5905 NTPv4 client request packet (48 bytes).
func BuildNTPProbe(transmitTime time.Time) []byte {
	buf := make([]byte, 48)
	// Byte 0: LI=0 (no warning), VN=4 (NTPv4), Mode=3 (Client) -> 00 100 011 = 0x23
	buf[0] = 0x23
	buf[1] = 0x00 // Stratum: unspecified
	buf[2] = 0x04 // Poll: 16 seconds
	buf[3] = 0xfa // Precision: -6 (approx 15ms)
	// Bytes 4-39: Root delay, dispersion, refid, timestamps initialized to 0

	// Bytes 40-47: Transmit Timestamp (seconds since 1900 + fraction)
	const ntpEpochOffset = 2208988800
	sec := uint32(transmitTime.Unix() + ntpEpochOffset)
	frac := uint32((uint64(transmitTime.Nanosecond()) << 32) / 1000000000)
	binary.BigEndian.PutUint32(buf[40:44], sec)
	binary.BigEndian.PutUint32(buf[44:48], frac)
	return buf
}

// BuildSNMPProbe crafts an RFC 1905 SNMPv2c GetRequest packet for sysDescr.0 (43 bytes).
// OID 1.3.6.1.2.1.1.1.0 in ASN.1 BER: 2b 06 01 02 01 01 01 00
func BuildSNMPProbe(community string, reqID int32) []byte {
	commBytes := []byte(community)
	commLen := byte(len(commBytes))

	// Pre-assembled OID VarBind sequence for sysDescr.0 (1.3.6.1.2.1.1.1.0):
	// SEQUENCE (12B contents, 14B total TLV): OID TLV (10B) + NULL TLV (2B)
	varBind := []byte{
		0x30, 0x0c,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
		0x05, 0x00,
	}

	// VarBindList SEQUENCE (16B)
	varBindList := append([]byte{0x30, byte(len(varBind))}, varBind...)

	// GetRequest-PDU (0xa0)
	// reqID (INTEGER 4B), error-status (0), error-index (0), VarBindList
	pduPayload := make([]byte, 0, 10+len(varBindList))
	pduPayload = append(pduPayload, 0x02, 0x04)
	pduPayload = binary.BigEndian.AppendUint32(pduPayload, uint32(reqID))
	pduPayload = append(pduPayload, 0x02, 0x01, 0x00) // error-status = 0
	pduPayload = append(pduPayload, 0x02, 0x01, 0x00) // error-index = 0
	pduPayload = append(pduPayload, varBindList...)

	pdu := append([]byte{0xa0, byte(len(pduPayload))}, pduPayload...)

	// Outer Message SEQUENCE: version (INTEGER 1 = v2c), community, PDU
	msgPayload := make([]byte, 0, 3+2+int(commLen)+len(pdu))
	msgPayload = append(msgPayload, 0x02, 0x01, 0x01) // version 1 (SNMPv2c)
	msgPayload = append(msgPayload, 0x04, commLen)
	msgPayload = append(msgPayload, commBytes...)
	msgPayload = append(msgPayload, pdu...)

	return append([]byte{0x30, byte(len(msgPayload))}, msgPayload...)
}

// BuildSyslogProbe crafts an RFC 5424 test probe frame.
func BuildSyslogProbe(host, msg string) []byte {
	// PRI 134: Facility local0 (16) * 8 + Severity info (6) = 134
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	frame := fmt.Sprintf("<134>1 %s %s contraband 1 CTRB-PROBE - %s", ts, host, msg)
	return []byte(frame)
}

// BuildQUICProbe crafts an RFC 9000 QUIC Initial probe packet padded to 1200 bytes.
func BuildQUICProbe() []byte {
	pkt := make([]byte, 1200)

	// Long Header Initial: 0xc0 (Header Form=1, Fixed=1, Type=0x00 Initial, Reserved=0, PN Len=1)
	pkt[0] = 0xc0
	binary.BigEndian.PutUint32(pkt[1:5], 0x00000001) // Version: QUIC v1 (RFC 9000)

	// Destination Connection ID (DCID): 8 bytes
	pkt[5] = 0x08
	_, _ = rand.Read(pkt[6:14])

	// Source Connection ID (SCID): 8 bytes
	pkt[14] = 0x08
	_, _ = rand.Read(pkt[15:23])

	// Token Length: 0
	pkt[23] = 0x00

	// Length (remaining packet length: 1200 - 26 = 1174 bytes)
	// Varint encoding: 2-byte prefix 0x40
	binary.BigEndian.PutUint16(pkt[24:26], 0x4496) // 0x4000 | 1174

	// Packet Number: 1 byte
	pkt[26] = 0x00

	// Remaining 1173 bytes (pkt[27:1200]) are initialized to 0x00 (RFC 9000 PADDING frames)
	return pkt
}

// BuildGenericUDPProbe crafts a standard fallback probe datagram.
func BuildGenericUDPProbe(token string) []byte {
	if token == "" {
		token = common.UDPProbeToken
	}
	return []byte(token)
}
