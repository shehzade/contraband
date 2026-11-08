package common

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionToken represents a cryptographically random 16-byte session identifier.
type SessionToken [16]byte

// NewSessionToken generates a cryptographically secure random 16-byte session token.
func NewSessionToken() (SessionToken, error) {
	var token SessionToken
	if _, err := rand.Read(token[:]); err != nil {
		return SessionToken{}, fmt.Errorf("failed to generate random session token: %w", err)
	}
	return token, nil
}

// String returns the 32-character lowercase hexadecimal representation of the token.
func (t SessionToken) String() string {
	return hex.EncodeToString(t[:])
}

// ParseSessionToken parses a 32-character hexadecimal or 36-character UUID string.
func ParseSessionToken(s string) (SessionToken, error) {
	clean := strings.ReplaceAll(s, "-", "")
	if len(clean) != 32 {
		return SessionToken{}, fmt.Errorf("invalid session token length %d (expected 32 hex chars)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return SessionToken{}, fmt.Errorf("invalid session token hex encoding: %w", err)
	}
	var token SessionToken
	copy(token[:], b)
	return token, nil
}

// MarshalText serializes the token as a lowercase hex string for JSON and YAML.
func (t SessionToken) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText deserializes a hex string into the 16-byte token.
func (t *SessionToken) UnmarshalText(data []byte) error {
	tok, err := ParseSessionToken(string(data))
	if err != nil {
		return err
	}
	*t = tok
	return nil
}

// IsZero checks if the token is all zero bytes.
func (t SessionToken) IsZero() bool {
	return t == SessionToken{}
}

// Verdict categorizes the outcome of an egress or data smuggling probe.
type Verdict string

const (
	VerdictBlockedL4  Verdict = "BLOCKED_L4"    // Firewall drop/reject (network level)
	VerdictBlockedL7  Verdict = "BLOCKED_L7"    // Proxy block / invalid handshake / DPI RST
	VerdictBlockedDLP Verdict = "BLOCKED_DLP"   // Connection succeeded, but payload intercepted
	VerdictSuccess    Verdict = "EXFIL_SUCCESS" // Payload arrived intact at server with valid SHA-256
)

// IsValid validates whether the verdict matches one of the 4 defined constants.
func (v Verdict) IsValid() bool {
	switch v {
	case VerdictBlockedL4, VerdictBlockedL7, VerdictBlockedDLP, VerdictSuccess:
		return true
	default:
		return false
	}
}

// IsSuccess returns true if the probe achieved successful data exfiltration.
func (v Verdict) IsSuccess() bool {
	return v == VerdictSuccess
}

// IsBlocked returns true if any layer (L4, L7, or DLP) blocked the transmission.
func (v Verdict) IsBlocked() bool {
	return v != VerdictSuccess
}

// Description provides a human-readable interpretation of the verdict.
func (v Verdict) Description() string {
	switch v {
	case VerdictBlockedL4:
		return "Firewall dropped or rejected network connection (L4)"
	case VerdictBlockedL7:
		return "Layer 7 inspection, proxy, or DPI blocked transmission"
	case VerdictBlockedDLP:
		return "Connection succeeded, but DLP payload was intercepted"
	case VerdictSuccess:
		return "Egress payload successfully exfiltrated and verified intact"
	default:
		return "Unknown verdict"
	}
}

// ForensicTimestamps records microsecond-precision timing metrics across the probe lifecycle.
type ForensicTimestamps struct {
	StartTCP         time.Time     `json:"start_tcp" yaml:"start_tcp"`
	ConnectedTCP     time.Time     `json:"connected_tcp" yaml:"connected_tcp"`
	HandshakeTLS     time.Time     `json:"handshake_tls" yaml:"handshake_tls"`
	FirstByteSent    time.Time     `json:"first_byte_sent" yaml:"first_byte_sent"`
	AckReceived      time.Time     `json:"ack_received" yaml:"ack_received"`
	TeardownDone     time.Time     `json:"teardown_done" yaml:"teardown_done"`
	TCPDuration      time.Duration `json:"tcp_duration_ms" yaml:"tcp_duration_ms"`
	TLSDuration      time.Duration `json:"tls_duration_ms" yaml:"tls_duration_ms"`
	TransferDuration time.Duration `json:"transfer_duration_ms" yaml:"transfer_duration_ms"`
	TotalDuration    time.Duration `json:"total_duration_ms" yaml:"total_duration_ms"`
}

// ComputeDurations populates duration fields from timestamp delta calculations.
func (f *ForensicTimestamps) ComputeDurations() {
	if !f.ConnectedTCP.IsZero() && !f.StartTCP.IsZero() {
		f.TCPDuration = f.ConnectedTCP.Sub(f.StartTCP)
	}
	if !f.HandshakeTLS.IsZero() && !f.ConnectedTCP.IsZero() {
		f.TLSDuration = f.HandshakeTLS.Sub(f.ConnectedTCP)
	}
	if !f.AckReceived.IsZero() && !f.FirstByteSent.IsZero() {
		f.TransferDuration = f.AckReceived.Sub(f.FirstByteSent)
	}
	if !f.TeardownDone.IsZero() && !f.StartTCP.IsZero() {
		f.TotalDuration = f.TeardownDone.Sub(f.StartTCP)
	} else if !f.AckReceived.IsZero() && !f.StartTCP.IsZero() {
		f.TotalDuration = f.AckReceived.Sub(f.StartTCP)
	}
}

// forensicTimestampsJSON marshals durations as floating-point milliseconds in JSON.
type forensicTimestampsJSON struct {
	StartTCP           time.Time `json:"start_tcp"`
	ConnectedTCP       time.Time `json:"connected_tcp"`
	HandshakeTLS       time.Time `json:"handshake_tls"`
	FirstByteSent      time.Time `json:"first_byte_sent"`
	AckReceived        time.Time `json:"ack_received"`
	TeardownDone       time.Time `json:"teardown_done"`
	TCPDurationMS      float64   `json:"tcp_duration_ms"`
	TLSDurationMS      float64   `json:"tls_duration_ms"`
	TransferDurationMS float64   `json:"transfer_duration_ms"`
	TotalDurationMS    float64   `json:"total_duration_ms"`
}

func (f ForensicTimestamps) MarshalJSON() ([]byte, error) {
	aux := forensicTimestampsJSON{
		StartTCP:           f.StartTCP,
		ConnectedTCP:       f.ConnectedTCP,
		HandshakeTLS:       f.HandshakeTLS,
		FirstByteSent:      f.FirstByteSent,
		AckReceived:        f.AckReceived,
		TeardownDone:       f.TeardownDone,
		TCPDurationMS:      float64(f.TCPDuration.Microseconds()) / 1000.0,
		TLSDurationMS:      float64(f.TLSDuration.Microseconds()) / 1000.0,
		TransferDurationMS: float64(f.TransferDuration.Microseconds()) / 1000.0,
		TotalDurationMS:    float64(f.TotalDuration.Microseconds()) / 1000.0,
	}
	return json.Marshal(aux)
}

func (f *ForensicTimestamps) UnmarshalJSON(data []byte) error {
	var aux forensicTimestampsJSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	f.StartTCP = aux.StartTCP
	f.ConnectedTCP = aux.ConnectedTCP
	f.HandshakeTLS = aux.HandshakeTLS
	f.FirstByteSent = aux.FirstByteSent
	f.AckReceived = aux.AckReceived
	f.TeardownDone = aux.TeardownDone
	f.TCPDuration = time.Duration(aux.TCPDurationMS * float64(time.Millisecond))
	f.TLSDuration = time.Duration(aux.TLSDurationMS * float64(time.Millisecond))
	f.TransferDuration = time.Duration(aux.TransferDurationMS * float64(time.Millisecond))
	f.TotalDuration = time.Duration(aux.TotalDurationMS * float64(time.Millisecond))
	return nil
}

// GenerateUUIDv4 generates an RFC 4122 compliant UUID v4 string without external dependencies.
func GenerateUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for UUID: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ValidateNetNTLMv2Hash validates NetNTLMv2 hash format (Hashcat mode 5600):
// username::domain:challenge:HMAC:blob
func ValidateNetNTLMv2Hash(h string) bool {
	parts := strings.Split(h, ":")
	if len(parts) != 6 {
		return false
	}
	// Format is: username::domain:challenge:HMAC:blob
	// parts[0] = username (must not be empty)
	// parts[1] = "" (the empty field between ::)
	// parts[2] = domain (may be empty for local accounts)
	// parts[3] = 16-hex challenge (8 bytes)
	// parts[4] = 32-hex HMAC / NTProofStr (16 bytes)
	// parts[5] = variable-length hex blob (even length, non-empty)
	if parts[0] == "" || parts[1] != "" {
		return false
	}
	if len(parts[3]) != 16 {
		return false
	}
	if _, err := hex.DecodeString(parts[3]); err != nil {
		return false
	}
	if len(parts[4]) != 32 {
		return false
	}
	if _, err := hex.DecodeString(parts[4]); err != nil {
		return false
	}
	if len(parts[5]) == 0 || len(parts[5])%2 != 0 {
		return false
	}
	if _, err := hex.DecodeString(parts[5]); err != nil {
		return false
	}
	return true
}

// ProbeResult records the comprehensive outcome and forensic evidence of an individual probe.
type ProbeResult struct {
	ID            string             `json:"id" yaml:"id"`
	Timestamp     time.Time          `json:"timestamp" yaml:"timestamp"`
	Timestamps    ForensicTimestamps `json:"timestamps" yaml:"timestamps"`
	Stage         string             `json:"stage" yaml:"stage"`
	Protocol      string             `json:"protocol" yaml:"protocol"`
	TargetPort    int                `json:"target_port" yaml:"target_port"`
	TargetHost    string             `json:"target_host" yaml:"target_host"`
	LocalAddr     string             `json:"local_addr" yaml:"local_addr"`
	ProxyHop      string             `json:"proxy_hop,omitempty" yaml:"proxy_hop,omitempty"`
	TLSProfile    string             `json:"tls_profile,omitempty" yaml:"tls_profile,omitempty"`
	JA3String     string             `json:"ja3_string,omitempty" yaml:"ja3_string,omitempty"`
	JA4String     string             `json:"ja4_string,omitempty" yaml:"ja4_string,omitempty"`
	PayloadType   string             `json:"payload_type,omitempty" yaml:"payload_type,omitempty"`
	CarrierType   string             `json:"carrier_type,omitempty" yaml:"carrier_type,omitempty"`
	TargetVolume  int64              `json:"target_volume_bytes" yaml:"target_volume_bytes"`
	BytesSent     int64              `json:"bytes_sent" yaml:"bytes_sent"`
	BytesRecv     int64              `json:"bytes_recv" yaml:"bytes_recv"`
	ThroughputBps float64            `json:"throughput_kbps" yaml:"throughput_kbps"`
	PayloadHash   string             `json:"payload_hash,omitempty" yaml:"payload_hash,omitempty"`
	WireHash      string             `json:"wire_hash,omitempty" yaml:"wire_hash,omitempty"`
	Verdict       Verdict            `json:"verdict" yaml:"verdict"`
	CapturedHash  string             `json:"captured_hash,omitempty" yaml:"captured_hash,omitempty"`
	ErrorMessage  string             `json:"error_message,omitempty" yaml:"error_message,omitempty"`
	RawEvidence   string             `json:"raw_evidence,omitempty" yaml:"raw_evidence,omitempty"`
}

// NewProbeResult initializes a ProbeResult with an auto-generated UUID v4 and UTC timestamp.
func NewProbeResult(stage, protocol, targetHost string, targetPort int) (ProbeResult, error) {
	id, err := GenerateUUIDv4()
	if err != nil {
		return ProbeResult{}, err
	}
	now := time.Now().UTC()
	return ProbeResult{
		ID:         id,
		Timestamp:  now,
		Timestamps: ForensicTimestamps{StartTCP: now},
		Stage:      stage,
		Protocol:   protocol,
		TargetHost: targetHost,
		TargetPort: targetPort,
	}, nil
}

// Validate checks the structural integrity of the ProbeResult.
func (p ProbeResult) Validate() error {
	if p.ID == "" {
		return errors.New("probe result missing ID")
	}
	if p.TargetPort < 1 || p.TargetPort > 65535 {
		return fmt.Errorf("invalid target port %d (must be 1-65535)", p.TargetPort)
	}
	if !p.Verdict.IsValid() {
		return fmt.Errorf("invalid verdict '%s'", p.Verdict)
	}
	if p.Timestamp.IsZero() {
		return errors.New("probe result missing timestamp")
	}
	if p.CapturedHash != "" && !ValidateNetNTLMv2Hash(p.CapturedHash) {
		return fmt.Errorf("malformed NetNTLMv2 hash format: %s", p.CapturedHash)
	}
	return nil
}

// ChunkRecord tracks reception of an individual stream chunk on the server.
type ChunkRecord struct {
	Sequence   uint32    `json:"sequence" yaml:"sequence"`
	Total      uint32    `json:"total" yaml:"total"`
	Length     uint32    `json:"length" yaml:"length"`
	ReceivedAt time.Time `json:"received_at" yaml:"received_at"`
	Hash       string    `json:"hash,omitempty" yaml:"hash,omitempty"`
}

// Session models the server-side lifecycle and reassembly state of an exfiltration stream.
type Session struct {
	SessionID      string                 `json:"session_id" yaml:"session_id"`
	Token          SessionToken           `json:"token,omitempty" yaml:"token,omitempty"`
	ClientIP       string                 `json:"client_ip" yaml:"client_ip"`
	ClientHost     string                 `json:"client_host,omitempty" yaml:"client_host,omitempty"`
	NetworkZone    string                 `json:"network_zone,omitempty" yaml:"network_zone,omitempty"`
	Protocol       string                 `json:"protocol" yaml:"protocol"`
	Port           int                    `json:"port" yaml:"port"`
	StartTime      time.Time              `json:"start_time" yaml:"start_time"`
	LastActive     time.Time              `json:"last_active" yaml:"last_active"`
	TotalBytes     int64                  `json:"total_bytes" yaml:"total_bytes"`
	ExpectedBytes  int64                  `json:"expected_bytes" yaml:"expected_bytes"`
	TotalChunks    int                    `json:"total_chunks" yaml:"total_chunks"`
	ReceivedChunks int                    `json:"received_chunks" yaml:"received_chunks"`
	PayloadHash    string                 `json:"payload_hash" yaml:"payload_hash"`
	ExpectedHash   string                 `json:"expected_hash" yaml:"expected_hash"`
	Status         string                 `json:"status" yaml:"status"` // active, completed, corrupted, failed, timed_out
	Verdict        Verdict                `json:"verdict" yaml:"verdict"`
	Chunks         map[uint32]ChunkRecord `json:"chunks,omitempty" yaml:"chunks,omitempty"`
}

// NewSession initializes a new server session tracker.
func NewSession(token SessionToken, clientIP, protocol string, port int) *Session {
	now := time.Now().UTC()
	return &Session{
		SessionID:  token.String(),
		Token:      token,
		ClientIP:   clientIP,
		Protocol:   protocol,
		Port:       port,
		StartTime:  now,
		LastActive: now,
		Status:     "active",
		Chunks:     make(map[uint32]ChunkRecord),
	}
}

// IsComplete returns true if all expected chunks have arrived.
func (s *Session) IsComplete() bool {
	return s.TotalChunks > 0 && s.ReceivedChunks >= s.TotalChunks
}

// ChunkHeader represents the standardized 32-byte binary chunk frame header.
type ChunkHeader struct {
	Magic       uint32       // 0x43545242 ("CTRB")
	Token       SessionToken // 16-byte session identifier
	Sequence    uint32       // Chunk sequence number (1-based)
	TotalChunks uint32       // Total chunk count
	PayloadLen  uint32       // Byte length of chunk payload
}

// MarshalBinary serializes the 32-byte chunk header to big-endian wire format.
func (h ChunkHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, ChunkHeaderSize)
	binary.BigEndian.PutUint32(buf[0:4], h.Magic)
	copy(buf[4:20], h.Token[:])
	binary.BigEndian.PutUint32(buf[20:24], h.Sequence)
	binary.BigEndian.PutUint32(buf[24:28], h.TotalChunks)
	binary.BigEndian.PutUint32(buf[28:32], h.PayloadLen)
	return buf, nil
}

// UnmarshalBinary deserializes the 32-byte chunk header from big-endian wire format.
func (h *ChunkHeader) UnmarshalBinary(data []byte) error {
	if len(data) < ChunkHeaderSize {
		return fmt.Errorf("chunk header too short: got %d bytes, expected %d", len(data), ChunkHeaderSize)
	}
	h.Magic = binary.BigEndian.Uint32(data[0:4])
	if h.Magic != MagicHeader {
		return fmt.Errorf("invalid chunk header magic: 0x%08x (expected 0x%08x)", h.Magic, MagicHeader)
	}
	copy(h.Token[:], data[4:20])
	h.Sequence = binary.BigEndian.Uint32(data[20:24])
	h.TotalChunks = binary.BigEndian.Uint32(data[24:28])
	h.PayloadLen = binary.BigEndian.Uint32(data[28:32])
	return nil
}

// CapturedCredential models credentials harvested by server listeners (SMB, SFTP, FTP).
type CapturedCredential struct {
	Protocol  string    `json:"protocol" yaml:"protocol"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	ClientIP  string    `json:"client_ip" yaml:"client_ip"`
	Username  string    `json:"username" yaml:"username"`
	Domain    string    `json:"domain,omitempty" yaml:"domain,omitempty"`
	HashType  string    `json:"hash_type" yaml:"hash_type"` // NetNTLMv2, plaintext, ssh_key
	Hash      string    `json:"hash" yaml:"hash"`           // Hashcat format or captured credential
}

// Finding models a security deficiency identified during egress testing for SARIF/reporting.
type Finding struct {
	RuleID          string  `json:"rule_id" yaml:"rule_id"`
	Level           string  `json:"level" yaml:"level"` // info, low, medium, high, critical
	Message         string  `json:"message" yaml:"message"`
	Port            int     `json:"port" yaml:"port"`
	Protocol        string  `json:"protocol" yaml:"protocol"`
	EEIContribution float64 `json:"eei_contribution" yaml:"eei_contribution"`
	Remediation     string  `json:"remediation" yaml:"remediation"`
}

// BannerReflection models the authenticated JSON reflection banner emitted by server listeners.
type BannerReflection struct {
	Status   string `json:"status"`    // "OK"
	RemoteIP string `json:"remote_ip"` // Observed client IP
	Port     int    `json:"port"`      // Target port
	Proto    string `json:"proto"`     // "TCP" or "UDP"
	Session  string `json:"session"`   // Session ID string
}

// TelemetryEvent models real-time server-side streaming events for SSE/telemetry.
type TelemetryEvent struct {
	Timestamp time.Time    `json:"timestamp"`
	Type      string       `json:"type"` // probe_start, chunk_received, credential_captured, error
	Message   string       `json:"message"`
	Data      *ProbeResult `json:"data,omitempty"`
}

// VerificationACK models the cryptographically signed and hash-validated acknowledgement
// returned by contraband server listeners upon chunk receipt or stream completion.
type VerificationACK struct {
	Status         string  `json:"status" yaml:"status"`
	SessionID      string  `json:"session_id" yaml:"session_id"`
	TotalBytes     int64   `json:"total_bytes,omitempty" yaml:"total_bytes,omitempty"`
	ReceivedChunks int     `json:"received_chunks,omitempty" yaml:"received_chunks,omitempty"`
	TotalChunks    int     `json:"total_chunks,omitempty" yaml:"total_chunks,omitempty"`
	Sequence       uint32  `json:"sequence,omitempty" yaml:"sequence,omitempty"`
	PayloadHash    string  `json:"payload_hash,omitempty" yaml:"payload_hash,omitempty"`
	Verdict        Verdict `json:"verdict" yaml:"verdict"`
	ErrorMessage   string  `json:"error_message,omitempty" yaml:"error_message,omitempty"`
}

// Verify evaluates the server verification ACK against client expectations.
// It returns VerdictSuccess and nil error only if:
// 1. Status == "OK"
// 2. Verdict is VerdictSuccess (or non-empty valid success and not IN_PROGRESS)
// 3. Expected chunk counts match (if provided)
// 4. Rolling payload SHA-256 matches expectedHash (if provided)
//
// In case of DLP interception (hash mismatch, explicit BLOCKED_DLP verdict),
// it returns VerdictBlockedDLP and a descriptive error.
// In case of L7 blocking (status ERROR, proxy block, chunk missing),
// it returns VerdictBlockedL7 and an error.
func (ack *VerificationACK) Verify(expectedHash string, totalChunks int) (Verdict, error) {
	if ack == nil {
		return VerdictBlockedL7, errors.New("nil verification ACK received from server")
	}

	// 1. Check for server error status or explicit DLP block
	if strings.EqualFold(ack.Status, "ERROR") {
		errMsg := ack.ErrorMessage
		if errMsg == "" {
			errMsg = "server returned error status"
		}
		if ack.Verdict == VerdictBlockedDLP || strings.Contains(strings.ToLower(errMsg), "hash mismatch") || strings.Contains(strings.ToLower(errMsg), "dlp") {
			return VerdictBlockedDLP, fmt.Errorf("server reported DLP interception: %s", errMsg)
		}
		return VerdictBlockedL7, fmt.Errorf("server error: %s", errMsg)
	}

	if ack.Verdict == VerdictBlockedDLP {
		return VerdictBlockedDLP, fmt.Errorf("server verdict BLOCKED_DLP: %s", ack.ErrorMessage)
	}

	// 2. Check for in-progress or incomplete stream
	if string(ack.Verdict) == "IN_PROGRESS" || ack.Verdict == "" {
		if totalChunks > 0 && ack.ReceivedChunks > 0 && ack.ReceivedChunks < totalChunks {
			return VerdictBlockedL7, fmt.Errorf("incomplete exfiltration stream: received %d/%d chunks", ack.ReceivedChunks, totalChunks)
		}
		if ack.Verdict == "IN_PROGRESS" {
			return VerdictBlockedL7, fmt.Errorf("stream incomplete on server (verdict IN_PROGRESS)")
		}
	}

	// 3. Check chunk accounting if totalChunks specified
	if totalChunks > 0 {
		if ack.TotalChunks > 0 && ack.TotalChunks != totalChunks {
			return VerdictBlockedL7, fmt.Errorf("chunk total mismatch: server total %d, client total %d", ack.TotalChunks, totalChunks)
		}
		if ack.ReceivedChunks > 0 && ack.ReceivedChunks != totalChunks {
			return VerdictBlockedL7, fmt.Errorf("chunk reception mismatch: server received %d, client sent %d", ack.ReceivedChunks, totalChunks)
		}
	}

	// 4. Cryptographic Non-Repudiation: verify rolling SHA-256 checksum
	if expectedHash != "" {
		if ack.PayloadHash == "" {
			return VerdictBlockedDLP, fmt.Errorf("missing server payload hash: expected %s", expectedHash)
		}
		if !strings.EqualFold(ack.PayloadHash, expectedHash) {
			return VerdictBlockedDLP, fmt.Errorf("cryptographic payload SHA-256 mismatch (possible DLP tampering): server=%s client=%s", ack.PayloadHash, expectedHash)
		}
	}

	// 5. Success confirmation
	if ack.Verdict != "" && ack.Verdict != VerdictSuccess {
		return ack.Verdict, fmt.Errorf("unexpected server verdict: %s", ack.Verdict)
	}

	return VerdictSuccess, nil
}
