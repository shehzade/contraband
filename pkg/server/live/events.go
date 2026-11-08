package live

import (
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// EventType categorizes real-time dashboard events.
type EventType string

const (
	EventSessionStart       EventType = "session_start"
	EventConnectionOpen     EventType = "connection_open"
	EventChunkProgress      EventType = "chunk_progress"
	EventChunkReceived      EventType = "chunk_received"
	EventSessionComplete    EventType = "session_complete"
	EventProbeReceived      EventType = "probe_received"
	EventRateTick           EventType = "rate_tick"
	EventReportUploaded     EventType = "report_uploaded"
	EventProtocolStatus     EventType = "protocol_status"
	EventPortStatus         EventType = "port_status"
	EventCredentialCaptured EventType = "credential_captured"
	EventHeartbeat          EventType = "heartbeat"
	EventDashboardReset     EventType = "dashboard_reset"
)

// LiveEvent represents an individual telemetry event emitted over SSE.
type LiveEvent struct {
	ID          string      `json:"id"`
	Type        EventType   `json:"type"`
	Timestamp   time.Time   `json:"timestamp"`
	TimestampMS float64     `json:"timestamp_ms"`
	SessionID   string      `json:"session_id,omitempty"`
	NetworkZone string      `json:"network_zone,omitempty"`
	ClientHost  string      `json:"client_host,omitempty"`
	ClientIP    string      `json:"client_ip,omitempty"`
	Protocol    string      `json:"protocol,omitempty"`
	Message     string      `json:"message"`
	Data        interface{} `json:"data,omitempty"`
}

// SessionProgressData carries active stream metrics for EventChunkProgress.
type SessionProgressData struct {
	SessionID        string  `json:"session_id"`
	NetworkZone      string  `json:"network_zone"`
	ClientHost       string  `json:"client_host"`
	ClientIP         string  `json:"client_ip"`
	Protocol         string  `json:"protocol"`
	Port             int     `json:"port,omitempty"`
	Sequence         uint32  `json:"sequence"`
	TotalChunks      uint32  `json:"total_chunks"`
	BytesTransferred int64   `json:"bytes_transferred"`
	TotalBytes       int64   `json:"total_bytes"`
	ProgressPct      float64 `json:"progress_pct"`
	InstantMBs       float64 `json:"instant_mbs"`
	RollingHash      string  `json:"rolling_hash,omitempty"`
	ElapsedMS        float64 `json:"elapsed_ms"`
}

// SessionCompleteData carries final completion metrics for EventSessionComplete.
type SessionCompleteData struct {
	SessionID   string         `json:"session_id"`
	NetworkZone string         `json:"network_zone"`
	ClientHost  string         `json:"client_host"`
	ClientIP    string         `json:"client_ip"`
	Protocol    string         `json:"protocol"`
	Port        int            `json:"port,omitempty"`
	TotalBytes  int64          `json:"total_bytes"`
	TotalChunks int            `json:"total_chunks"`
	DurationMS  float64        `json:"duration_ms"`
	AverageMBs  float64        `json:"average_mbs"`
	FinalHash   string         `json:"final_hash"`
	HashMatched bool           `json:"hash_matched"`
	Verdict     common.Verdict `json:"verdict"`
}

// ReportUploadData carries high-level metrics for EventReportUploaded.
type ReportUploadData struct {
	ReportID     string  `json:"report_id"`
	TargetHost   string  `json:"target_host"`
	NetworkZone  string  `json:"network_zone"`
	ClientHost   string  `json:"client_host"`
	ClientIP     string  `json:"client_ip"`
	EEIScore     float64 `json:"eei_score"`
	Posture      string  `json:"posture"`
	TotalProbes  int     `json:"total_probes"`
	SuccessCount int     `json:"success_count"`
	BlockedL4    int     `json:"blocked_l4"`
	BlockedL7    int     `json:"blocked_l7"`
	BlockedDLP   int     `json:"blocked_dlp"`
	UploadedAt   string  `json:"uploaded_at"`
}

// ProbeData carries probe telemetry for EventProbeReceived.
type ProbeData struct {
	ProbeID     string         `json:"probe_id"`
	NetworkZone string         `json:"network_zone"`
	ClientHost  string         `json:"client_host"`
	ClientIP    string         `json:"client_ip"`
	Protocol    string         `json:"protocol"`
	TargetPort  int            `json:"target_port"`
	Verdict     common.Verdict `json:"verdict"`
	TimestampMS float64        `json:"timestamp_ms"`
}

// ConnectionOpenData carries connection telemetry for EventConnectionOpen.
type ConnectionOpenData struct {
	SessionID   string  `json:"session_id,omitempty"`
	NetworkZone string  `json:"network_zone"`
	ClientHost  string  `json:"client_host"`
	ClientIP    string  `json:"client_ip"`
	Protocol    string  `json:"protocol"`
	Port        int     `json:"port"`
	TimestampMS float64 `json:"timestamp_ms"`
}

// RateTickData carries sliding-window throughput telemetry for EventRateTick.
type RateTickData struct {
	InstantThroughputMBs float64 `json:"instant_throughput_mbs"`
	PeakThroughputMBs    float64 `json:"peak_throughput_mbs"`
	ActiveStreams        int     `json:"active_streams"`
	TotalBytes           int64   `json:"total_bytes"`
	TimestampMS          float64 `json:"timestamp_ms"`
}

// PortStatus tracks individual port listening and traffic state for port status matrix.
type PortStatus struct {
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"` // "TCP" or "UDP"
	Service    string    `json:"service"`  // "HTTP", "HTTPS", "DNS", "Reflector", etc.
	Status     string    `json:"status"`   // "listening", "receiving", "blocked", "idle", "reflection"
	BytesRecv  int64     `json:"bytes_recv"`
	ProbesRecv int64     `json:"probes_recv"`
	LastActive time.Time `json:"last_active"`
}

// DashboardResetData carries reset confirmation metadata for EventDashboardReset.
type DashboardResetData struct {
	DeletedFiles bool    `json:"deleted_files"`
	EvidenceDir  string  `json:"evidence_dir,omitempty"`
	TimestampMS  float64 `json:"timestamp_ms"`
}

// SafePrefix safely truncates a string to at most maxLen characters without panicking.
func SafePrefix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
