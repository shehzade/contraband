package live

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// GlobalMetrics aggregates top-level dial and gauge values.
type GlobalMetrics struct {
	InstantThroughputMBs float64 `json:"instant_throughput_mbs"`
	PeakThroughputMBs    float64 `json:"peak_throughput_mbs"`
	TotalBytesSmuggled   int64   `json:"total_bytes_smuggled"`
	SmuggledFormatted    string  `json:"smuggled_formatted"`
	ActiveStreams        int     `json:"active_streams"`
	GlobalEEIScore       float64 `json:"global_eei_score"`
	EEIPosture           string  `json:"eei_posture"`
	TotalSessions        int     `json:"total_sessions"`
	TotalChunks          int64   `json:"total_chunks"`
	TotalCredentials     int     `json:"total_credentials"`
	TotalReports         int     `json:"total_reports"`
}

// ZoneMetrics tracks activity per network zone (e.g. CORP-LAN, DMZ, CLOUD-VPC).
type ZoneMetrics struct {
	ZoneName       string   `json:"zone_name"`
	TotalBytes     int64    `json:"total_bytes"`
	BytesFormatted string   `json:"bytes_formatted"`
	ActiveStreams  int      `json:"active_streams"`
	TotalSessions  int      `json:"total_sessions"`
	SuccessCount   int      `json:"success_count"`
	BlockedCount   int      `json:"blocked_count"`
	HostCount      int      `json:"host_count"`
	Hosts          []string `json:"hosts,omitempty"`
}

// ProtocolStatus tracks state and volume for each of the 20 smuggling protocols.
type ProtocolStatus struct {
	Protocol       string    `json:"protocol"`
	Status         string    `json:"status"` // "streaming", "ready", "blocked", "idle"
	TotalBytes     int64     `json:"total_bytes"`
	BytesFormatted string    `json:"bytes_formatted"`
	TotalChunks    int64     `json:"total_chunks"`
	ActiveStreams  int       `json:"active_streams"`
	LastActive     time.Time `json:"last_active"`
}

// TerminalLogEntry represents a live colorized log message.
type TerminalLogEntry struct {
	ID          string  `json:"id,omitempty"`
	Timestamp   string  `json:"timestamp"` // HH:MM:SS.mmm
	TimestampMS float64 `json:"timestamp_ms"`
	Level       string  `json:"level"` // "INFO", "SUCCESS", "WARN", "ALERT", "EXFIL"
	Zone        string  `json:"zone"`
	Host        string  `json:"host"`
	Protocol    string  `json:"protocol"`
	Message     string  `json:"message"`
}

// MetricsState represents the entire live state snapshot for the dashboard.
type MetricsState struct {
	Global          GlobalMetrics             `json:"global"`
	Active          []SessionProgressData     `json:"active_sessions"`
	Recent          []SessionCompleteData     `json:"recent_sessions"`
	Zones           map[string]ZoneMetrics    `json:"zones"`
	Protocols       map[string]ProtocolStatus `json:"protocols"`
	Ports           []PortStatus              `json:"ports"`
	Logs            []TerminalLogEntry        `json:"recent_logs"`
	ReportSummaries []ReportUploadData        `json:"reports"`
}

// MetricsTracker aggregates all metrics with thread safety and sliding window rates.
type MetricsTracker struct {
	mu sync.RWMutex

	global        GlobalMetrics
	active        map[string]*SessionProgressData
	recent        []SessionCompleteData
	zones         map[string]*ZoneMetrics
	protocols     map[string]*ProtocolStatus
	ports         map[int]*PortStatus
	logs          []TerminalLogEntry
	reports       []ReportUploadData
	zoneHosts     map[string]map[string]bool
	knownZones    map[string]string
	knownHosts    map[string]string
	totalProbes   int
	successProbes int
	blockedProbes int
	logSeq        int64

	// Sliding window for instant throughput calculation
	rateMu        sync.Mutex
	windowBytes   int64
	windowStart   time.Time
	lastSampleMBs float64
}

// All standard 20 protocols
var standardProtocols = []string{
	common.ProtoHTTP1, common.ProtoHTTP2, common.ProtoHTTP3, common.ProtoWebSocket,
	common.ProtoGRPC, common.ProtoWebDAV, common.ProtoDNSA, common.ProtoDNSTXT,
	common.ProtoDoH, common.ProtoDoT, common.ProtoFTP, common.ProtoFTPS,
	common.ProtoSFTP, common.ProtoSMTP, common.ProtoSMBTCP, common.ProtoSMBQUIC,
	common.ProtoAWSS3, common.ProtoGCPGCS, common.ProtoAzureBlob,
	common.ProtoICMP, common.ProtoNTP, common.ProtoSyslog, common.ProtoMQTT,
}

// NewMetricsTracker initializes metrics containers, standard protocols, and monitored ports.
func NewMetricsTracker() *MetricsTracker {
	mt := &MetricsTracker{
		active:      make(map[string]*SessionProgressData),
		recent:      make([]SessionCompleteData, 0, 100),
		zones:       make(map[string]*ZoneMetrics),
		protocols:   make(map[string]*ProtocolStatus),
		ports:       make(map[int]*PortStatus),
		logs:        make([]TerminalLogEntry, 0, 200),
		reports:     make([]ReportUploadData, 0, 50),
		zoneHosts:   make(map[string]map[string]bool),
		knownZones:  make(map[string]string),
		knownHosts:  make(map[string]string),
		windowStart: time.Now(),
		global: GlobalMetrics{
			EEIPosture: "Hardened",
		},
	}

	for _, p := range standardProtocols {
		mt.protocols[p] = &ProtocolStatus{
			Protocol:       p,
			Status:         "ready",
			BytesFormatted: "0 B",
		}
	}

	standardPorts := []struct {
		port  int
		proto string
		serv  string
	}{
		{21, "TCP", "FTP"},
		{22, "TCP", "SSH/SFTP"},
		{25, "TCP", "SMTP"},
		{53, "UDP", "DNS"},
		{80, "TCP", "HTTP"},
		{123, "UDP", "NTP"},
		{443, "TCP", "HTTPS"},
		{445, "TCP", "SMB"},
		{465, "TCP", "SMTPS"},
		{514, "UDP", "Syslog"},
		{587, "TCP", "SMTP-Sub"},
		{853, "TCP", "DoT"},
		{990, "TCP", "FTPS"},
		{1883, "TCP", "MQTT"},
		{4430, "UDP", "SMB-QUIC"},
		{6514, "TCP", "Syslog-TLS"},
		{8080, "TCP", "HTTP-Alt"},
		{8443, "TCP", "HTTPS-Alt"},
		{8883, "TCP", "MQTT-TLS"},
		{50051, "TCP", "gRPC"},
	}
	for _, sp := range standardPorts {
		mt.ports[sp.port] = &PortStatus{
			Port:     sp.port,
			Protocol: sp.proto,
			Service:  sp.serv,
			Status:   "listening",
		}
	}

	return mt
}

// FormatBytes formats byte counts into human-readable strings.
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatTimestampMS formats current time as HH:MM:SS.mmm.
func FormatTimestampMS(t time.Time) string {
	return fmt.Sprintf("%02d:%02d:%02d.%03d",
		t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1000000)
}

// ProtoToPort maps standardized protocol strings to standard network listener ports.
func ProtoToPort(proto string) int {
	switch proto {
	case common.ProtoHTTP1, "http1", "http", common.ProtoWebDAV, common.ProtoWebSocket, "websocket", "ws":
		return 80
	case common.ProtoHTTP2, "http2", "https", common.ProtoHTTP3, "http3", "quic", common.ProtoAWSS3, common.ProtoGCPGCS, common.ProtoAzureBlob:
		return 443
	case common.ProtoDNSA, common.ProtoDNSTXT, "dns":
		return 53
	case common.ProtoFTP:
		return 21
	case common.ProtoFTPS:
		return 990
	case common.ProtoSFTP:
		return 22
	case common.ProtoSMTP:
		return 25
	case common.ProtoSMBFile, common.ProtoSMBHash, "smb":
		return 445
	case common.ProtoSMBQUIC:
		return 4430
	case common.ProtoNTPTime, "ntp":
		return 123
	case common.ProtoSyslog:
		return 514
	case common.ProtoMQTT:
		return 1883
	case common.ProtoGRPC, "grpc":
		return 50051
	case common.ProtoDoT, "dot":
		return 853
	case common.ProtoDoH, "doh":
		return 8443
	default:
		return 0
	}
}

// ClassifyNetworkZone determines zone/subnet classification from an IP or hostname.
func ClassifyNetworkZone(clientIP string) string {
	if clientIP == "" {
		return "Default Zone"
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		lower := strings.ToLower(clientIP)
		if strings.Contains(lower, "dmz") {
			return "DMZ"
		}
		if strings.Contains(lower, "cloud") || strings.Contains(lower, "vpc") || strings.Contains(lower, "aws") || strings.Contains(lower, "gcp") {
			return "Cloud VPC"
		}
		if strings.Contains(lower, "branch") {
			return "Branch Office"
		}
		return "Corporate LAN"
	}
	if ip.IsLoopback() {
		return "Localhost"
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return "Corporate LAN"
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return "DMZ"
		case ip4[0] == 192 && ip4[1] == 168:
			return "Branch Office"
		case ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127:
			return "Cloud VPC"
		default:
			return "Cloud VPC"
		}
	}
	return "Cloud VPC"
}

// RecordChunk updates active stream, protocol, zone, and global metrics.
func (mt *MetricsTracker) RecordChunk(p SessionProgressData, chunkSize int64) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Update sliding window bytes for throughput
	mt.rateMu.Lock()
	mt.windowBytes += chunkSize
	mt.rateMu.Unlock()

	// Remember client's explicit zone and hostname if provided
	if p.ClientIP != "" {
		if p.NetworkZone != "" && p.NetworkZone != "DEFAULT" && p.NetworkZone != "Corporate LAN" && p.NetworkZone != "Default Zone" {
			mt.knownZones[p.ClientIP] = p.NetworkZone
		}
		if p.ClientHost != "" && p.ClientHost != p.ClientIP {
			mt.knownHosts[p.ClientIP] = p.ClientHost
		}
	}

	// Auto-classify zone if missing or default, prioritizing learned zone for this client IP
	if p.NetworkZone == "" || p.NetworkZone == "DEFAULT" || p.NetworkZone == "Default Zone" {
		if learnedZone, ok := mt.knownZones[p.ClientIP]; ok && learnedZone != "" {
			p.NetworkZone = learnedZone
		} else {
			p.NetworkZone = ClassifyNetworkZone(p.ClientIP)
		}
	}

	// Populate client host if missing, prioritizing learned host
	if p.ClientHost == "" {
		if learnedHost, ok := mt.knownHosts[p.ClientIP]; ok && learnedHost != "" {
			p.ClientHost = learnedHost
		} else if p.ClientIP != "" {
			p.ClientHost = p.ClientIP
		}
	}

	// Update active session
	sess, exists := mt.active[p.SessionID]
	if !exists {
		pCopy := p
		sess = &pCopy
		mt.active[p.SessionID] = sess
		mt.global.ActiveStreams = len(mt.active)
	} else {
		sess.Sequence = p.Sequence
		sess.TotalChunks = p.TotalChunks
		sess.BytesTransferred = p.BytesTransferred
		sess.TotalBytes = p.TotalBytes
		sess.ProgressPct = p.ProgressPct
		sess.InstantMBs = p.InstantMBs
		sess.RollingHash = p.RollingHash
		sess.ElapsedMS = p.ElapsedMS
		sess.NetworkZone = p.NetworkZone
		if sess.ClientHost == "" && p.ClientHost != "" {
			sess.ClientHost = p.ClientHost
		}
		if sess.ClientIP == "" && p.ClientIP != "" {
			sess.ClientIP = p.ClientIP
		}
		if sess.Protocol == "" && p.Protocol != "" {
			sess.Protocol = p.Protocol
		}
	}

	// Update global counts
	mt.global.TotalBytesSmuggled += chunkSize
	mt.global.SmuggledFormatted = FormatBytes(mt.global.TotalBytesSmuggled)
	mt.global.TotalChunks++

	// Update zone
	zoneName := p.NetworkZone
	if zoneName == "" {
		zoneName = "Default Zone"
	}
	zm, zExists := mt.zones[zoneName]
	if !zExists {
		zm = &ZoneMetrics{ZoneName: zoneName, BytesFormatted: "0 B"}
		mt.zones[zoneName] = zm
		mt.zoneHosts[zoneName] = make(map[string]bool)
	}
	zm.TotalBytes += chunkSize
	zm.BytesFormatted = FormatBytes(zm.TotalBytes)
	if p.ClientHost != "" {
		mt.zoneHosts[zoneName][p.ClientHost] = true
	} else if p.ClientIP != "" {
		mt.zoneHosts[zoneName][p.ClientIP] = true
	} else {
		mt.zoneHosts[zoneName]["host-unknown"] = true
	}
	zm.HostCount = len(mt.zoneHosts[zoneName])

	// Recount active streams for zone
	activeInZone := 0
	for _, act := range mt.active {
		if act.NetworkZone == zoneName {
			activeInZone++
		}
	}
	zm.ActiveStreams = activeInZone

	// Update protocol
	proto := p.Protocol
	if ps, ok := mt.protocols[proto]; ok {
		ps.TotalBytes += chunkSize
		ps.BytesFormatted = FormatBytes(ps.TotalBytes)
		ps.TotalChunks++
		ps.Status = "streaming"
		ps.LastActive = time.Now()
		// Count active streams for this protocol
		activeInProto := 0
		for _, act := range mt.active {
			if act.Protocol == proto {
				activeInProto++
			}
		}
		ps.ActiveStreams = activeInProto
	}

	// Update monitored port status
	port := p.Port
	if port <= 0 {
		port = ProtoToPort(p.Protocol)
	}
	if port > 0 {
		if ps, ok := mt.ports[port]; ok {
			ps.Status = "receiving"
			ps.BytesRecv += chunkSize
			ps.LastActive = time.Now()
		}
	}
}

// RecordSessionComplete finalizes an active session.
func (mt *MetricsTracker) RecordSessionComplete(sc SessionCompleteData) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	delete(mt.active, sc.SessionID)
	mt.global.ActiveStreams = len(mt.active)
	mt.global.TotalSessions++

	if sc.ClientIP != "" {
		if sc.NetworkZone != "" && sc.NetworkZone != "DEFAULT" && sc.NetworkZone != "Corporate LAN" && sc.NetworkZone != "Default Zone" {
			mt.knownZones[sc.ClientIP] = sc.NetworkZone
		}
		if sc.ClientHost != "" && sc.ClientHost != sc.ClientIP {
			mt.knownHosts[sc.ClientIP] = sc.ClientHost
		}
	}

	if sc.NetworkZone == "" || sc.NetworkZone == "DEFAULT" || sc.NetworkZone == "Default Zone" {
		if learnedZone, ok := mt.knownZones[sc.ClientIP]; ok && learnedZone != "" {
			sc.NetworkZone = learnedZone
		} else {
			sc.NetworkZone = ClassifyNetworkZone(sc.ClientIP)
		}
	}

	if sc.ClientHost == "" {
		if learnedHost, ok := mt.knownHosts[sc.ClientIP]; ok && learnedHost != "" {
			sc.ClientHost = learnedHost
		} else if sc.ClientIP != "" {
			sc.ClientHost = sc.ClientIP
		}
	}

	// Append to recent sessions (keep max 100)
	mt.recent = append([]SessionCompleteData{sc}, mt.recent...)
	if len(mt.recent) > 100 {
		mt.recent = mt.recent[:100]
	}

	// Update zone stats
	zoneName := sc.NetworkZone
	if zoneName == "" {
		zoneName = "Default Zone"
	}
	if zm, ok := mt.zones[zoneName]; ok {
		zm.TotalSessions++
		if sc.Verdict.IsSuccess() {
			zm.SuccessCount++
		} else {
			zm.BlockedCount++
		}
		activeInZone := 0
		for _, act := range mt.active {
			if act.NetworkZone == zoneName {
				activeInZone++
			}
		}
		zm.ActiveStreams = activeInZone
	}

	// Update protocol status
	if ps, ok := mt.protocols[sc.Protocol]; ok {
		activeInProto := 0
		for _, act := range mt.active {
			if act.Protocol == sc.Protocol {
				activeInProto++
			}
		}
		ps.ActiveStreams = activeInProto
		if activeInProto == 0 {
			if sc.Verdict.IsBlocked() {
				ps.Status = "blocked"
			} else {
				ps.Status = "ready"
			}
		}
	}

	// Update port status
	port := sc.Port
	if port <= 0 {
		port = ProtoToPort(sc.Protocol)
	}
	if port > 0 {
		if ps, ok := mt.ports[port]; ok {
			if sc.Verdict.IsBlocked() {
				ps.Status = "blocked"
				ps.LastActive = time.Now()
			} else {
				// Keep LastActive fresh so the 3-second decay loop transitions status back to listening gracefully,
				// ensuring UI can visibly display receiving indicator.
				ps.LastActive = time.Now()
			}
		}
	}

	// Add log entry
	logLevel := "SUCCESS"
	if sc.Verdict.IsBlocked() {
		logLevel = "ALERT"
	}
	now := time.Now()
	mt.addLogLocked(TerminalLogEntry{
		Timestamp:   FormatTimestampMS(now),
		TimestampMS: float64(now.UnixNano()) / 1e6,
		Level:       logLevel,
		Zone:        sc.NetworkZone,
		Host:        sc.ClientHost,
		Protocol:    sc.Protocol,
		Message:     fmt.Sprintf("[%s] Session %s complete (%s transferred in %.2fms, avg %.2f MB/s, verdict: %s)", sc.Protocol, SafePrefix(sc.SessionID, 8), FormatBytes(sc.TotalBytes), sc.DurationMS, sc.AverageMBs, sc.Verdict),
	})
}

// RecordProbe records an individual probe result, updating EEI risk score and port status.
func (mt *MetricsTracker) RecordProbe(p common.ProbeResult) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.totalProbes++
	if p.Verdict.IsSuccess() {
		mt.successProbes++
	} else if p.Verdict.IsBlocked() {
		mt.blockedProbes++
	}

	if mt.totalProbes > 0 {
		score := (float64(mt.successProbes) / float64(mt.totalProbes)) * 100.0
		mt.global.GlobalEEIScore = math.Round(score*100) / 100
		if score >= 75.0 {
			mt.global.EEIPosture = "Critical"
		} else if score >= 40.0 {
			mt.global.EEIPosture = "Moderate"
		} else {
			mt.global.EEIPosture = "Hardened"
		}
	}

	// Update port status
	port := ProtoToPort(p.Protocol)
	if port == 0 && p.TargetPort > 0 {
		port = p.TargetPort
	}
	if port > 0 {
		if ps, ok := mt.ports[port]; ok {
			ps.ProbesRecv++
			ps.BytesRecv += p.BytesSent + p.BytesRecv
			ps.LastActive = time.Now()
			if p.Verdict.IsSuccess() {
				ps.Status = "reflection"
			} else if p.Verdict.IsBlocked() {
				ps.Status = "blocked"
			}
		}
	}

	// Terminal log
	now := time.Now()
	level := "INFO"
	if p.Verdict.IsSuccess() {
		level = "EXFIL"
	} else if p.Verdict.IsBlocked() {
		level = "ALERT"
	}
	mt.addLogLocked(TerminalLogEntry{
		Timestamp:   FormatTimestampMS(now),
		TimestampMS: float64(now.UnixNano()) / 1e6,
		Level:       level,
		Zone:        ClassifyNetworkZone(p.TargetHost),
		Host:        p.TargetHost,
		Protocol:    p.Protocol,
		Message:     fmt.Sprintf("[%s] Probe recorded port %d: %s (sent %s)", p.Protocol, port, p.Verdict, FormatBytes(p.BytesSent)),
	})
}

// RecordReportUpload stores synced assessment report metadata.
func (mt *MetricsTracker) RecordReportUpload(r ReportUploadData) {
	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.reports = append([]ReportUploadData{r}, mt.reports...)
	if len(mt.reports) > 50 {
		mt.reports = mt.reports[:50]
	}
	mt.global.TotalReports = len(mt.reports)

	// Update Global EEI score to the latest or average report score
	mt.global.GlobalEEIScore = r.EEIScore
	mt.global.EEIPosture = r.Posture

	now := time.Now()
	mt.addLogLocked(TerminalLogEntry{
		Timestamp:   FormatTimestampMS(now),
		TimestampMS: float64(now.UnixNano()) / 1e6,
		Level:       "INFO",
		Zone:        r.NetworkZone,
		Host:        r.ClientHost,
		Protocol:    "ASSESSMENT",
		Message:     fmt.Sprintf("Client report synced: %s (EEI: %.2f%%, %d probes, %d succeeded, %d blocked)", SafePrefix(r.ReportID, 8), r.EEIScore, r.TotalProbes, r.SuccessCount, r.BlockedL4+r.BlockedL7+r.BlockedDLP),
	})
}

// AddLog appends a live terminal log entry.
func (mt *MetricsTracker) AddLog(entry TerminalLogEntry) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.addLogLocked(entry)
}

func (mt *MetricsTracker) addLogLocked(entry TerminalLogEntry) {
	now := time.Now()
	if entry.Timestamp == "" {
		entry.Timestamp = FormatTimestampMS(now)
	}
	if entry.TimestampMS == 0 {
		entry.TimestampMS = float64(now.UnixNano()) / 1e6
	}
	if entry.ID == "" {
		mt.logSeq++
		entry.ID = fmt.Sprintf("log-%d", mt.logSeq)
	}
	mt.logs = append(mt.logs, entry)
	if len(mt.logs) > 200 {
		mt.logs = mt.logs[len(mt.logs)-200:]
	}
}

// Reset clears all active/recent sessions, logs, reports, and zeroes all dials and matrices.
func (mt *MetricsTracker) Reset() {
	mt.rateMu.Lock()
	mt.windowBytes = 0
	mt.windowStart = time.Now()
	mt.lastSampleMBs = 0
	mt.rateMu.Unlock()

	mt.mu.Lock()
	defer mt.mu.Unlock()

	mt.global = GlobalMetrics{
		InstantThroughputMBs: 0,
		PeakThroughputMBs:    0,
		TotalBytesSmuggled:   0,
		SmuggledFormatted:    "0 B",
		ActiveStreams:        0,
		GlobalEEIScore:       0,
		EEIPosture:           "Hardened",
		TotalSessions:        0,
		TotalChunks:          0,
		TotalCredentials:     0,
		TotalReports:         0,
	}

	mt.active = make(map[string]*SessionProgressData)
	mt.recent = make([]SessionCompleteData, 0, 100)
	mt.zones = make(map[string]*ZoneMetrics)
	mt.zoneHosts = make(map[string]map[string]bool)
	mt.reports = make([]ReportUploadData, 0, 50)
	mt.logs = make([]TerminalLogEntry, 0, 200)
	mt.totalProbes = 0
	mt.successProbes = 0
	mt.blockedProbes = 0

	for _, ps := range mt.protocols {
		ps.Status = "ready"
		ps.TotalBytes = 0
		ps.BytesFormatted = "0 B"
		ps.TotalChunks = 0
		ps.ActiveStreams = 0
		ps.LastActive = time.Time{}
	}

	for _, ps := range mt.ports {
		ps.Status = "listening"
		ps.BytesRecv = 0
		ps.ProbesRecv = 0
		ps.LastActive = time.Time{}
	}

	now := time.Now()
	mt.addLogLocked(TerminalLogEntry{
		Timestamp:   FormatTimestampMS(now),
		TimestampMS: float64(now.UnixNano()) / 1e6,
		Level:       "INFO",
		Message:     "Dashboard telemetry reset by operator",
	})
}

// TickWindow recalculates instantaneous throughput and decay idle protocol states.
func (mt *MetricsTracker) TickWindow() {
	now := time.Now()

	mt.rateMu.Lock()
	elapsed := now.Sub(mt.windowStart).Seconds()
	bytes := mt.windowBytes
	mt.windowBytes = 0
	mt.windowStart = now
	mt.rateMu.Unlock()

	var instantMBs float64
	if elapsed > 0 {
		instantMBs = (float64(bytes) / (1024 * 1024)) / elapsed
	}

	mt.mu.Lock()
	defer mt.mu.Unlock()

	// Smooth or update instant throughput
	mt.lastSampleMBs = math.Round(instantMBs*100) / 100
	mt.global.InstantThroughputMBs = mt.lastSampleMBs
	if mt.lastSampleMBs > mt.global.PeakThroughputMBs {
		mt.global.PeakThroughputMBs = mt.lastSampleMBs
	}

	// Decay protocols from streaming to ready if no active streams
	for _, ps := range mt.protocols {
		if ps.ActiveStreams == 0 && ps.Status == "streaming" && now.Sub(ps.LastActive) > 3*time.Second {
			ps.Status = "ready"
		}
	}

	// Decay ports from reflection/receiving to listening if inactive for >3s
	for _, ps := range mt.ports {
		if (ps.Status == "reflection" || ps.Status == "receiving") && now.Sub(ps.LastActive) > 3*time.Second {
			ps.Status = "listening"
		}
	}
}

// Snapshot returns a complete, thread-safe deep copy of the current metrics state.
func (mt *MetricsTracker) Snapshot() MetricsState {
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	state := MetricsState{
		Global:          mt.global,
		Active:          make([]SessionProgressData, 0, len(mt.active)),
		Recent:          make([]SessionCompleteData, len(mt.recent)),
		Zones:           make(map[string]ZoneMetrics, len(mt.zones)),
		Protocols:       make(map[string]ProtocolStatus, len(mt.protocols)),
		Logs:            make([]TerminalLogEntry, len(mt.logs)),
		ReportSummaries: make([]ReportUploadData, len(mt.reports)),
	}

	for _, a := range mt.active {
		state.Active = append(state.Active, *a)
	}
	copy(state.Recent, mt.recent)
	copy(state.Logs, mt.logs)
	copy(state.ReportSummaries, mt.reports)

	for k, v := range mt.zones {
		zm := *v
		if hosts, ok := mt.zoneHosts[k]; ok {
			hostList := make([]string, 0, len(hosts))
			for h := range hosts {
				hostList = append(hostList, h)
			}
			zm.Hosts = hostList
		}
		state.Zones[k] = zm
	}

	for k, v := range mt.protocols {
		state.Protocols[k] = *v
	}

	portsList := make([]PortStatus, 0, len(mt.ports))
	for _, p := range mt.ports {
		portsList = append(portsList, *p)
	}
	sort.Slice(portsList, func(i, j int) bool {
		return portsList[i].Port < portsList[j].Port
	})
	state.Ports = portsList

	return state
}
