package live

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/report"
)

// StoredReport retains an uploaded client assessment report with its pre-rendered artifacts.
type StoredReport struct {
	ID          string                   `json:"id"`
	Report      *report.AssessmentReport `json:"report"`
	RawHTML     []byte                   `json:"-"`
	RawJSON     []byte                   `json:"-"`
	RawSARIF    []byte                   `json:"-"`
	Remediation []byte                   `json:"-"`
	NetworkZone string                   `json:"network_zone"`
	ClientHost  string                   `json:"client_host"`
	ClientIP    string                   `json:"client_ip"`
	UploadedAt  time.Time                `json:"uploaded_at"`
}

// LiveHub coordinates SSE subscribers, real-time metrics, and report storage.
type LiveHub struct {
	startOnce   sync.Once
	metrics     *MetricsTracker
	subMu       sync.RWMutex
	subscribers map[chan LiveEvent]bool

	repMu   sync.RWMutex
	reports map[string]*StoredReport

	ctx    context.Context
	cancel context.CancelFunc
}

// NewLiveHub creates and returns an initialized hub.
func NewLiveHub() *LiveHub {
	return &LiveHub{
		metrics:     NewMetricsTracker(),
		subscribers: make(map[chan LiveEvent]bool),
		reports:     make(map[string]*StoredReport),
	}
}

// Start begins background telemetry calculation, rate ticks, and heartbeat broadcasts.
func (h *LiveHub) Start(ctx context.Context) {
	h.startOnce.Do(func() {
		h.ctx, h.cancel = context.WithCancel(ctx)

		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-h.ctx.Done():
					return
				case <-ticker.C:
					h.metrics.TickWindow()

					snapshot := h.metrics.Snapshot()
					now := time.Now()
					nowMS := float64(now.UnixNano()) / 1e6

					// 1. Broadcast sliding window rate tick
					h.Broadcast(LiveEvent{
						ID:          fmt.Sprintf("tick-%d", now.UnixMilli()),
						Type:        EventRateTick,
						Timestamp:   now,
						TimestampMS: nowMS,
						Message:     fmt.Sprintf("Rate tick: %.2f MB/s (peak: %.2f MB/s, streams: %d)", snapshot.Global.InstantThroughputMBs, snapshot.Global.PeakThroughputMBs, snapshot.Global.ActiveStreams),
						Data: RateTickData{
							InstantThroughputMBs: snapshot.Global.InstantThroughputMBs,
							PeakThroughputMBs:    snapshot.Global.PeakThroughputMBs,
							ActiveStreams:        snapshot.Global.ActiveStreams,
							TotalBytes:           snapshot.Global.TotalBytesSmuggled,
							TimestampMS:          nowMS,
						},
					})

					// 2. Broadcast periodic heartbeat with complete snapshot
					h.Broadcast(LiveEvent{
						ID:          fmt.Sprintf("hb-%d", now.UnixMilli()),
						Type:        EventHeartbeat,
						Timestamp:   now,
						TimestampMS: nowMS,
						Message:     "Heartbeat update",
						Data:        snapshot,
					})
				}
			}
		}()
	})
}

// Stop shuts down the hub and disconnects subscribers.
func (h *LiveHub) Stop() {
	if h.cancel != nil {
		h.cancel()
	}
	h.subMu.Lock()
	defer h.subMu.Unlock()
	for ch := range h.subscribers {
		close(ch)
		delete(h.subscribers, ch)
	}
}

// Subscribe registers a new SSE event listener.
func (h *LiveHub) Subscribe() chan LiveEvent {
	ch := make(chan LiveEvent, 256)
	h.subMu.Lock()
	h.subscribers[ch] = true
	h.subMu.Unlock()
	return ch
}

// Unsubscribe removes an SSE event listener.
func (h *LiveHub) Unsubscribe(ch chan LiveEvent) {
	h.subMu.Lock()
	defer h.subMu.Unlock()
	if _, ok := h.subscribers[ch]; ok {
		delete(h.subscribers, ch)
		close(ch)
	}
}

// Broadcast sends an event to all subscribers without blocking callers.
func (h *LiveHub) Broadcast(event LiveEvent) {
	h.subMu.RLock()
	defer h.subMu.RUnlock()

	for ch := range h.subscribers {
		select {
		case ch <- event:
		default:
			// Non-blocking drop for slow consumers to prevent stalling the hub
		}
	}
}

// RecordConnectionOpen registers a new client connection arrival and broadcasts connection_open.
func (h *LiveHub) RecordConnectionOpen(zone, host, ip, proto string, port int, sessionID string) {
	now := time.Now()
	nowMS := float64(now.UnixNano()) / 1e6
	if zone == "" {
		zone = ClassifyNetworkZone(ip)
	}
	if host == "" {
		host = ip
	}

	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("conn-%d", now.UnixNano()),
		Type:        EventConnectionOpen,
		Timestamp:   now,
		TimestampMS: nowMS,
		SessionID:   sessionID,
		NetworkZone: zone,
		ClientHost:  host,
		ClientIP:    ip,
		Protocol:    proto,
		Message:     fmt.Sprintf("[%s] Connection opened from %s (%s:%d)", proto, host, ip, port),
		Data: ConnectionOpenData{
			SessionID:   sessionID,
			NetworkZone: zone,
			ClientHost:  host,
			ClientIP:    ip,
			Protocol:    proto,
			Port:        port,
			TimestampMS: nowMS,
		},
	})
}

// RecordChunk registers an incoming payload chunk and broadcasts chunk_received.
func (h *LiveHub) RecordChunk(p SessionProgressData, chunkSize int64) {
	h.metrics.RecordChunk(p, chunkSize)

	now := time.Now()
	nowMS := float64(now.UnixNano()) / 1e6
	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("chk-%s-%d", SafePrefix(p.SessionID, 8), p.Sequence),
		Type:        EventChunkReceived,
		Timestamp:   now,
		TimestampMS: nowMS,
		SessionID:   p.SessionID,
		NetworkZone: p.NetworkZone,
		ClientHost:  p.ClientHost,
		ClientIP:    p.ClientIP,
		Protocol:    p.Protocol,
		Message:     fmt.Sprintf("[%s] Chunk %d/%d received (%.2f MB/s)", p.Protocol, p.Sequence, p.TotalChunks, p.InstantMBs),
		Data:        p,
	})
}

// RecordSessionComplete registers session finalization and broadcasts session_complete.
func (h *LiveHub) RecordSessionComplete(sc SessionCompleteData) {
	h.metrics.RecordSessionComplete(sc)

	now := time.Now()
	nowMS := float64(now.UnixNano()) / 1e6
	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("done-%s", SafePrefix(sc.SessionID, 8)),
		Type:        EventSessionComplete,
		Timestamp:   now,
		TimestampMS: nowMS,
		SessionID:   sc.SessionID,
		NetworkZone: sc.NetworkZone,
		ClientHost:  sc.ClientHost,
		ClientIP:    sc.ClientIP,
		Protocol:    sc.Protocol,
		Message:     fmt.Sprintf("[%s] Session completed with verdict %s (%s in %.2fms)", sc.Protocol, sc.Verdict, FormatBytes(sc.TotalBytes), sc.DurationMS),
		Data:        sc,
	})
}

// RecordProbe registers an individual reflection/sweep probe result and broadcasts probe_received.
func (h *LiveHub) RecordProbe(p common.ProbeResult) {
	h.metrics.RecordProbe(p)

	now := time.Now()
	nowMS := float64(now.UnixNano()) / 1e6
	zone := ClassifyNetworkZone(p.TargetHost)

	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("prb-%d", now.UnixNano()),
		Type:        EventProbeReceived,
		Timestamp:   now,
		TimestampMS: nowMS,
		NetworkZone: zone,
		ClientHost:  p.TargetHost,
		ClientIP:    p.LocalAddr,
		Protocol:    p.Protocol,
		Message:     fmt.Sprintf("[%s] Probe recorded for %s:%d: %s", p.Protocol, p.TargetHost, p.TargetPort, p.Verdict),
		Data: ProbeData{
			ProbeID:     p.ID,
			NetworkZone: zone,
			ClientHost:  p.TargetHost,
			ClientIP:    p.LocalAddr,
			Protocol:    p.Protocol,
			TargetPort:  p.TargetPort,
			Verdict:     p.Verdict,
			TimestampMS: nowMS,
		},
	})
}

// StoreReport saves an uploaded assessment report bundle and broadcasts notification.
func (h *LiveHub) StoreReport(rep *report.AssessmentReport, rawHTML, rawJSON, rawSARIF, remediation []byte, zone, host, ip string) string {
	reportID := rep.ID
	if reportID == "" {
		reportID = fmt.Sprintf("rep-%d", time.Now().UnixMilli())
		rep.ID = reportID
	}

	stored := &StoredReport{
		ID:          reportID,
		Report:      rep,
		RawHTML:     rawHTML,
		RawJSON:     rawJSON,
		RawSARIF:    rawSARIF,
		Remediation: remediation,
		NetworkZone: zone,
		ClientHost:  host,
		ClientIP:    ip,
		UploadedAt:  time.Now(),
	}

	h.repMu.Lock()
	const maxRetainedReports = 50
	if len(h.reports) >= maxRetainedReports {
		for oldID := range h.reports {
			delete(h.reports, oldID)
			break
		}
	}
	h.reports[reportID] = stored
	h.repMu.Unlock()

	summary := ReportUploadData{
		ReportID:     reportID,
		TargetHost:   rep.TargetHost,
		NetworkZone:  zone,
		ClientHost:   host,
		ClientIP:     ip,
		EEIScore:     rep.Summary.EEIScore,
		Posture:      string(rep.Summary.Posture),
		TotalProbes:  rep.Summary.TotalProbes,
		SuccessCount: rep.Summary.SuccessCount,
		BlockedL4:    rep.Summary.BlockedL4,
		BlockedL7:    rep.Summary.BlockedL7,
		BlockedDLP:   rep.Summary.BlockedDLP,
		UploadedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	h.metrics.RecordReportUpload(summary)

	now := time.Now()
	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("rep-event-%s", SafePrefix(reportID, 8)),
		Type:        EventReportUploaded,
		Timestamp:   now,
		TimestampMS: float64(now.UnixNano()) / 1e6,
		NetworkZone: zone,
		ClientHost:  host,
		ClientIP:    ip,
		Message:     fmt.Sprintf("New Assessment Report uploaded: %s (EEI: %.2f%%)", SafePrefix(reportID, 8), rep.Summary.EEIScore),
		Data:        summary,
	})

	return reportID
}

// GetReport retrieves a stored report by ID.
func (h *LiveHub) GetReport(id string) (*StoredReport, bool) {
	h.repMu.RLock()
	defer h.repMu.RUnlock()
	rep, ok := h.reports[id]
	return rep, ok
}

// ListReports returns summaries of all uploaded reports.
func (h *LiveHub) ListReports() []ReportUploadData {
	h.repMu.RLock()
	defer h.repMu.RUnlock()

	list := make([]ReportUploadData, 0, len(h.reports))
	for _, r := range h.reports {
		list = append(list, ReportUploadData{
			ReportID:     r.ID,
			TargetHost:   r.Report.TargetHost,
			NetworkZone:  r.NetworkZone,
			ClientHost:   r.ClientHost,
			ClientIP:     r.ClientIP,
			EEIScore:     r.Report.Summary.EEIScore,
			Posture:      string(r.Report.Summary.Posture),
			TotalProbes:  r.Report.Summary.TotalProbes,
			SuccessCount: r.Report.Summary.SuccessCount,
			BlockedL4:    r.Report.Summary.BlockedL4,
			BlockedL7:    r.Report.Summary.BlockedL7,
			BlockedDLP:   r.Report.Summary.BlockedDLP,
			UploadedAt:   r.UploadedAt.UTC().Format(time.RFC3339),
		})
	}
	return list
}

// GetMetricsSnapshot returns the current state of metrics.
func (h *LiveHub) GetMetricsSnapshot() MetricsState {
	return h.metrics.Snapshot()
}

// AddLog appends a live terminal log.
func (h *LiveHub) AddLog(level, zone, host, proto, msg string) {
	now := time.Now()
	entry := TerminalLogEntry{
		Timestamp:   FormatTimestampMS(now),
		TimestampMS: float64(now.UnixNano()) / 1e6,
		Level:       level,
		Zone:        zone,
		Host:        host,
		Protocol:    proto,
		Message:     msg,
	}
	h.metrics.AddLog(entry)
}

// Reset clears all metrics, active sessions, logs, and stored reports, and broadcasts EventDashboardReset.
func (h *LiveHub) Reset(deletedFiles bool, evidenceDir string) {
	h.metrics.Reset()

	h.repMu.Lock()
	h.reports = make(map[string]*StoredReport)
	h.repMu.Unlock()

	now := time.Now()
	nowMS := float64(now.UnixNano()) / 1e6
	h.Broadcast(LiveEvent{
		ID:          fmt.Sprintf("reset-%d", now.UnixMilli()),
		Type:        EventDashboardReset,
		Timestamp:   now,
		TimestampMS: nowMS,
		Message:     "Dashboard telemetry and metrics reset by operator",
		Data: DashboardResetData{
			DeletedFiles: deletedFiles,
			EvidenceDir:  evidenceDir,
			TimestampMS:  nowMS,
		},
	})
}

// MarshalJSON marshals current metrics snapshot for API endpoints.
func (h *LiveHub) MarshalJSON() ([]byte, error) {
	return json.Marshal(h.metrics.Snapshot())
}
