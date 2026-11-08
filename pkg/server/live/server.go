package live

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/report"
)

//go:embed dashboard.html
var dashboardHTML []byte

// ResetCallback is invoked when an operator triggers a dashboard state reset.
type ResetCallback func(deleteFiles bool) error

// ResetRequest defines the JSON payload for resetting the dashboard.
type ResetRequest struct {
	DeleteFiles bool `json:"delete_files"`
}

// ResetResponse models the confirmation payload returned by the reset API.
type ResetResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	DeletedFiles bool   `json:"deleted_files"`
	EvidenceDir  string `json:"evidence_dir,omitempty"`
}

// DashboardServer coordinates the HTTP live dashboard and report center.
type DashboardServer struct {
	mu            sync.Mutex
	hub           *LiveHub
	httpServer    *http.Server
	listener      net.Listener
	addr          string
	evidenceDir   string
	resetCallback ResetCallback
	closed        bool
}

// UploadReportPayload models the payload sent by the client when syncing its report.
type UploadReportPayload struct {
	Report      *report.AssessmentReport `json:"report"`
	RawHTML     string                   `json:"raw_html,omitempty"`
	RawJSON     string                   `json:"raw_json,omitempty"`
	RawSARIF    string                   `json:"raw_sarif,omitempty"`
	Remediation string                   `json:"remediation,omitempty"`
	NetworkZone string                   `json:"network_zone,omitempty"`
	ClientHost  string                   `json:"client_host,omitempty"`
	ClientIP    string                   `json:"client_ip,omitempty"`
}

// NewDashboardServer creates and binds a new DashboardServer instance.
func NewDashboardServer(bindAddr string, hub *LiveHub) (*DashboardServer, error) {
	if hub == nil {
		hub = NewLiveHub()
	}

	if bindAddr == "" {
		bindAddr = "0.0.0.0:8080"
	}
	if !strings.Contains(bindAddr, ":") {
		bindAddr = ":" + bindAddr
	}

	ln, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind live dashboard on %s: %w", bindAddr, err)
	}

	ds := &DashboardServer{
		hub:      hub,
		listener: ln,
		addr:     ln.Addr().String(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ds.handleRoot)
	mux.HandleFunc("/dashboard", ds.handleDashboard)
	mux.HandleFunc("/api/v1/live/events", ds.handleSSEEvents)
	mux.HandleFunc("/events", ds.handleSSEEvents)
	mux.HandleFunc("/api/stream", ds.handleSSEEvents)
	mux.HandleFunc("/api/v1/live/metrics", ds.handleMetrics)
	mux.HandleFunc("/metrics", ds.handleMetrics)
	mux.HandleFunc("/api/metrics", ds.handleMetrics)
	mux.HandleFunc("/api/v1/reports", ds.handleReports)
	mux.HandleFunc("/api/v1/reports/", ds.handleReportArtifacts)
	mux.HandleFunc("/reports", ds.handleDashboard)
	mux.HandleFunc("/api/v1/live/reset", ds.handleReset)
	mux.HandleFunc("/api/v1/reset", ds.handleReset)

	ds.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0, // SSE requires unbounded write timeout
		IdleTimeout:  60 * time.Second,
	}

	return ds, nil
}

// Addr returns the bound TCP address.
func (ds *DashboardServer) Addr() string {
	return ds.addr
}

// Hub returns the underlying LiveHub.
func (ds *DashboardServer) Hub() *LiveHub {
	return ds.hub
}

// SetEvidenceDir sets the directory path for reconstructed payload evidence.
func (ds *DashboardServer) SetEvidenceDir(dir string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.evidenceDir = dir
}

// SetResetCallback registers a hook executed whenever an operator resets the dashboard.
func (ds *DashboardServer) SetResetCallback(cb ResetCallback) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.resetCallback = cb
}

// Start begins serving HTTP and SSE requests.
func (ds *DashboardServer) Start(ctx context.Context) error {
	ds.hub.Start(ctx)

	go func() {
		<-ctx.Done()
		_ = ds.Shutdown(context.Background())
	}()

	err := ds.httpServer.Serve(ds.listener)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Shutdown gracefully terminates the dashboard server.
func (ds *DashboardServer) Shutdown(ctx context.Context) error {
	ds.mu.Lock()
	if ds.closed {
		ds.mu.Unlock()
		return nil
	}
	ds.closed = true
	ds.mu.Unlock()

	ds.hub.Stop()
	return ds.httpServer.Shutdown(ctx)
}

func (ds *DashboardServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusTemporaryRedirect)
}

func (ds *DashboardServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dashboardHTML)
}

func (ds *DashboardServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	snapshot := ds.hub.GetMetricsSnapshot()
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (ds *DashboardServer) handleSSEEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := ds.hub.Subscribe()
	defer ds.hub.Unsubscribe(ch)

	// Send initial snapshot on connect
	initialState := ds.hub.GetMetricsSnapshot()
	initData, _ := json.Marshal(LiveEvent{
		ID:          fmt.Sprintf("init-%d", time.Now().UnixMilli()),
		Type:        EventHeartbeat,
		Timestamp:   time.Now(),
		TimestampMS: float64(time.Now().UnixNano()) / 1e6,
		Message:     "Initial snapshot",
		Data:        initialState,
	})
	_, _ = fmt.Fprintf(w, "event: heartbeat\ndata: %s\n\n", initData)
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, data)
			flusher.Flush()
		}
	}
}

func (ds *DashboardServer) handleReports(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		reports := ds.hub.ListReports()
		_ = json.NewEncoder(w).Encode(reports)

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024)) // 8MB ceiling for heap invariant
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to read payload: %v", err), http.StatusBadRequest)
			return
		}

		var payload UploadReportPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, fmt.Sprintf("Malformed report JSON: %v", err), http.StatusBadRequest)
			return
		}

		if payload.Report == nil {
			http.Error(w, "Missing 'report' field in payload", http.StatusBadRequest)
			return
		}

		clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
		if payload.ClientIP == "" {
			payload.ClientIP = clientIP
		}

		// Save report
		reportID := ds.hub.StoreReport(
			payload.Report,
			[]byte(payload.RawHTML),
			[]byte(payload.RawJSON),
			[]byte(payload.RawSARIF),
			[]byte(payload.Remediation),
			payload.NetworkZone,
			payload.ClientHost,
			payload.ClientIP,
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":    "OK",
			"report_id": reportID,
			"url":       fmt.Sprintf("/reports"),
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ds *DashboardServer) handleReportArtifacts(w http.ResponseWriter, r *http.Request) {
	// Path pattern: /api/v1/reports/{id}/{artifact}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/reports/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}

	reportID := parts[0]
	artifact := parts[1]

	rep, ok := ds.hub.GetReport(reportID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch artifact {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if len(rep.RawHTML) > 0 {
			_, _ = w.Write(rep.RawHTML)
		} else {
			// Dynamically render if raw HTML wasn't provided
			htmlStr, err := report.GenerateHTML(rep.Report)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to render HTML: %v", err), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte(htmlStr))
		}

	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"contraband_report_%s.json\"", reportID))
		if len(rep.RawJSON) > 0 {
			_, _ = w.Write(rep.RawJSON)
		} else {
			_ = json.NewEncoder(w).Encode(rep.Report)
		}

	case "sarif":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"contraband_report_%s.sarif\"", reportID))
		if len(rep.RawSARIF) > 0 {
			_, _ = w.Write(rep.RawSARIF)
		} else {
			sarifBytes, err := report.ExportSARIF(rep.Report)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to render SARIF: %v", err), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(sarifBytes)
		}

	case "remediation":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"contraband_remediation_%s.sh\"", reportID))
		if len(rep.Remediation) > 0 {
			_, _ = w.Write(rep.Remediation)
		} else {
			ruleSet := report.GenerateRemediation(rep.Report.Probes, rep.Report.TargetHost)
			_, _ = w.Write([]byte(ruleSet.FormatAll()))
		}

	default:
		http.NotFound(w, r)
	}
}

func (ds *DashboardServer) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed, use POST", http.StatusMethodNotAllowed)
		return
	}

	var req ResetRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	ds.mu.Lock()
	cb := ds.resetCallback
	evDir := ds.evidenceDir
	ds.mu.Unlock()

	var callbackErr error
	if cb != nil {
		callbackErr = cb(req.DeleteFiles)
	}

	ds.hub.Reset(req.DeleteFiles, evDir)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp := ResetResponse{
		Success:      callbackErr == nil,
		Message:      "Dashboard telemetry reset successfully",
		DeletedFiles: req.DeleteFiles,
		EvidenceDir:  evDir,
	}
	if callbackErr != nil {
		resp.Message = fmt.Sprintf("Reset completed with warnings: %v", callbackErr)
	}
	_ = json.NewEncoder(w).Encode(resp)
}
