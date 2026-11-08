package report

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ServerOptions configures the embedded reporting web server.
type ServerOptions struct {
	BindAddr        string
	InputPath       string
	Report          *AssessmentReport
	AutoOpen        bool
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// MiniServer encapsulates the HTTP reporting listener and routes.
type MiniServer struct {
	httpServer *http.Server
	listener   net.Listener
	report     *AssessmentReport
	addr       string
	autoOpen   bool
	startTime  time.Time
}

// NewMiniServer initializes the HTTP server on the configured address.
func NewMiniServer(opts ServerOptions) (*MiniServer, error) {
	if opts.Report == nil {
		if opts.InputPath == "" {
			return nil, errors.New("must provide either Report or InputPath to MiniServer")
		}
		rep, err := LoadReport(opts.InputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load assessment report: %w", err)
		}
		opts.Report = rep
	}

	bind := opts.BindAddr
	if bind == "" {
		bind = "127.0.0.1:8088"
	}
	if !strings.Contains(bind, ":") {
		bind = ":" + bind
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("failed to bind report server on %s: %w", bind, err)
	}

	ms := &MiniServer{
		listener:  ln,
		report:    opts.Report,
		addr:      ln.Addr().String(),
		autoOpen:  opts.AutoOpen,
		startTime: time.Now().UTC(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", ms.handleRoot)
	mux.HandleFunc("/api/summary", ms.handleSummary)
	mux.HandleFunc("/api/timeline", ms.handleTimeline)
	mux.HandleFunc("/api/remediation", ms.handleRemediation)
	mux.HandleFunc("/healthz", ms.handleHealthz)

	readTimeout := opts.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 10 * time.Second
	}
	writeTimeout := opts.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 30 * time.Second
	}

	ms.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	return ms, nil
}

// URL returns the local accessible URL for the report server.
func (s *MiniServer) URL() string {
	host, port, err := net.SplitHostPort(s.addr)
	if err != nil {
		return fmt.Sprintf("http://%s", s.addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}

// Start begins serving requests asynchronously.
func (s *MiniServer) Start() error {
	if s.autoOpen {
		go func() {
			time.Sleep(100 * time.Millisecond)
			if err := OpenBrowser(s.URL()); err != nil {
				common.GetLogger().Info(fmt.Sprintf("Browser auto-launch skipped (%v). Access report at: %s", err, s.URL()))
			}
		}()
	}
	return s.httpServer.Serve(s.listener)
}

// Shutdown gracefully terminates the HTTP server.
func (s *MiniServer) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// ServeReport starts the reporting mini-server, manages auto-open, and waits for interrupt signals.
func ServeReport(ctx context.Context, opts ServerOptions) error {
	server, err := NewMiniServer(opts)
	if err != nil {
		return err
	}

	logger := common.GetLogger()
	logger.Info(fmt.Sprintf("Contraband Report Server listening at %s", server.URL()))
	logger.Info("Press Ctrl+C to terminate the server")

	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errChan <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-ctx.Done():
		logger.Info("Context cancelled, shutting down report server...")
	case sig := <-sigChan:
		logger.Info(fmt.Sprintf("Received signal %v, shutting down report server...", sig))
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}

	shutdownTimeout := opts.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	return server.Shutdown(shutdownCtx)
}

// --- Handler Implementations ---

func (s *MiniServer) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	if err := WriteHTML(w, s.report); err != nil {
		http.Error(w, fmt.Sprintf("Template rendering error: %v", err), http.StatusInternalServerError)
	}
}

func (s *MiniServer) handleSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.report.Summary)
}

func (s *MiniServer) handleTimeline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.report.Probes)
}

func (s *MiniServer) handleRemediation(w http.ResponseWriter, r *http.Request) {
	vendor := strings.ToLower(r.URL.Query().Get("vendor"))
	if vendor != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch vendor {
		case "pan_os", "pan", "paloalto":
			_, _ = w.Write([]byte(s.report.Remediation.PANOSRules))
		case "fortigate", "forti":
			_, _ = w.Write([]byte(s.report.Remediation.FortiGateRules))
		case "nftables", "nft":
			_, _ = w.Write([]byte(s.report.Remediation.NFTablesRules))
		case "iptables", "ipt":
			_, _ = w.Write([]byte(s.report.Remediation.IPTablesRules))
		case "cisco_asa", "asa", "cisco":
			_, _ = w.Write([]byte(s.report.Remediation.CiscoASARules))
		default:
			http.Error(w, fmt.Sprintf("Unknown vendor '%s'", vendor), http.StatusBadRequest)
		}
		return
	}

	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		combined := fmt.Sprintf("# === PALO ALTO NETWORKS ===\n%s\n\n# === FORTINET FORTIGATE ===\n%s\n\n# === LINUX NFTABLES ===\n%s\n\n# === LINUX IPTABLES ===\n%s\n\n# === CISCO ASA ===\n%s\n",
			s.report.Remediation.PANOSRules, s.report.Remediation.FortiGateRules, s.report.Remediation.NFTablesRules, s.report.Remediation.IPTablesRules, s.report.Remediation.CiscoASARules)
		_, _ = w.Write([]byte(combined))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.report.Remediation)
}

func (s *MiniServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	uptime := time.Since(s.startTime)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"uptime_ms": float64(uptime.Microseconds()) / 1000.0,
	})
}

// OpenBrowser launches the client's default desktop browser with headless fallback.
func OpenBrowser(url string) error {
	// Suppress browser spawning when explicitly disabled or during automated testing
	if os.Getenv("CONTRABAND_NO_BROWSER") != "" {
		return nil
	}

	switch runtime.GOOS {
	case "windows":
		if flag.Lookup("test.v") != nil {
			return nil
		}
		return exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		if flag.Lookup("test.v") != nil {
			return nil
		}
		return exec.Command("open", url).Start()
	default: // Linux, FreeBSD, OpenBSD
		// Check for headless environment
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return errors.New("headless environment detected: no DISPLAY or WAYLAND_DISPLAY available")
		}
		if flag.Lookup("test.v") != nil {
			return nil
		}
		return exec.Command("xdg-open", url).Start()
	}
}
