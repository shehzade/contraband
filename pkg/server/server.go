package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server/certgen"
	"github.com/shehzade/contraband/pkg/server/live"
)

// ServerConfig defines runtime options for the Contraband reflection and listener server.
type ServerConfig struct {
	BindIP        string        `json:"bind_ip"`
	Domain        string        `json:"domain"`
	Ports         string        `json:"ports"`
	Protocols     string        `json:"protocols"`
	SMBMode       string        `json:"smb_mode"`
	CertPath      string        `json:"cert_path"`
	KeyPath       string        `json:"key_path"`
	EnableEBPF    bool          `json:"enable_ebpf"`
	DBPath        string        `json:"db_path"`
	SavePayload   bool          `json:"save_payload"`
	EvidenceDir   string        `json:"evidence_dir"`
	DashboardAddr string        `json:"dashboard_addr,omitempty"`
	EnableTCP     bool          `json:"enable_tcp"`
	EnableUDP     bool          `json:"enable_udp"`
	Banner        string        `json:"banner"`
	PeekTimeout   time.Duration `json:"peek_timeout"`
	SocketTimeout time.Duration `json:"socket_timeout"`
}

// DefaultServerConfig returns a ServerConfig with standard operational defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		BindIP:        "0.0.0.0",
		Domain:        "contraband.example.com",
		Ports:         "quick",
		Protocols:     "all",
		SMBMode:       "hash-capture",
		DBPath:        ":memory:",
		EvidenceDir:   "evidence",
		EnableTCP:     true,
		EnableUDP:     true,
		PeekTimeout:   100 * time.Millisecond,
		SocketTimeout: 3 * time.Second,
	}
}

// Listener defines the contract required for dedicated protocol servers.
// Compatible with listeners.ProtocolListener.
type Listener interface {
	Name() string
	Protocol() string
	Ports() []int
	Start(ctx context.Context, ledger Ledger) error
	Stop() error
}

// DemuxHandler defines the handler function for demuxed smuggling connections.
type DemuxHandler func(conn net.Conn, peeked []byte, port int) error

// Multiplexer defines the contract for multi-port reflection.
// Compatible with multiplexer.Multiplexer.
type Multiplexer interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	RegisterDemuxHandler(magic uint32, handler DemuxHandler)
}

// ServerEngine orchestrates the session ledger, dynamic TLS/SSH certs, dedicated L7 listeners,
// and userspace port multiplexer reflector.
type ServerEngine struct {
	mu              sync.RWMutex
	config          ServerConfig
	ledger          Ledger
	listeners       []Listener
	multiplexer     Multiplexer
	tlsConfig       *tls.Config
	sshHostKey      *certgen.SSHHostKey
	logger          common.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	running         bool
	wg              sync.WaitGroup
	savedMu         sync.Mutex
	savedSessions   map[string]bool
	dashboardServer *live.DashboardServer
	liveHub         *live.LiveHub
}

// NewServerEngine initializes the server components, ledger, and dynamic certs.
func NewServerEngine(cfg ServerConfig) (*ServerEngine, error) {
	logger := common.GetLogger()

	// Apply defaults
	if cfg.BindIP == "" {
		cfg.BindIP = "0.0.0.0"
	}
	if cfg.Domain == "" {
		cfg.Domain = "contraband.example.com"
	}
	if cfg.Ports == "" {
		cfg.Ports = "quick"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = ":memory:"
	}
	if cfg.SMBMode == "" {
		cfg.SMBMode = "hash-capture"
	}
	if cfg.EvidenceDir == "" {
		cfg.EvidenceDir = "evidence"
	}
	if cfg.PeekTimeout <= 0 {
		cfg.PeekTimeout = 100 * time.Millisecond
	}
	if cfg.SocketTimeout <= 0 {
		cfg.SocketTimeout = 3 * time.Second
	}

	// 1. Initialize Session Ledger
	ledger, err := NewLedger(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ledger: %w", err)
	}

	// 2. TLS & SSH Dynamic Cert Generation
	var tlsConfig *tls.Config
	if cfg.CertPath != "" && cfg.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			ledger.Close()
			return nil, fmt.Errorf("failed to load TLS certificate pair: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		}
	} else {
		ca, err := certgen.NewCA("Contraband Assessment Root CA")
		if err != nil {
			ledger.Close()
			return nil, fmt.Errorf("failed to generate ephemeral CA: %w", err)
		}
		hosts := []string{"localhost", "127.0.0.1", cfg.Domain, cfg.BindIP}
		tlsConfig, err = certgen.NewServerTLSConfig(hosts, ca)
		if err != nil {
			ledger.Close()
			return nil, fmt.Errorf("failed to generate dynamic TLS config: %w", err)
		}
	}

	sshHostKey, err := certgen.GenerateSSHHostKey()
	if err != nil {
		ledger.Close()
		return nil, fmt.Errorf("failed to generate dynamic SSH host key: %w", err)
	}

	var liveHub *live.LiveHub
	var dashServer *live.DashboardServer
	if cfg.DashboardAddr != "" {
		liveHub = live.NewLiveHub()
		ds, err := live.NewDashboardServer(cfg.DashboardAddr, liveHub)
		if err != nil {
			ledger.Close()
			return nil, fmt.Errorf("failed to initialize live dashboard server: %w", err)
		}
		dashServer = ds
		ledger.SetObserver(NewHubLedgerObserver(liveHub))
	}

	engine := &ServerEngine{
		config:          cfg,
		ledger:          ledger,
		listeners:       make([]Listener, 0),
		tlsConfig:       tlsConfig,
		sshHostKey:      sshHostKey,
		logger:          logger,
		savedSessions:   make(map[string]bool),
		dashboardServer: dashServer,
		liveHub:         liveHub,
	}

	if dashServer != nil {
		dashServer.SetEvidenceDir(cfg.EvidenceDir)
		dashServer.SetResetCallback(func(deleteFiles bool) error {
			return engine.ResetState(deleteFiles)
		})
	}

	return engine, nil
}

// HubLedgerObserver bridges state.Ledger events to the real-time LiveHub.
type HubLedgerObserver struct {
	hub *live.LiveHub
}

// NewHubLedgerObserver creates a new HubLedgerObserver.
func NewHubLedgerObserver(hub *live.LiveHub) *HubLedgerObserver {
	return &HubLedgerObserver{hub: hub}
}

// OnChunkReceived forwards chunk arrival events to LiveHub.
func (o *HubLedgerObserver) OnChunkReceived(session *common.Session, seq, total uint32, chunkSize int64) {
	if o.hub == nil || session == nil {
		return
	}
	clientIP := session.ClientIP
	host := session.ClientHost
	zone := session.NetworkZone

	var progressPct float64
	if total > 0 {
		progressPct = math.Round((float64(seq)/float64(total))*10000) / 100
	}

	durMs := float64(session.LastActive.Sub(session.StartTime).Microseconds()) / 1000.0
	if durMs < 0 {
		durMs = 0
	}

	var instantMBs float64
	if durMs > 0 && session.TotalBytes > 0 {
		instantMBs = math.Round(((float64(session.TotalBytes)/(1024*1024))/(durMs/1000.0))*100) / 100
	}

	expectedBytes := session.ExpectedBytes
	if expectedBytes == 0 && total > 0 && chunkSize > 0 {
		expectedBytes = int64(total) * chunkSize
	}

	o.hub.RecordChunk(live.SessionProgressData{
		SessionID:        session.Token.String(),
		NetworkZone:      zone,
		ClientHost:       host,
		ClientIP:         clientIP,
		Protocol:         session.Protocol,
		Port:             session.Port,
		Sequence:         seq,
		TotalChunks:      total,
		BytesTransferred: session.TotalBytes,
		TotalBytes:       expectedBytes,
		ProgressPct:      progressPct,
		InstantMBs:       instantMBs,
		ElapsedMS:        durMs,
	}, chunkSize)
}

// OnSessionCompleted forwards session finalization events to LiveHub.
func (o *HubLedgerObserver) OnSessionCompleted(session *common.Session) {
	if o.hub == nil || session == nil {
		return
	}
	clientIP := session.ClientIP
	host := session.ClientHost
	zone := session.NetworkZone

	durMs := float64(session.LastActive.Sub(session.StartTime).Microseconds()) / 1000.0
	if durMs < 0 {
		durMs = 0
	}

	var avgMBs float64
	if durMs > 0 && session.TotalBytes > 0 {
		avgMBs = math.Round(((float64(session.TotalBytes)/(1024*1024))/(durMs/1000.0))*100) / 100
	}

	hashMatched := session.ExpectedHash != "" && strings.EqualFold(session.PayloadHash, session.ExpectedHash)

	o.hub.RecordSessionComplete(live.SessionCompleteData{
		SessionID:   session.Token.String(),
		NetworkZone: zone,
		ClientHost:  host,
		ClientIP:    clientIP,
		Protocol:    session.Protocol,
		Port:        session.Port,
		TotalBytes:  session.TotalBytes,
		TotalChunks: session.TotalChunks,
		DurationMS:  math.Round(durMs*100) / 100,
		AverageMBs:  avgMBs,
		FinalHash:   session.PayloadHash,
		HashMatched: hashMatched,
		Verdict:     session.Verdict,
	})
}

// OnProbeRecorded forwards probe results to LiveHub.
func (o *HubLedgerObserver) OnProbeRecorded(probe *common.ProbeResult) {
	if o.hub == nil || probe == nil {
		return
	}
	o.hub.RecordProbe(*probe)
}

// RegisterListener registers a dedicated protocol listener with the engine.
func (s *ServerEngine) RegisterListener(l Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, l)
}

// SetMultiplexer sets the userspace port multiplexer reflector and binds smuggling demux handler.
func (s *ServerEngine) SetMultiplexer(m Multiplexer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.multiplexer = m
	if m != nil && s.ledger != nil {
		m.RegisterDemuxHandler(common.MagicHeader, s.handleDemuxSmuggling)
	}
}

// handleDemuxSmuggling processes incoming raw TCP smuggling streams prefixed with 32-byte ChunkHeader.
func (s *ServerEngine) handleDemuxSmuggling(conn net.Conn, peeked []byte, port int) error {
	defer conn.Close()

	buf := make([]byte, 65536)
	copy(buf, peeked)
	peekedLen := len(peeked)

	for {
		for peekedLen < common.ChunkHeaderSize {
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf[peekedLen:])
			if err != nil {
				if err == io.EOF && peekedLen == 0 {
					return nil
				}
				return err
			}
			peekedLen += n
		}

		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(buf[:common.ChunkHeaderSize]); err != nil {
			return err
		}
		if hdr.Magic != common.MagicHeader {
			return fmt.Errorf("invalid chunk header magic: 0x%x", hdr.Magic)
		}

		totalNeeded := common.ChunkHeaderSize + int(hdr.PayloadLen)
		for cap(buf) < totalNeeded {
			newBuf := make([]byte, totalNeeded*2)
			copy(newBuf, buf[:peekedLen])
			buf = newBuf
		}
		for peekedLen < totalNeeded {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf[peekedLen:totalNeeded])
			if err != nil {
				return err
			}
			peekedLen += n
		}

		payload := make([]byte, hdr.PayloadLen)
		copy(payload, buf[common.ChunkHeaderSize:totalNeeded])

		if s.ledger != nil {
			clientIP, portStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
			port, _ := strconv.Atoi(portStr)
			if clientIP == "" {
				clientIP = conn.RemoteAddr().String()
			}
			_, _, _ = s.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, "", clientIP, "raw_tcp_smuggle", port, clientIP, "")
		}

		ack := fmt.Sprintf("{\"status\":\"OK\",\"session\":\"%s\",\"seq\":%d}\n", hdr.Token.String(), hdr.Sequence)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte(ack)); err != nil {
			return err
		}

		remaining := peekedLen - totalNeeded
		if remaining > 0 {
			copy(buf, buf[totalNeeded:peekedLen])
			peekedLen = remaining
		} else {
			peekedLen = 0
			if hdr.Sequence >= hdr.TotalChunks {
				break
			}
		}
	}
	return nil
}

// GetLedger returns the underlying session ledger.
func (s *ServerEngine) GetLedger() Ledger {
	return s.ledger
}

// GetTLSConfig returns the generated or loaded TLS configuration.
func (s *ServerEngine) GetTLSConfig() *tls.Config {
	return s.tlsConfig
}

// GetSSHHostKey returns the generated SSH host key.
func (s *ServerEngine) GetSSHHostKey() *certgen.SSHHostKey {
	return s.sshHostKey
}

// GetConfig returns the runtime server configuration.
func (s *ServerEngine) GetConfig() ServerConfig {
	return s.config
}

// GetListeners returns all registered listeners.
func (s *ServerEngine) GetListeners() []Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	copied := make([]Listener, len(s.listeners))
	copy(copied, s.listeners)
	return copied
}

// Start spawns all registered protocol listeners and the port multiplexer reflector.
func (s *ServerEngine) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server engine is already running")
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.running = true
	listenersCopy := make([]Listener, len(s.listeners))
	copy(listenersCopy, s.listeners)
	mux := s.multiplexer
	s.mu.Unlock()

	// Ensure evidence directory exists if SavePayload is enabled
	if s.config.SavePayload {
		if err := os.MkdirAll(s.config.EvidenceDir, 0755); err != nil {
			s.logger.Warn(fmt.Sprintf("Failed to create evidence directory %q: %v", s.config.EvidenceDir, err))
		}
	}

	// Launch dedicated protocol listeners
	for _, l := range listenersCopy {
		listener := l
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := listener.Start(s.ctx, s.ledger); err != nil {
				s.logger.Warn(fmt.Sprintf("Listener %s terminated: %v", listener.Name(), err))
			}
		}()
	}

	// Launch userspace port multiplexer
	if mux != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := mux.Start(s.ctx); err != nil {
				s.logger.Warn(fmt.Sprintf("Multiplexer terminated: %v", err))
			}
		}()
	}

	// Payload retention worker
	if s.config.SavePayload {
		s.wg.Add(1)
		go s.payloadRetentionWorker()
	}

	// Launch live command center dashboard
	if s.dashboardServer != nil && s.liveHub != nil {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := s.dashboardServer.Start(s.ctx); err != nil {
				s.logger.Warn(fmt.Sprintf("Dashboard server exited: %v", err))
			}
		}()
		s.logger.Info(fmt.Sprintf("Live Command Center Dashboard active at http://%s/dashboard", s.config.DashboardAddr))
		trySpawnPort8088Redirect(s.ctx, s.config.DashboardAddr)
	}

	s.logger.Info(fmt.Sprintf("Server Engine running on %s (%d protocol listeners registered)",
		s.config.BindIP, len(listenersCopy)))

	return nil
}

// flushCompletedSessionsToDisk iterates all ledger sessions, writes completed
// payloads to evidence_dir if not previously saved, and marks them in savedSessions.
func (s *ServerEngine) flushCompletedSessionsToDisk() {
	if s.ledger == nil || !s.config.SavePayload {
		return
	}
	sessions, err := s.ledger.GetAllSessions()
	if err != nil {
		return
	}

	_ = os.MkdirAll(s.config.EvidenceDir, 0755)

	s.savedMu.Lock()
	defer s.savedMu.Unlock()

	for _, sess := range sessions {
		if sess == nil || sess.Status != "completed" {
			continue
		}
		tokStr := sess.Token.String()
		if s.savedSessions[tokStr] {
			continue
		}

		payload, err := s.ledger.GetSessionPayload(sess.Token)
		if err != nil || len(payload) == 0 {
			continue
		}

		safeProto := common.SanitizeProtocolName(sess.Protocol)
		filename := fmt.Sprintf("%s_%s.bin", tokStr, safeProto)
		dest := filepath.Join(s.config.EvidenceDir, filename)
		cleanDest := filepath.Clean(dest)
		cleanEvidenceDir := filepath.Clean(s.config.EvidenceDir)
		rel, err := filepath.Rel(cleanEvidenceDir, cleanDest)
		if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
			s.logger.Warn(fmt.Sprintf("Path traversal detected! Refusing to write to %s", dest))
			continue
		}
		if writeErr := os.WriteFile(cleanDest, payload, 0600); writeErr == nil {
			s.savedSessions[tokStr] = true
			s.logger.Info(fmt.Sprintf("Reconstructed payload written to %s (%d bytes)", cleanDest, len(payload)))
		} else {
			s.logger.Warn(fmt.Sprintf("Failed to write evidence payload to %s: %v", cleanDest, writeErr))
		}
	}
}

func (s *ServerEngine) payloadRetentionWorker() {
	defer s.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// Flush any sessions completed prior to context cancellation
			s.flushCompletedSessionsToDisk()
			return
		case <-ticker.C:
			s.flushCompletedSessionsToDisk()
		}
	}
}

// FlushEvidence triggers an immediate flush of all completed sessions to the evidence directory.
func (s *ServerEngine) FlushEvidence() {
	s.flushCompletedSessionsToDisk()
}

// Stop gracefully terminates all listeners, the multiplexer, and closes the ledger with a default 5-second timeout.
func (s *ServerEngine) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}

// Shutdown gracefully terminates all listeners, the multiplexer, flushes evidence, and closes the ledger.
func (s *ServerEngine) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	listenersCopy := make([]Listener, len(s.listeners))
	copy(listenersCopy, s.listeners)
	mux := s.multiplexer
	s.mu.Unlock()

	s.logger.Info("Initiating graceful server engine shutdown...")

	// Stop dedicated listeners
	for _, l := range listenersCopy {
		_ = l.Stop()
	}

	// Stop multiplexer
	if mux != nil {
		_ = mux.Shutdown(ctx)
	}

	// Stop dashboard server
	if s.dashboardServer != nil {
		_ = s.dashboardServer.Shutdown(ctx)
	}

	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		s.logger.Info("All server listeners stopped cleanly")
	case <-ctx.Done():
		s.logger.Warn("Shutdown context expired before all listeners exited")
	}

	// Guaranteed final flush of any sessions completed prior to or during shutdown
	if s.config.SavePayload {
		s.flushCompletedSessionsToDisk()
	}

	if s.ledger != nil {
		_ = s.ledger.Close()
	}

	return nil
}

// GetLiveHub returns the live telemetry hub, if active.
func (s *ServerEngine) GetLiveHub() *live.LiveHub {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveHub
}

// GetDashboardServer returns the live dashboard HTTP server, if active.
func (s *ServerEngine) GetDashboardServer() *live.DashboardServer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dashboardServer
}

// ResetState purges the ledger state, completed session registry, and optionally evidence files from disk.
func (s *ServerEngine) ResetState(deleteFiles bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Reset the underlying ledger
	if s.ledger != nil {
		if err := s.ledger.Reset(); err != nil {
			s.logger.Warn(fmt.Sprintf("Failed to reset ledger: %v", err))
		}
	}

	// 2. Clear saved sessions tracking
	s.savedMu.Lock()
	s.savedSessions = make(map[string]bool)
	s.savedMu.Unlock()

	// 3. If requested, delete exfiltrated evidence files from disk
	if deleteFiles && s.config.EvidenceDir != "" {
		entries, err := os.ReadDir(s.config.EvidenceDir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					filePath := filepath.Join(s.config.EvidenceDir, entry.Name())
					_ = os.Remove(filePath)
				}
			}
			s.logger.Info(fmt.Sprintf("Purged exfiltrated evidence files from %s", s.config.EvidenceDir))
		}
	}

	s.logger.Info(fmt.Sprintf("Server state reset complete (deleteFiles=%v)", deleteFiles))
	return nil
}

// trySpawnPort8088Redirect attempts to bind 8088 and redirect requests to the live dashboard port.
func trySpawnPort8088Redirect(ctx context.Context, targetDashAddr string) {
	if strings.Contains(targetDashAddr, ":8088") {
		return
	}
	ln, err := net.Listen("tcp", "0.0.0.0:8088")
	if err != nil {
		return
	}
	dashPort := "8080"
	parts := strings.Split(targetDashAddr, ":")
	if len(parts) >= 2 && parts[len(parts)-1] != "" {
		dashPort = parts[len(parts)-1]
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := fmt.Sprintf("http://127.0.0.1:%s/dashboard", dashPort)
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		_ = srv.Serve(ln)
	}()
}
