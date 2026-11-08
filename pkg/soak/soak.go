package soak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shehzade/contraband/pkg/client"
	"github.com/shehzade/contraband/pkg/client/dlp"
	"github.com/shehzade/contraband/pkg/client/exfil"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/report"
	"github.com/shehzade/contraband/pkg/server/live"
)

// SoakConfig configures the overnight continuous soak and stress engine.
type SoakConfig struct {
	TargetServer      string        `json:"target_server"`
	DashboardURL      string        `json:"dashboard_url"`
	Duration          time.Duration `json:"duration"`
	LogPath           string        `json:"log_path"`
	MaxHeapCeiling    uint64        `json:"max_heap_ceiling"`
	SampleInterval    time.Duration `json:"sample_interval"`
	ReportInterval    time.Duration `json:"report_interval"`
	Volumes           []int64       `json:"volumes"`
	ValidationVolumes []int64       `json:"validation_volumes"`
	Concurrency       int           `json:"concurrency"`
	DryRun            bool          `json:"dry_run"`
	EvidenceDir       string        `json:"evidence_dir"`
}

// DefaultSoakConfig returns production defaults for the 8-10 hour continuous soak engine.
func DefaultSoakConfig() SoakConfig {
	return SoakConfig{
		TargetServer:      "127.0.0.1",
		DashboardURL:      "http://127.0.0.1:8080",
		Duration:          10 * time.Hour,
		LogPath:           "evidence/soak_test.log",
		MaxHeapCeiling:    DefaultMaxHeapCeiling, // 32MB
		SampleInterval:    500 * time.Millisecond,
		ReportInterval:    2 * time.Minute,
		Volumes:           AllVolumeTiers(),
		ValidationVolumes: ValidationVolumeTiers(),
		Concurrency:       len(AllZones()), // 5 concurrent zones
		EvidenceDir:       "evidence",
	}
}

// SoakSummary provides high-level summary statistics of the soak execution.
type SoakSummary struct {
	StartTime          time.Time     `json:"start_time"`
	ElapsedTime        time.Duration `json:"elapsed_time"`
	ElapsedMS          float64       `json:"elapsed_ms"`
	TotalScenarios     int64         `json:"total_scenarios"`
	SuccessScenarios   int64         `json:"success_scenarios"`
	FailedScenarios    int64         `json:"failed_scenarios"`
	TotalBytesSmuggled int64         `json:"total_bytes_smuggled"`
	FormattedBytes     string        `json:"formatted_bytes"`
	ReportsUploaded    int64         `json:"reports_uploaded"`
	NegativePasses     int64         `json:"negative_passes"`
	NegativeFails      int64         `json:"negative_fails"`
	PeakHeapMB         float64       `json:"peak_heap_mb"`
	MemoryViolations   int64         `json:"memory_violations"`
	MemoryHealthy      bool          `json:"memory_healthy"`
}

// SoakEngine orchestrates multi-zone concurrent streaming, memory bounding,
// continuous evidence logging, negative disruption injection, and live dashboard synchronization.
type SoakEngine struct {
	mu                 sync.RWMutex
	config             SoakConfig
	logger             *SoakLogger
	memMonitor         *MemoryMonitor
	matrix             []Scenario
	probesTotal        int64
	probesSuccess      int64
	probesFailed       int64
	bytesTransferred   int64
	reportsUploaded    int64
	negativePasses     int64
	negativeFails      int64
	startTime          time.Time
	recentProbesMu     sync.Mutex
	recentProbes       []common.ProbeResult
}

// NewSoakEngine instantiates and initializes all soak components.
func NewSoakEngine(cfg SoakConfig) (*SoakEngine, error) {
	if cfg.TargetServer == "" {
		cfg.TargetServer = "127.0.0.1"
	}
	if cfg.DashboardURL == "" {
		cfg.DashboardURL = "http://127.0.0.1:8080"
	}
	if cfg.LogPath == "" {
		cfg.LogPath = "evidence/soak_test.log"
	}
	if cfg.MaxHeapCeiling == 0 {
		cfg.MaxHeapCeiling = DefaultMaxHeapCeiling
	}
	if cfg.SampleInterval <= 0 {
		cfg.SampleInterval = 500 * time.Millisecond
	}
	if cfg.ReportInterval <= 0 {
		cfg.ReportInterval = 2 * time.Minute
	}
	if len(cfg.Volumes) == 0 {
		cfg.Volumes = AllVolumeTiers()
	}
	if len(cfg.ValidationVolumes) == 0 {
		cfg.ValidationVolumes = ValidationVolumeTiers()
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = len(AllZones())
	}
	if cfg.EvidenceDir == "" {
		cfg.EvidenceDir = "evidence"
	}

	logger, err := NewSoakLogger(cfg.LogPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize soak logger: %w", err)
	}

	// Strictly bound memory heap ceiling via runtime directives
	debug.SetGCPercent(20)
	debug.SetMemoryLimit(int64(cfg.MaxHeapCeiling))

	memMonitor := NewMemoryMonitor(cfg.MaxHeapCeiling, cfg.SampleInterval)
	matrix := GenerateScenarioMatrix(cfg.Volumes)

	engine := &SoakEngine{
		config:       cfg,
		logger:       logger,
		memMonitor:   memMonitor,
		matrix:       matrix,
		recentProbes: make([]common.ProbeResult, 0, 100),
	}

	// Register memory violation callback to log alerts immediately
	memMonitor.SetOnViolation(func(stats MemoryStats) {
		logger.LogAlert(fmt.Sprintf("MEMORY INVARIANT BREACHED: HeapAlloc=%.2fMB exceeds ceiling=%.2fMB",
			stats.HeapAllocMB, stats.CeilingMB))
	})

	return engine, nil
}

// Close gracefully closes loggers and background resources.
func (e *SoakEngine) Close() error {
	if e.logger != nil {
		return e.logger.Close()
	}
	return nil
}

// MemoryMonitor returns the active MemoryMonitor instance.
func (e *SoakEngine) MemoryMonitor() *MemoryMonitor {
	return e.memMonitor
}

// Matrix returns the full scenario matrix.
func (e *SoakEngine) Matrix() []Scenario {
	return e.matrix
}

// ExecuteScenario executes a single matrix scenario (live exfil or negative test injection).
func (e *SoakEngine) ExecuteScenario(ctx context.Context, sc Scenario) error {
	atomic.AddInt64(&e.probesTotal, 1)

	// Case 1: Negative Testing Disruption Injection
	if sc.IsNegative {
		port := client.DefaultPortForProtocol(sc.Protocol)
		negRes := ExecuteNegativeScenario(ctx, sc, e.config.TargetServer, port)

		if negRes.Passed {
			atomic.AddInt64(&e.negativePasses, 1)
			atomic.AddInt64(&e.probesSuccess, 1)
		} else {
			atomic.AddInt64(&e.negativeFails, 1)
			atomic.AddInt64(&e.probesFailed, 1)
		}

		e.logger.LogNegativeTest(
			sc.NegativeType,
			sc.Zone,
			negRes.Target,
			negRes.ActualVerdict,
			negRes.ExpectedVerdict,
			negRes.LatencyMS,
			negRes.Passed,
		)

		probe := common.ProbeResult{
			ID:           fmt.Sprintf("soak-neg-%d", time.Now().UnixNano()),
			Timestamp:    time.Now().UTC(),
			Stage:        "soak_negative",
			Protocol:     sc.Protocol,
			TargetHost:   e.config.TargetServer,
			TargetPort:   port,
			PayloadType:  sc.DLPType,
			CarrierType:  sc.CarrierType,
			Verdict:      negRes.ActualVerdict,
			ErrorMessage: negRes.ErrorMessage,
		}
		probe.Timestamps.TotalDuration = time.Duration(negRes.LatencyMS * float64(time.Millisecond))
		e.recordRecentProbe(probe)
		return nil
	}

	// Case 2: Live Protocol Exfiltration Stream
	ex, err := exfil.GetExfiltrator(sc.Protocol)
	if err != nil {
		atomic.AddInt64(&e.probesFailed, 1)
		e.logger.LogAlert(fmt.Sprintf("protocol %q not registered: %v", sc.Protocol, err))
		return err
	}

	port := client.DefaultPortForProtocol(sc.Protocol)
	isTLS := port == 443 || port == 8443 || port == 9443 || port == 10443 || port == 853 || port == 990 || port == 465 || port == 4430
	sessionToken, _ := common.NewSessionToken()

	chunkSize := common.DefaultChunkSize
	if IsCovertProtocol(sc.Protocol) {
		chunkSize = 512
	}
	timeout := 45 * time.Second
	if sc.VolumeBytes > Volume100MB {
		timeout = time.Duration(sc.VolumeBytes/(2*1024*1024))*time.Second + 30*time.Second
	}

	exfilOpts := exfil.ExfilOptions{
		TargetHost:     e.config.TargetServer,
		TargetPort:     port,
		UseTLS:         isTLS,
		InsecureTLS:    true,
		TLSFingerprint: sc.TLSFingerprint,
		SessionToken:   sessionToken,
		ChunkSize:      chunkSize,
		TotalBytes:     sc.VolumeBytes,
		Timeout:        timeout,
		PayloadType:    sc.DLPType,
		CarrierType:    sc.CarrierType,
		Headers:        make(map[string]string),
	}
	exfilOpts.Headers["X-Contraband-Zone"] = sc.Zone

	dlpConfig := dlp.GeneratorConfig{
		DLPType:     sc.DLPType,
		CarrierType: sc.CarrierType,
		Seed:        time.Now().UnixNano(),
	}

	streamer := dlp.NewDLPStreamer(sc.VolumeBytes, dlpConfig)
	defer streamer.Close()

	// Leave ExpectedHash empty so streaming exfiltration does not assert against pre-read zero hash.
	exfilOpts.ExpectedHash = ""

	if sc.Transforms != "" {
		exfilOpts.Headers["X-Contraband-Transforms"] = sc.Transforms
	}
	if sc.Stego != "" {
		exfilOpts.Headers["X-Contraband-Stego"] = sc.Stego
	}
	if sc.Cadence != "" {
		exfilOpts.Headers["X-Contraband-Cadence"] = sc.Cadence
	}

	start := time.Now()
	res, exErr := ex.Exfiltrate(ctx, streamer, exfilOpts)
	dur := time.Since(start)
	latMs := float64(dur.Microseconds()) / 1000.0

	// Immediate proactive garbage collection and memory sampling
	runtime.GC()
	memStats := e.memMonitor.Sample()

	expectedHash := streamer.ChecksumHex()

	verdict := common.VerdictSuccess
	var errMsg string
	if exErr != nil {
		verdict = common.ClassifyError(exErr)
		errMsg = exErr.Error()
		atomic.AddInt64(&e.probesFailed, 1)
	} else {
		atomic.AddInt64(&e.probesSuccess, 1)
		atomic.AddInt64(&e.bytesTransferred, sc.VolumeBytes)
	}

	e.logger.LogProbe(
		sc.Zone,
		sc.Protocol,
		sc.VolumeStr,
		verdict,
		latMs,
		memStats.HeapAllocMB,
		memStats.CeilingMB,
		expectedHash,
		errMsg,
	)

	var probe common.ProbeResult
	if res != nil {
		probe = *res
	} else {
		probe = common.ProbeResult{
			ID:           fmt.Sprintf("soak-%d", time.Now().UnixNano()),
			Timestamp:    time.Now().UTC(),
			Stage:        "soak_exfil",
			Protocol:     sc.Protocol,
			TargetHost:   e.config.TargetServer,
			TargetPort:   port,
			PayloadType:  sc.DLPType,
			CarrierType:  sc.CarrierType,
			PayloadHash:  expectedHash,
			Verdict:      verdict,
			ErrorMessage: errMsg,
		}
	}
	probe.Timestamps.TotalDuration = dur
	e.recordRecentProbe(probe)

	return nil
}

func (e *SoakEngine) recordRecentProbe(p common.ProbeResult) {
	e.recentProbesMu.Lock()
	defer e.recentProbesMu.Unlock()
	if len(e.recentProbes) >= 100 {
		e.recentProbes = e.recentProbes[1:]
	}
	e.recentProbes = append(e.recentProbes, p)
}

// GenerateAndSyncReport compiles the accumulated probes into an AssessmentReport,
// generates HTML/JSON/SARIF artifacts, and uploads them to the live dashboard report server.
func (e *SoakEngine) GenerateAndSyncReport(ctx context.Context, zone string) error {
	e.recentProbesMu.Lock()
	probesCopy := make([]common.ProbeResult, len(e.recentProbes))
	copy(probesCopy, e.recentProbes)
	e.recentProbesMu.Unlock()

	if len(probesCopy) == 0 {
		return nil
	}

	start := time.Now()
	rep := report.NewAssessmentReport(e.config.TargetServer, probesCopy, nil, nil, 10*time.Second)

	rawJSON, _ := report.ExportJSON(rep)
	htmlStr, _ := report.GenerateHTML(rep)
	rawHTML := []byte(htmlStr)
	rawSARIF, _ := report.ExportSARIF(rep)

	remediationSet := report.GenerateRemediation(probesCopy, e.config.TargetServer)
	var remediationScript []byte
	if remediationSet != nil {
		remediationScript = []byte(remediationSet.FormatAll())
	}

	durMs := float64(time.Since(start).Microseconds()) / 1000.0

	// Upload to Dashboard
	if e.config.DashboardURL != "" {
		baseURL := e.config.DashboardURL
		targetURL := baseURL + "/api/v1/reports"

		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "contraband-soak-worker"
		}
		if zone == "" {
			zone = ZoneLANCorp
		}

		payload := live.UploadReportPayload{
			Report:      rep,
			RawHTML:     string(rawHTML),
			RawJSON:     string(rawJSON),
			RawSARIF:    string(rawSARIF),
			Remediation: string(remediationScript),
			NetworkZone: zone,
			ClientHost:  hostname,
			ClientIP:    "127.0.0.1",
		}

		payloadBytes, mErr := json.Marshal(payload)
		if mErr == nil {
			req, rErr := http.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(payloadBytes))
			if rErr == nil {
				req.Header.Set("Content-Type", "application/json")
				client := &http.Client{Timeout: 5 * time.Second}
				resp, pErr := client.Do(req)
				if pErr == nil {
					_ = resp.Body.Close()
					if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
						atomic.AddInt64(&e.reportsUploaded, 1)
						e.logger.LogReportUploaded(rep.ID, zone, rep.Summary.EEIScore, string(rep.Summary.Posture), durMs)
					}
				}
			}
		}
	}

	// Also persist local forensic report snapshots into evidence dir
	if e.config.EvidenceDir != "" {
		_ = os.MkdirAll(e.config.EvidenceDir, 0755)
		jsonPath := filepath.Join(e.config.EvidenceDir, fmt.Sprintf("soak_report_%s.json", zone))
		htmlPath := filepath.Join(e.config.EvidenceDir, fmt.Sprintf("soak_report_%s.html", zone))
		sarifPath := filepath.Join(e.config.EvidenceDir, fmt.Sprintf("soak_report_%s.sarif", zone))

		_ = os.WriteFile(jsonPath, rawJSON, 0644)
		_ = os.WriteFile(htmlPath, rawHTML, 0644)
		_ = os.WriteFile(sarifPath, rawSARIF, 0644)
	}

	return nil
}

// Summary returns the current execution metrics summary.
func (e *SoakEngine) Summary() SoakSummary {
	elapsed := time.Since(e.startTime)
	elapsedMs := float64(elapsed.Microseconds()) / 1000.0

	tot := atomic.LoadInt64(&e.probesTotal)
	succ := atomic.LoadInt64(&e.probesSuccess)
	fail := atomic.LoadInt64(&e.probesFailed)
	bytesXfer := atomic.LoadInt64(&e.bytesTransferred)
	reps := atomic.LoadInt64(&e.reportsUploaded)
	negPass := atomic.LoadInt64(&e.negativePasses)
	negFail := atomic.LoadInt64(&e.negativeFails)

	peakMB := e.memMonitor.PeakHeapAllocMB()
	violations := e.memMonitor.Violations()

	return SoakSummary{
		StartTime:          e.startTime,
		ElapsedTime:        elapsed,
		ElapsedMS:          elapsedMs,
		TotalScenarios:     tot,
		SuccessScenarios:   succ,
		FailedScenarios:    fail,
		TotalBytesSmuggled: bytesXfer,
		FormattedBytes:     common.FormatBytes(bytesXfer),
		ReportsUploaded:    reps,
		NegativePasses:     negPass,
		NegativeFails:      negFail,
		PeakHeapMB:         peakMB,
		MemoryViolations:   violations,
		MemoryHealthy:      violations == 0 && peakMB < float64(e.config.MaxHeapCeiling)/(1024*1024),
	}
}
