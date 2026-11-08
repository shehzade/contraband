package client

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/shehzade/contraband/pkg/client/exfil/cloud"
	_ "github.com/shehzade/contraband/pkg/client/exfil/covert"
	_ "github.com/shehzade/contraband/pkg/client/exfil/dns"
	_ "github.com/shehzade/contraband/pkg/client/exfil/file"
	_ "github.com/shehzade/contraband/pkg/client/exfil/mail"
	_ "github.com/shehzade/contraband/pkg/client/exfil/smb"
	_ "github.com/shehzade/contraband/pkg/client/exfil/web"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/report"
)

// ClientConfig holds all CLI and programmatic configuration parameters for the client engine.
type ClientConfig struct {
	Server         string `json:"server"`
	Ports          string `json:"ports"`
	Port           int    `json:"port,omitempty"`
	Protocols      string `json:"protocols"`
	DLPPayloads    string `json:"dlp_payloads"`
	CarrierType    string `json:"carrier_type"`
	Size           string `json:"size"`
	ChunkSize      string `json:"chunk_size"`
	Threads        int    `json:"threads"`
	Throughput     string `json:"throughput"`
	Cadence        string `json:"cadence"`
	IntervalMin    string `json:"interval_min"`
	IntervalMax    string `json:"interval_max"`
	Transforms     string `json:"transforms"`
	Passphrase     string `json:"passphrase"`
	Stego          string `json:"stego"`
	TLSFingerprint string `json:"tls_fingerprint"`
	Proxy          string `json:"proxy"`
	ProxyAuth      string `json:"proxy_auth"`
	Concurrency    int    `json:"concurrency"`
	RateLimit      int    `json:"rate_limit"`
	OutputJSON     string `json:"output_json"`
	OutputHTML     string `json:"output_html"`
	OutputSARIF    string `json:"output_sarif"`
	SyncReport     string `json:"sync_report"`
	Zone           string `json:"zone"`
	NoColor        bool   `json:"no_color"`
	Destroy        bool   `json:"destroy"`
	SavePayload    bool   `json:"save_payload"`
	EvidenceDir    string `json:"evidence_dir"`
	DryRun         bool   `json:"dry_run"`
	Seed           int64  `json:"seed"`
	Verbose        bool   `json:"verbose"`
	JSON           bool   `json:"json"`
}

// DefaultClientConfig returns a ClientConfig populated with standard operational defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Server:         "127.0.0.1",
		Ports:          "quick",
		Port:           0,
		Protocols:      "all",
		DLPPayloads:    "all",
		CarrierType:    "csv",
		Size:           "1MB",
		ChunkSize:      "1MB",
		Threads:        4,
		Throughput:     "unlimited",
		Cadence:        common.CadenceSteady,
		IntervalMin:    "500ms",
		IntervalMax:    "4s",
		Transforms:     "raw",
		Stego:          common.StegoNone,
		TLSFingerprint: common.TLSFingerprintChrome,
		Proxy:          "auto",
		ProxyAuth:      "basic",
		Concurrency:    100,
		RateLimit:      500,
		EvidenceDir:    "evidence",
		Zone:           "corporate-default",
		Seed:           0,
	}
}

// DefaultPortForProtocol returns the standard port associated with a protocol identifier.
func DefaultPortForProtocol(proto string) int {
	switch proto {
	case common.ProtoHTTP1, "http1", "http", common.ProtoWebDAV:
		return 80
	case common.ProtoHTTP2, "http2", "https", common.ProtoHTTP3, "http3", "quic", common.ProtoDoH, common.ProtoSMBQUIC, common.ProtoAWSS3, common.ProtoGCPGCS, common.ProtoAzureBlob:
		return 443
	case common.ProtoWebSocket, "websocket", "ws":
		return 80
	case common.ProtoGRPC, "grpc":
		return 50051
	case common.ProtoDNSA, common.ProtoDNSTXT, "dns":
		return 53
	case common.ProtoDoT, "dot":
		return 853
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
	case common.ProtoICMPEcho, "icmp":
		return 0
	case common.ProtoNTPTime, "ntp":
		return 123
	case common.ProtoSyslog:
		return 514
	case common.ProtoMQTT:
		return 1883
	default:
		return 80
	}
}

// ResolveProtocols expands a protocol string ("all", category, or list) into a slice of protocol names.
func ResolveProtocols(spec string) []string {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" || spec == "all" {
		var list []string
		order := []string{
			common.CategoryWeb,
			common.CategoryDNS,
			common.CategoryFile,
			common.CategoryMail,
			common.CategorySMB,
			common.CategoryCloud,
			common.CategoryCovert,
		}
		for _, cat := range order {
			list = append(list, common.CategoryMap[cat]...)
		}
		return list
	}

	if protos, ok := common.CategoryMap[spec]; ok {
		return protos
	}

	parts := strings.Split(spec, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			if protos, ok := common.CategoryMap[trimmed]; ok {
				result = append(result, protos...)
			} else {
				result = append(result, trimmed)
			}
		}
	}
	return result
}

// RunAssessment coordinates the full 7-stage egress assessment workflow.
func RunAssessment(ctx context.Context, cfg ClientConfig) (*report.AssessmentReport, error) {
	logger := common.GetLogger()
	startTime := time.Now().UTC()

	// Apply defaults
	if cfg.Server == "" {
		cfg.Server = "127.0.0.1"
	}
	if cfg.Port > 0 && (cfg.Ports == "" || cfg.Ports == "quick") {
		cfg.Ports = strconv.Itoa(cfg.Port)
	}
	if cfg.Ports == "" {
		cfg.Ports = "quick"
	}
	if cfg.Protocols == "" {
		cfg.Protocols = "all"
	}
	if cfg.DLPPayloads == "" {
		cfg.DLPPayloads = "all"
	}
	if cfg.CarrierType == "" {
		cfg.CarrierType = "csv"
	}
	if cfg.Size == "" {
		cfg.Size = "1MB"
	}
	if cfg.ChunkSize == "" {
		cfg.ChunkSize = "1MB"
	}
	if cfg.Cadence == "" {
		cfg.Cadence = common.CadenceSteady
	}
	if cfg.TLSFingerprint == "" {
		cfg.TLSFingerprint = common.TLSFingerprintChrome
	}
	if cfg.Proxy == "" {
		cfg.Proxy = "auto"
	}
	if cfg.EvidenceDir == "" {
		cfg.EvidenceDir = "evidence"
	}
	if cfg.Zone == "" {
		cfg.Zone = "corporate-default"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 100
	}
	if cfg.RateLimit < 0 {
		cfg.RateLimit = 500
	}

	// If SavePayload is enabled, ensure evidence directory exists
	if cfg.SavePayload {
		if err := os.MkdirAll(cfg.EvidenceDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create evidence directory %q: %w", cfg.EvidenceDir, err)
		}
	}

	// Pre-flight dry-run validation
	if cfg.DryRun {
		logger.Info("[DRY-RUN] Pre-flight validation passed successfully. Exiting without transmission.")
		return &report.AssessmentReport{
			TargetHost:  cfg.Server,
			GeneratedAt: startTime,
		}, nil
	}

	var allProbes []common.ProbeResult

	// STAGE 1: Layer 4 Egress Port Matrix Sweep
	sweepProbes, err := runStage1Sweep(ctx, cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("stage 1 sweep failed: %w", err)
	}
	allProbes = append(allProbes, sweepProbes...)

	// STAGE 2: Corporate Proxy Discovery & Traversal
	fallbackEngine := runStage2Proxy(ctx, cfg, logger)

	// STAGE 3: Traffic Shaper & Cadence Pacing
	shaper, cadenceEngine := runStage3Shaping(ctx, cfg, logger)

	// STAGE 4: Procedural Synthetic DLP Generation
	s4, err := runStage4DLP(ctx, &cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("stage 4 dlp synthesis failed: %w", err)
	}

	// STAGE 5: Evasion Transforms & Steganography
	pipeline, hasEvasion := runStage5Evasion(cfg, s4.EffectiveSeed)

	// STAGE 6: L7 Protocol Smuggling Matrix
	exfilProbes, err := runStage6Exfil(
		ctx,
		cfg,
		logger,
		s4.TargetBytes,
		s4.DLPConfig,
		s4.ExpectedHash,
		fallbackEngine,
		shaper,
		cadenceEngine,
		pipeline,
		hasEvasion,
	)
	if err != nil {
		return nil, fmt.Errorf("stage 6 exfiltration failed: %w", err)
	}
	allProbes = append(allProbes, exfilProbes...)

	// STAGE 7: Report Generation, Remediation, ANSI Table & Dashboard Sync
	return runStage7Reporting(ctx, cfg, logger, allProbes, startTime)
}
