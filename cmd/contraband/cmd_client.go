package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/shehzade/contraband/pkg/client"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/spf13/cobra"
)

var (
	clientServer         string
	clientPorts          string
	clientProtocols      string
	clientDLP            string
	clientCarrierType    string
	clientSize           string
	clientChunkSize      string
	clientThreads        int
	clientThroughput     string
	clientCadence        string
	clientIntervalMin    string
	clientIntervalMax    string
	clientTransforms     string
	clientPassphrase     string
	clientStego          string
	clientTLSFingerprint string
	clientProxy          string
	clientProxyAuth      string
	clientConcurrency    int
	clientRateLimit      int
	clientOutputJSON     string
	clientOutputHTML     string
	clientOutputSARIF    string
	clientDestroy        bool
	clientSavePayload    bool
	clientEvidenceDir    string
	clientRateAlias      string
	clientSyncReport     string
	clientZone           string
	clientNoColor        bool
)

var clientCmd = &cobra.Command{
	Use:     "client",
	Aliases: []string{"smuggle", "agent"},
	Short:   "Execute end-to-end egress assessment and synthetic DLP data smuggling",
	Long: `Sequences full 6-stage assessment lifecycle:
Stage 1: L4 Port Sweep
Stage 2: Corporate Proxy Discovery & Traversal
Stage 3: Adaptive Traffic Shaping & Cadence Pacing
Stage 4: Procedural DLP Secret Synthesis (<32MB RAM)
Stage 5: Multi-Stage Evasion & Steganography
Stage 6: Multi-Protocol L7 Data Exfiltration across 20 protocols.`,
	RunE: runClient,
}

func init() {
	clientCmd.Flags().StringVarP(&clientServer, "server", "s", "127.0.0.1", "Target server IP or hostname (required for live assessment)")
	clientCmd.Flags().StringVarP(&clientPorts, "ports", "p", "quick", "Port preset: 'quick' (25), 'standard' (200), 'full', or custom '80,443,8000-8100'")
	clientCmd.Flags().StringVar(&clientProtocols, "protocols", "all", "Protocols: 'all', category ('web','dns','file','mail','smb','cloud','covert'), or comma-separated list")
	clientCmd.Flags().StringVar(&clientDLP, "dlp", "all", "Synthetic DLP payloads: 'all', 'pci', 'pii', 'hipaa', 'secrets'")
	clientCmd.Flags().StringVar(&clientCarrierType, "carrier-type", "csv", "Procedural text carrier: 'csv', 'json', 'sql', 'email', 'syslog', 'noise'")
	clientCmd.Flags().StringVar(&clientSize, "size", "1MB", "Data volume to exfiltrate ('100KB', '50MB', '2GB', '10GB')")
	clientCmd.Flags().StringVar(&clientChunkSize, "chunk-size", "1MB", "Transfer chunk size ('64KB', '1MB', '10MB')")
	clientCmd.Flags().IntVar(&clientThreads, "threads", 4, "Concurrent worker streams (1–64)")
	clientCmd.Flags().StringVar(&clientThroughput, "throughput", "unlimited", "Outbound rate limit ('100KB/s', '5MB/s', 'unlimited')")
	clientCmd.Flags().StringVar(&clientCadence, "cadence", "steady", "Traffic pacing: 'burst', 'steady', 'jittered', 'office-hours', 'low-and-slow'")
	clientCmd.Flags().StringVar(&clientIntervalMin, "interval-min", "500ms", "Minimum jitter sleep interval")
	clientCmd.Flags().StringVar(&clientIntervalMax, "interval-max", "4s", "Maximum jitter sleep interval")
	clientCmd.Flags().StringVar(&clientTransforms, "transforms", "raw", "Evasion chain: comma-separated 'raw', 'base64', 'hex', 'gzip', 'zstd', 'aes_gcm'")
	clientCmd.Flags().StringVar(&clientPassphrase, "passphrase", "", "Passphrase for AES-256-GCM encryption")
	clientCmd.Flags().StringVar(&clientStego, "stego", "none", "Steganographic carrier: 'none', 'bmp', 'png', 'wav', 'jpeg-zip', 'pdf-jar'")
	clientCmd.Flags().StringVar(&clientTLSFingerprint, "tls-fingerprint", "chrome", "uTLS Client Hello: 'chrome', 'edge', 'safari', 'firefox', 'curl', 'default'")
	clientCmd.Flags().StringVar(&clientProxy, "proxy", "auto", "Proxy traversal: 'auto' (WinHTTP/WPAD), 'direct', or 'http://user:pass@host:port'")
	clientCmd.Flags().StringVar(&clientProxyAuth, "proxy-auth", "basic", "Proxy authentication: 'basic', 'ntlm', 'negotiate'")
	clientCmd.Flags().IntVar(&clientConcurrency, "concurrency", 100, "Sweep worker pool concurrency (1–1000)")
	clientCmd.Flags().IntVar(&clientRateLimit, "rate-limit", 500, "Maximum sweep packets per second (0 = unlimited)")
	clientCmd.Flags().StringVar(&clientOutputJSON, "output-json", "", "Destination file for full JSON results")
	clientCmd.Flags().StringVar(&clientOutputHTML, "output-html", "", "Destination file for interactive zero-CDN HTML dashboard")
	clientCmd.Flags().StringVar(&clientOutputSARIF, "output-sarif", "", "Destination file for SARIF v2.1.0 vulnerability report")
	clientCmd.Flags().StringVar(&clientSyncReport, "sync-report", "", "URL of live dashboard server to synchronize report to (e.g. http://10.0.0.1:8080)")
	clientCmd.Flags().StringVar(&clientZone, "zone", "corporate-default", "Network zone or segment identifier for multi-zone telemetry")
	clientCmd.Flags().BoolVar(&clientNoColor, "no-color", false, "Disable ANSI color formatting in terminal output")
	clientCmd.Flags().BoolVar(&clientDestroy, "destroy", false, "Auto-cleanup uploaded objects in cloud storage (AWS, GCP, Azure)")
	clientCmd.Flags().BoolVar(&clientSavePayload, "save-payload", false, "Physically retain full exfiltrated payload on client disk")
	clientCmd.Flags().StringVar(&clientEvidenceDir, "evidence-dir", "evidence", "Directory to store reconstructed exfiltration payloads")

	// Operator flag aliases
	clientCmd.Flags().StringVar(&clientServer, "target", "127.0.0.1", "Alias for --server")
	clientCmd.Flags().StringVar(&clientRateAlias, "rate", "", "Alias for --throughput (e.g. '10MB/s') or --rate-limit (e.g. 500)")
	clientCmd.Flags().StringVar(&clientThroughput, "bandwidth", "unlimited", "Alias for --throughput")
	clientCmd.Flags().StringVar(&clientTLSFingerprint, "utls", "chrome", "Alias for --tls-fingerprint")
	clientCmd.Flags().StringVar(&clientIntervalMax, "jitter", "4s", "Alias for --interval-max")
	clientCmd.Flags().StringVar(&clientIntervalMax, "timing-jitter", "4s", "Alias for --interval-max")
	clientCmd.Flags().StringVar(&clientOutputJSON, "output", "", "Alias for --output-json")
	clientCmd.Flags().StringVar(&clientEvidenceDir, "report-dir", "evidence", "Alias for --evidence-dir")

	rootCmd.AddCommand(clientCmd)
}

func runClient(cmd *cobra.Command, args []string) error {
	cfg := client.DefaultClientConfig()

	// Merge CLI flags
	cfg.Server = clientServer
	cfg.Ports = clientPorts
	cfg.Protocols = clientProtocols
	cfg.DLPPayloads = clientDLP
	cfg.CarrierType = clientCarrierType
	cfg.Size = clientSize
	cfg.ChunkSize = clientChunkSize
	cfg.Threads = clientThreads
	cfg.Throughput = clientThroughput
	cfg.Cadence = clientCadence
	cfg.IntervalMin = clientIntervalMin
	cfg.IntervalMax = clientIntervalMax
	cfg.Transforms = clientTransforms
	cfg.Passphrase = clientPassphrase
	cfg.Stego = clientStego
	cfg.TLSFingerprint = clientTLSFingerprint
	cfg.Proxy = clientProxy
	cfg.ProxyAuth = clientProxyAuth
	cfg.Concurrency = clientConcurrency
	cfg.RateLimit = clientRateLimit
	cfg.OutputJSON = clientOutputJSON
	cfg.OutputHTML = clientOutputHTML
	cfg.OutputSARIF = clientOutputSARIF
	cfg.SyncReport = clientSyncReport
	cfg.Zone = clientZone
	cfg.NoColor = clientNoColor
	cfg.Destroy = clientDestroy
	cfg.SavePayload = clientSavePayload
	cfg.EvidenceDir = clientEvidenceDir
	cfg.Seed = flagSeed

	// CLI alias overrides
	if cmd.Flags().Changed("target") {
		cfg.Server = clientServer
	}
	if cmd.Flags().Changed("rate") {
		if val, err := strconv.Atoi(clientRateAlias); err == nil {
			cfg.RateLimit = val
			clientRateLimit = val
		} else if strings.HasSuffix(strings.ToLower(clientRateAlias), "/s") || strings.HasSuffix(strings.ToLower(clientRateAlias), "/sec") || strings.ToLower(clientRateAlias) == "unlimited" {
			if _, err := common.ParseBandwidthRate(clientRateAlias); err != nil {
				return fmt.Errorf("invalid bandwidth rate %q: %w", clientRateAlias, err)
			}
			cfg.Throughput = clientRateAlias
			clientThroughput = clientRateAlias
		} else {
			return fmt.Errorf("invalid argument %q for \"--rate\" flag: strconv.ParseInt: parsing %q: invalid syntax", clientRateAlias, clientRateAlias)
		}
	}
	if cmd.Flags().Changed("bandwidth") {
		cfg.Throughput = clientThroughput
	}
	if cmd.Flags().Changed("utls") {
		cfg.TLSFingerprint = clientTLSFingerprint
	}
	if cmd.Flags().Changed("jitter") || cmd.Flags().Changed("timing-jitter") {
		cfg.IntervalMax = clientIntervalMax
	}
	if cmd.Flags().Changed("output") {
		cfg.OutputJSON = clientOutputJSON
	}
	if cmd.Flags().Changed("report-dir") {
		cfg.EvidenceDir = clientEvidenceDir
	}

	// Merge configuration profile if loaded
	if loadedConfig != nil {
		if loadedConfig.Target.Server != "" && !cmd.Flags().Changed("server") && !cmd.Flags().Changed("target") {
			cfg.Server = loadedConfig.Target.Server
		}
		if loadedConfig.Target.Ports != "" && !cmd.Flags().Changed("ports") {
			cfg.Ports = loadedConfig.Target.Ports
		}
		if len(loadedConfig.Target.Protocols) > 0 && !cmd.Flags().Changed("protocols") {
			cfg.Protocols = strings.Join(loadedConfig.Target.Protocols, ",")
		}
		if len(loadedConfig.DLP.Payloads) > 0 && !cmd.Flags().Changed("dlp") {
			cfg.DLPPayloads = strings.Join(loadedConfig.DLP.Payloads, ",")
		}
		if loadedConfig.DLP.CarrierType != "" && !cmd.Flags().Changed("carrier-type") {
			cfg.CarrierType = loadedConfig.DLP.CarrierType
		}
		if loadedConfig.DLP.Size != "" && !cmd.Flags().Changed("size") {
			cfg.Size = loadedConfig.DLP.Size
		}
		if loadedConfig.Traffic.Threads > 0 && !cmd.Flags().Changed("threads") {
			cfg.Threads = loadedConfig.Traffic.Threads
		}
		if loadedConfig.Traffic.Throughput != "" && !cmd.Flags().Changed("throughput") && !cmd.Flags().Changed("bandwidth") && !cmd.Flags().Changed("rate") {
			cfg.Throughput = loadedConfig.Traffic.Throughput
		}
		if loadedConfig.Sweep.RateLimit > 0 && !cmd.Flags().Changed("rate-limit") && !cmd.Flags().Changed("rate") {
			cfg.RateLimit = loadedConfig.Sweep.RateLimit
		}
		if loadedConfig.Traffic.Cadence != "" && !cmd.Flags().Changed("cadence") {
			cfg.Cadence = loadedConfig.Traffic.Cadence
		}
		if loadedConfig.Proxy.Mode != "" && !cmd.Flags().Changed("proxy") {
			cfg.Proxy = loadedConfig.Proxy.Mode
		}
		if loadedConfig.Output.JSONPath != "" && !cmd.Flags().Changed("output-json") && !cmd.Flags().Changed("output") {
			cfg.OutputJSON = loadedConfig.Output.JSONPath
		}
		if loadedConfig.Output.HTMLPath != "" && !cmd.Flags().Changed("output-html") {
			cfg.OutputHTML = loadedConfig.Output.HTMLPath
		}
	}

	// Pre-Flight Dry Run Check
	if flagDryRun {
		return RunClientDryRun(cfg)
	}

	ctx := context.Background()
	_, err := client.RunAssessment(ctx, cfg)
	return err
}
