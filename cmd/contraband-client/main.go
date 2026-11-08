package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"

	"github.com/shehzade/contraband/pkg/client"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/dryrun"
	"github.com/spf13/cobra"
)

var (
	flagConfig  string
	flagVerbose bool
	flagJSON    bool
	flagSeed    int64
	flagDryRun  bool

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

	loadedConfig *common.ProfileConfig
	appLogger    common.Logger
)

var rootCmd = &cobra.Command{
	Use:   "contraband-client",
	Short: "Contraband Standalone Egress Assessment Client",
	Long: `Dedicated standalone client binary for automated network egress assessment,
multi-protocol data smuggling, corporate proxy traversal, synthetic DLP verification,
and forensic reporting.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		appLogger = common.GetLogger()
		if flagJSON {
			appLogger.SetMode(common.LogModeJSON)
		}
		if flagVerbose {
			appLogger.SetLevel(common.LogLevelDebug)
		}
		if flagSeed != 0 {
			rand.Seed(flagSeed)
			appLogger.Debug(fmt.Sprintf("Initialized deterministic random seed: %d", flagSeed))
		}
		if flagConfig != "" {
			cfg, err := common.LoadProfileConfig(flagConfig)
			if err != nil {
				return fmt.Errorf("failed to load configuration profile: %w", err)
			}
			loadedConfig = cfg
		}
		return nil
	},
	RunE: runClientStandalone,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "Path to YAML/JSON configuration profile")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose debug logging")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output results in structured JSON format")
	rootCmd.PersistentFlags().Int64Var(&flagSeed, "seed", 0, "Deterministic random seed for reproducible runs")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "Pre-flight validation without transmitting live network traffic")

	rootCmd.Flags().StringVarP(&clientServer, "server", "s", "127.0.0.1", "Target server IP or hostname")
	rootCmd.Flags().StringVarP(&clientPorts, "ports", "p", "quick", "Port preset: 'quick', 'standard', 'full', or comma/range")
	rootCmd.Flags().StringVar(&clientProtocols, "protocols", "all", "Protocols: 'all', category, or comma-separated list")
	rootCmd.Flags().StringVar(&clientDLP, "dlp", "all", "Synthetic DLP payloads: 'all', 'pci', 'pii', 'hipaa', 'secrets'")
	rootCmd.Flags().StringVar(&clientCarrierType, "carrier-type", "csv", "Procedural text carrier: 'csv', 'json', 'sql', 'email', 'syslog'")
	rootCmd.Flags().StringVar(&clientSize, "size", "1MB", "Data volume to exfiltrate ('100KB', '50MB', '2GB')")
	rootCmd.Flags().StringVar(&clientChunkSize, "chunk-size", "1MB", "Transfer chunk size ('64KB', '1MB')")
	rootCmd.Flags().IntVar(&clientThreads, "threads", 4, "Concurrent worker streams (1–64)")
	rootCmd.Flags().StringVar(&clientThroughput, "throughput", "unlimited", "Outbound rate limit ('100KB/s', '5MB/s', 'unlimited')")
	rootCmd.Flags().StringVar(&clientCadence, "cadence", "steady", "Traffic pacing: 'burst', 'steady', 'jittered', 'office-hours'")
	rootCmd.Flags().StringVar(&clientIntervalMin, "interval-min", "500ms", "Minimum jitter sleep interval")
	rootCmd.Flags().StringVar(&clientIntervalMax, "interval-max", "4s", "Maximum jitter sleep interval")
	rootCmd.Flags().StringVar(&clientTransforms, "transforms", "raw", "Evasion chain: comma-separated 'raw', 'base64', 'hex', 'gzip', 'zstd', 'aes_gcm'")
	rootCmd.Flags().StringVar(&clientPassphrase, "passphrase", "", "Passphrase for AES-256-GCM encryption")
	rootCmd.Flags().StringVar(&clientStego, "stego", "none", "Steganographic carrier: 'none', 'bmp', 'png', 'wav', 'jpeg-zip', 'pdf-jar'")
	rootCmd.Flags().StringVar(&clientTLSFingerprint, "tls-fingerprint", "chrome", "uTLS Client Hello: 'chrome', 'edge', 'safari', 'firefox', 'curl', 'default'")
	rootCmd.Flags().StringVar(&clientProxy, "proxy", "auto", "Proxy traversal: 'auto', 'direct', or URL")
	rootCmd.Flags().StringVar(&clientProxyAuth, "proxy-auth", "basic", "Proxy authentication: 'basic', 'ntlm', 'negotiate'")
	rootCmd.Flags().IntVar(&clientConcurrency, "concurrency", 100, "Sweep worker pool concurrency")
	rootCmd.Flags().IntVar(&clientRateLimit, "rate-limit", 500, "Maximum sweep packets per second")
	rootCmd.Flags().StringVar(&clientOutputJSON, "output-json", "", "Destination file for full JSON results")
	rootCmd.Flags().StringVar(&clientOutputHTML, "output-html", "", "Destination file for interactive zero-CDN HTML dashboard")
	rootCmd.Flags().StringVar(&clientOutputSARIF, "output-sarif", "", "Destination file for SARIF v2.1.0 report")
	rootCmd.Flags().StringVar(&clientSyncReport, "sync-report", "", "URL of live dashboard server to synchronize report to (e.g. http://10.0.0.1:8080)")
	rootCmd.Flags().StringVar(&clientZone, "zone", "corporate-default", "Network zone or segment identifier for multi-zone telemetry")
	rootCmd.Flags().BoolVar(&clientNoColor, "no-color", false, "Disable ANSI color formatting in terminal output")
	rootCmd.Flags().BoolVar(&clientDestroy, "destroy", false, "Auto-cleanup uploaded objects in cloud storage")
	rootCmd.Flags().BoolVar(&clientSavePayload, "save-payload", false, "Physically retain full exfiltrated payload on client disk")
	rootCmd.Flags().StringVar(&clientEvidenceDir, "evidence-dir", "evidence", "Directory to store reconstructed exfiltration payloads")

	// Operator flag aliases
	rootCmd.Flags().StringVar(&clientServer, "target", "127.0.0.1", "Alias for --server")
	rootCmd.Flags().StringVar(&clientRateAlias, "rate", "", "Alias for --throughput (e.g. '10MB/s') or --rate-limit (e.g. 500)")
	rootCmd.Flags().StringVar(&clientThroughput, "bandwidth", "unlimited", "Alias for --throughput")
	rootCmd.Flags().StringVar(&clientTLSFingerprint, "utls", "chrome", "Alias for --tls-fingerprint")
	rootCmd.Flags().StringVar(&clientIntervalMax, "jitter", "4s", "Alias for --interval-max")
	rootCmd.Flags().StringVar(&clientIntervalMax, "timing-jitter", "4s", "Alias for --interval-max")
	rootCmd.Flags().StringVar(&clientOutputJSON, "output", "", "Alias for --output-json")
	rootCmd.Flags().StringVar(&clientEvidenceDir, "report-dir", "evidence", "Alias for --evidence-dir")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print client version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Contraband Client v%s (Pure Go, CGO_ENABLED=0)\n", common.Version)
		},
	})
}

func runClientStandalone(cmd *cobra.Command, args []string) error {
	cfg := client.DefaultClientConfig()

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

	if flagDryRun {
		return dryrun.RunClientDryRun(cfg)
	}

	ctx := context.Background()
	_, err := client.RunAssessment(ctx, cfg)
	return err
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
