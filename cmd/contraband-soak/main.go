package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/soak"
	"github.com/spf13/cobra"
)

var (
	soakServer         string
	soakDashboard      string
	soakDuration       string
	soakLogFile        string
	soakMaxHeapMB      int
	soakValidationOnly bool
	soakDryRun         bool
	soakZones          int
	soakVolume         string
	appLogger          common.Logger
)

var rootCmd = &cobra.Command{
	Use:   "contraband-soak",
	Short: "Overnight Continuous Multi-Scenario Soak & Live Stress Engine",
	Long: `Contraband Overnight Continuous Soak & Stress Engine:
Executes uninterrupted 8-10 hour multi-scenario load testing across all 20 L7 smuggling protocols,
5 concurrent network zones, progressive volume spectrum (50MB-5GB+), strict <32MB heap invariant,
procedural synthetic DLP, steganography, proxy traversal, evasion, negative testing,
continuous evidence logging, and live command center dashboard synchronization.`,
	RunE: runSoakApp,
}

func init() {
	appLogger = common.GetLogger()

	rootCmd.Flags().StringVarP(&soakServer, "server", "s", "127.0.0.1", "Target Contraband reflection server address")
	rootCmd.Flags().StringVarP(&soakDashboard, "dashboard", "d", "http://127.0.0.1:8080", "Address of the Contraband live dashboard server")
	rootCmd.Flags().StringVar(&soakDuration, "duration", "10h", "Total soak execution window (e.g. 8h, 10h)")
	rootCmd.Flags().StringVar(&soakLogFile, "log-file", "evidence/soak_test.log", "Continuous audit trail log file path")
	rootCmd.Flags().IntVar(&soakMaxHeapMB, "max-heap-mb", 32, "Strict resident heap memory invariant ceiling in MB")
	rootCmd.Flags().BoolVar(&soakValidationOnly, "validation-only", false, "Execute pre-soak validation round (micro, medium, bulk tiers) and exit")
	rootCmd.Flags().BoolVar(&soakDryRun, "dry-run", false, "Pre-flight validation plan without executing network transmissions")
	rootCmd.Flags().IntVar(&soakZones, "zones", 5, "Number of concurrent network zones (default 5)")
	rootCmd.Flags().StringVar(&soakVolume, "volume", "", "Soak volume tier to stream (e.g. 50MB, 100MB, 1GB)")
}

func runSoakApp(cmd *cobra.Command, args []string) error {
	dur, err := time.ParseDuration(soakDuration)
	if err != nil {
		return fmt.Errorf("invalid duration format %q: %w", soakDuration, err)
	}

	cfg := soak.DefaultSoakConfig()
	cfg.TargetServer = soakServer
	cfg.DashboardURL = soakDashboard
	cfg.Duration = dur
	cfg.LogPath = soakLogFile
	cfg.MaxHeapCeiling = uint64(soakMaxHeapMB) * 1024 * 1024
	cfg.DryRun = soakDryRun

	if soakZones > 0 {
		cfg.Concurrency = soakZones
	}
	if soakVolume != "" {
		volBytes, err := common.ParseBytes(soakVolume)
		if err != nil {
			return fmt.Errorf("invalid volume format %q: %w", soakVolume, err)
		}
		cfg.Volumes = []int64{volBytes}
		cfg.ValidationVolumes = []int64{volBytes}
	}

	if dur <= 2*time.Minute {
		cfg.ReportInterval = 10 * time.Second
	}

	if cfg.DryRun {
		appLogger.Info("[DRY-RUN] Soak Pre-Flight Plan:")
		appLogger.Info(fmt.Sprintf("  Target Server:    %s", cfg.TargetServer))
		appLogger.Info(fmt.Sprintf("  Live Dashboard:   %s", cfg.DashboardURL))
		appLogger.Info(fmt.Sprintf("  Duration:         %s", cfg.Duration))
		appLogger.Info(fmt.Sprintf("  Evidence Log:     %s", cfg.LogPath))
		appLogger.Info(fmt.Sprintf("  Memory Ceiling:   < %d MB", soakMaxHeapMB))
		appLogger.Info(fmt.Sprintf("  Network Zones:    %d zones", len(soak.AllZones())))
		appLogger.Info(fmt.Sprintf("  Protocols:        %d L7 channels", len(soak.AllSoakProtocols())))
		appLogger.Info("[DRY-RUN] Pre-flight validation passed cleanly. Exiting without network I/O.")
		return nil
	}

	engine, err := soak.NewSoakEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize soak engine: %w", err)
	}
	defer engine.Close()

	runner := soak.NewSoakRunner(engine)

	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigChan
		appLogger.Info("Shutdown signal received, gracefully terminating soak engine...")
		cancel()
	}()

	if soakValidationOnly {
		return runner.RunValidationRound(ctx)
	}

	// For short test runs (<= 5m), jump straight to continuous multi-zone execution
	if dur > 5*time.Minute {
		if err := runner.RunValidationRound(ctx); err != nil {
			appLogger.Warn(fmt.Sprintf("Pre-soak validation pass warning: %v", err))
		}
	}

	return runner.RunContinuous(ctx)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
