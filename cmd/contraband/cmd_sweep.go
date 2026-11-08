package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/client/sweep"
	"github.com/shehzade/contraband/pkg/client/traffic"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/spf13/cobra"
)

var (
	sweepTarget      string
	sweepPorts       string
	sweepProtocol    string
	sweepRate        int
	sweepConcurrency int
	sweepTimeout     string
	sweepProfile     string
)

var sweepCmd = &cobra.Command{
	Use:   "sweep",
	Short: "Execute Layer 4 TCP/UDP egress port sweep",
	Long: `Scan target ports using high-concurrency worker pools, token-bucket
rate limiting, microsecond timestamping, and JSON reflection verification.`,
	RunE: runSweep,
}

func init() {
	sweepCmd.Flags().StringVarP(&sweepTarget, "target", "t", "", "Target server IP or hostname (required)")
	sweepCmd.Flags().StringVarP(&sweepPorts, "ports", "p", "quick", "Ports to test: 'quick' (25), 'standard' (200), 'full' (65535), or '80,443,8000-8100'")
	sweepCmd.Flags().StringVar(&sweepProtocol, "protocol", "tcp", "Transport protocol: 'tcp', 'udp', or 'both'")
	sweepCmd.Flags().IntVarP(&sweepRate, "rate", "r", 500, "Maximum packets per second (0 = unlimited)")
	sweepCmd.Flags().IntVar(&sweepConcurrency, "concurrency", 100, "Worker pool concurrency (1-1000)")
	sweepCmd.Flags().StringVar(&sweepTimeout, "timeout", "1500ms", "Socket timeout per port probe")
	sweepCmd.Flags().StringVar(&sweepProfile, "profile", "fast", "Traffic cadence profile: 'stealth', 'fast', 'covert', 'bulk'")

	rootCmd.AddCommand(sweepCmd)
}

func runSweep(cmd *cobra.Command, args []string) error {
	if sweepTarget == "" {
		return fmt.Errorf("--target is required")
	}

	ports, err := common.ParsePortsField(sweepPorts)
	if err != nil {
		return fmt.Errorf("invalid --ports specification: %w", err)
	}

	timeout, err := common.ParseDuration(sweepTimeout)
	if err != nil {
		return fmt.Errorf("invalid --timeout: %w", err)
	}

	// Apply traffic profile presets if requested
	switch strings.ToLower(sweepProfile) {
	case traffic.PresetStealth:
		if !cmd.Flags().Changed("rate") {
			sweepRate = 50
		}
		if !cmd.Flags().Changed("concurrency") {
			sweepConcurrency = 1
		}
	case traffic.PresetCovert:
		if !cmd.Flags().Changed("rate") {
			sweepRate = 100
		}
		if !cmd.Flags().Changed("concurrency") {
			sweepConcurrency = 5
		}
	case traffic.PresetBulk:
		if !cmd.Flags().Changed("rate") {
			sweepRate = 2000
		}
		if !cmd.Flags().Changed("concurrency") {
			sweepConcurrency = 200
		}
	}

	// Pre-Flight Dry Run Check
	if flagDryRun {
		return RunSweepDryRun(sweepTarget, ports, sweepProtocol, sweepRate, sweepConcurrency, timeout)
	}

	var mode sweep.SweepMode
	switch strings.ToLower(sweepProtocol) {
	case "tcp":
		mode = sweep.ModeTCP
	case "udp":
		mode = sweep.ModeUDP
	case "both":
		mode = sweep.ModeBoth
	default:
		return fmt.Errorf("unknown protocol %q (use 'tcp', 'udp', or 'both')", sweepProtocol)
	}

	opts := sweep.SweepOptions{
		Mode:              mode,
		Concurrency:       sweepConcurrency,
		RateLimit:         sweepRate,
		Timeout:           timeout,
		JitterMin:         5 * time.Millisecond,
		JitterMax:         50 * time.Millisecond,
		RequireReflection: true,
		Logger:            appLogger,
	}

	engine := sweep.NewEngine(opts)
	ctx := context.Background()

	appLogger.Info(fmt.Sprintf("Starting egress sweep against %s (%d ports, %s, rate: %d pps)",
		sweepTarget, len(ports), mode, sweepRate))

	results, err := engine.Sweep(ctx, sweepTarget, ports)
	if err != nil {
		return fmt.Errorf("sweep execution failed: %w", err)
	}

	// Output results
	openCount := 0
	for _, res := range results {
		if res.Verdict == common.VerdictSuccess {
			openCount++
			latencyMs := float64(res.Timestamps.TCPDuration.Nanoseconds()) / 1e6
			appLogger.Success(fmt.Sprintf("OPEN: Port %d/%s (Latency: %.2fms)",
				res.TargetPort, res.Protocol, latencyMs))
		}
	}

	appLogger.Info(fmt.Sprintf("Sweep complete: %d/%d ports open/egressable", openCount, len(ports)))
	return nil
}
