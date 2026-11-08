package client

import (
	"context"
	"fmt"
	"time"

	"github.com/shehzade/contraband/pkg/client/sweep"
	"github.com/shehzade/contraband/pkg/common"
)

func runStage1Sweep(ctx context.Context, cfg ClientConfig, logger common.Logger) ([]common.ProbeResult, error) {
	ports, err := common.ParsePortsField(cfg.Ports)
	if err != nil {
		return nil, fmt.Errorf("invalid ports specification %q: %w", cfg.Ports, err)
	}

	logger.Info(fmt.Sprintf("Stage 1: Initiating L4 port sweep against %s (%d ports, concurrency: %d)",
		cfg.Server, len(ports), cfg.Concurrency))

	sweepOpts := sweep.SweepOptions{
		Mode:              sweep.ModeBoth,
		Concurrency:       cfg.Concurrency,
		RateLimit:         cfg.RateLimit,
		Timeout:           1500 * time.Millisecond,
		RequireReflection: false,
		Logger:            logger,
	}
	sweepEngine := sweep.NewEngine(sweepOpts)
	sweepResults, err := sweepEngine.Sweep(ctx, cfg.Server, ports)
	if err != nil {
		logger.Warn(fmt.Sprintf("L4 sweep completed with non-fatal warning: %v", err))
	}

	var probes []common.ProbeResult
	openPorts := 0
	for _, p := range sweepResults {
		probe := p
		probe.Stage = "sweep"
		probes = append(probes, probe)

		if probe.Verdict == common.VerdictSuccess {
			openPorts++
			latencyMs := float64(probe.Timestamps.TCPDuration.Microseconds()) / 1000.0
			logger.Success(fmt.Sprintf("[OPEN] Port %d/%s (Latency: %.2fms)", probe.TargetPort, probe.Protocol, latencyMs))
		}
	}
	logger.Info(fmt.Sprintf("Stage 1 Complete: %d/%d ports open/unfiltered", openPorts, len(ports)))
	return probes, nil
}
