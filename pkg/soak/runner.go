package soak

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// SoakRunner coordinates persistent continuous multi-zone execution across the 8-10 hour window.
type SoakRunner struct {
	engine *SoakEngine
	logger common.Logger
}

// NewSoakRunner wraps a SoakEngine for daemonized or bounded execution.
func NewSoakRunner(engine *SoakEngine) *SoakRunner {
	return &SoakRunner{
		engine: engine,
		logger: common.GetLogger(),
	}
}

// Engine returns the underlying SoakEngine.
func (r *SoakRunner) Engine() *SoakEngine {
	return r.engine
}

// RunValidationRound executes a rapid verification round across micro, medium, and bulk tiers
// to validate all pathways, memory ceiling invariants, and dashboard report sync.
func (r *SoakRunner) RunValidationRound(ctx context.Context) error {
	r.logger.Info("Starting Pre-Soak Validation Pass (Micro, Medium, Bulk tiers)...")
	r.engine.startTime = time.Now().UTC()
	r.engine.memMonitor.Start(ctx)

	valMatrix := GenerateScenarioMatrix(r.engine.config.ValidationVolumes)
	r.logger.Info(fmt.Sprintf("Validation matrix generated: %d scenarios across %d zones and %d protocols",
		len(valMatrix), len(AllZones()), len(AllSoakProtocols())))

	// Distribute scenarios into zone queues
	zoneQueues := make(map[string][]Scenario)
	for _, sc := range valMatrix {
		zoneQueues[sc.Zone] = append(zoneQueues[sc.Zone], sc)
	}

	var wg sync.WaitGroup
	for zone, queue := range zoneQueues {
		wg.Add(1)
		go func(z string, q []Scenario) {
			defer wg.Done()
			for _, sc := range q {
				select {
				case <-ctx.Done():
					return
				default:
					_ = r.engine.ExecuteScenario(ctx, sc)
					runtime.GC()
					time.Sleep(10 * time.Millisecond)
				}
			}
			// Sync zone report to live dashboard
			_ = r.engine.GenerateAndSyncReport(ctx, z)
		}(zone, queue)
	}

	wg.Wait()

	summary := r.engine.Summary()
	r.logger.Success(fmt.Sprintf("Validation Round Complete: %d/%d scenarios verified, %s transferred, Peak Heap: %.2fMB (Invariant Healthy: %t)",
		summary.SuccessScenarios, summary.TotalScenarios, summary.FormattedBytes, summary.PeakHeapMB, summary.MemoryHealthy))

	if !summary.MemoryHealthy {
		return fmt.Errorf("memory invariant breached during validation round: peak=%.2fMB, violations=%d",
			summary.PeakHeapMB, summary.MemoryViolations)
	}

	return nil
}

// RunContinuous launches the overnight 8-10 hour continuous multi-scenario soak engine.
// Executes uninterrupted across all 20 L7 protocols and large transfers until context cancel or duration expiration.
func (r *SoakRunner) RunContinuous(ctx context.Context) error {
	r.engine.startTime = time.Now().UTC()
	r.engine.memMonitor.Start(ctx)

	r.logger.Info(fmt.Sprintf("================================================================================"))
	r.logger.Info(fmt.Sprintf("OVERNIGHT 8-10 HOUR CONTINUOUS SOAK & LIVE STRESS ENGINE LAUNCHED"))
	r.logger.Info(fmt.Sprintf("Target: %s | Live Dashboard: %s | Duration: %s",
		r.engine.config.TargetServer, r.engine.config.DashboardURL, r.engine.config.Duration))
	r.logger.Info(fmt.Sprintf("Zones: 5 Concurrent | Protocols: 20 L7 Channels | Volumes: 50MB-5GB+ | Memory Ceiling: <32MB"))
	r.logger.Info(fmt.Sprintf("Continuous Logging: %s", r.engine.config.LogPath))
	r.logger.Info(fmt.Sprintf("================================================================================"))

	r.engine.logger.LogInfo(fmt.Sprintf("Soak engine started with %d scenarios in primary matrix. Duration: %s",
		len(r.engine.matrix), r.engine.config.Duration))

	zones := AllZones()
	scenariosByZone := make(map[string][]Scenario)
	for _, sc := range r.engine.matrix {
		scenariosByZone[sc.Zone] = append(scenariosByZone[sc.Zone], sc)
	}

	// Periodic report sync & memory status logger
	reportTicker := time.NewTicker(r.engine.config.ReportInterval)
	defer reportTicker.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reportTicker.C:
				memStats := r.engine.memMonitor.Sample()
				r.engine.logger.LogMemory(memStats)
				r.logger.Info(fmt.Sprintf("[SOAK MONITOR] %s | Smuggled: %s | Scenarios: %d | Reports: %d",
					r.engine.memMonitor.FormatStatus(),
					common.FormatBytes(r.engine.Summary().TotalBytesSmuggled),
					r.engine.Summary().TotalScenarios,
					r.engine.Summary().ReportsUploaded))

				// Sync periodic report for each zone to keep HUD spinning
				for _, z := range zones {
					_ = r.engine.GenerateAndSyncReport(ctx, z)
				}
			}
		}
	}()

	// Spawn concurrent worker goroutines for each network zone
	var wg sync.WaitGroup
	var errOnce sync.Once
	var firstErr error

	for _, zone := range zones {
		wg.Add(1)
		go func(z string) {
			defer wg.Done()
			q := scenariosByZone[z]
			if len(q) == 0 {
				q = r.engine.matrix
			}

			idx := 0
			round := 1

			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				sc := q[idx]
				if err := r.engine.ExecuteScenario(ctx, sc); err != nil {
					// Scenarios classify errors into verdicts without aborting soak
				}

				idx++
				if idx >= len(q) {
					idx = 0
					round++
					r.logger.Info(fmt.Sprintf("[ZONE %s] Completed round %d across all scenario matrix permutations", z, round-1))
					_ = r.engine.GenerateAndSyncReport(ctx, z)
				}

				// Brief yield to avoid CPU spinning when transfers complete
				time.Sleep(50 * time.Millisecond)
			}
		}(zone)
	}

	// Wait for context cancellation or timeout
	select {
	case <-ctx.Done():
		r.logger.Info("Soak engine received termination signal or duration elapsed. Initiating graceful shutdown...")
	}

	wg.Wait()

	finalSummary := r.engine.Summary()
	r.logger.Success(fmt.Sprintf("Soak engine shutdown complete. Elapsed: %.2fms | Total Scenarios: %d | Success: %d | Peak Heap: %.2fMB | Invariant Healthy: %t",
		finalSummary.ElapsedMS, finalSummary.TotalScenarios, finalSummary.SuccessScenarios, finalSummary.PeakHeapMB, finalSummary.MemoryHealthy))

	errOnce.Do(func() {
		if !finalSummary.MemoryHealthy {
			firstErr = fmt.Errorf("memory ceiling <32MB invariant breached during soak run")
		}
	})

	return firstErr
}
