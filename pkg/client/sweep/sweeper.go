package sweep

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// SweepMode designates the transport layer protocol under test.
type SweepMode string

const (
	ModeTCP  SweepMode = "TCP"
	ModeUDP  SweepMode = "UDP"
	ModeBoth SweepMode = "BOTH"
)

// SweepOptions configures the execution of the L4 sweep engine.
type SweepOptions struct {
	Mode              SweepMode     // ModeTCP, ModeUDP, ModeBoth (default: ModeTCP)
	Concurrency       int           // 1 to 1000 (default: common.DefaultConcurrency = 100)
	RateLimit         int           // Max packets per second; <=0 means unlimited (default: 500)
	Timeout           time.Duration // Socket dial/read timeout (default: 1500ms)
	JitterMin         time.Duration // Minimum randomized inter-probe delay (default: 5ms)
	JitterMax         time.Duration // Maximum randomized inter-probe delay (default: 50ms)
	RequireReflection bool          // If true, requires valid BannerReflection for VerdictSuccess (default: true)
	Logger            common.Logger // Leveled terminal/JSON logger
}

// DefaultSweepOptions returns production-grade defaults.
func DefaultSweepOptions() SweepOptions {
	return SweepOptions{
		Mode:              ModeTCP,
		Concurrency:       common.DefaultConcurrency,
		RateLimit:         common.DefaultRateLimit,
		Timeout:           common.DefaultTCPTimeout,
		JitterMin:         5 * time.Millisecond,
		JitterMax:         50 * time.Millisecond,
		RequireReflection: true,
		Logger:            common.GetLogger(),
	}
}

// Sweeper defines the interface for running concurrent egress sweeps.
type Sweeper interface {
	// Sweep executes a synchronous sweep across all target ports and returns results.
	Sweep(ctx context.Context, targetHost string, ports []int) ([]common.ProbeResult, error)

	// SweepStream executes the sweep and streams ProbeResult objects over out channel.
	// The out channel is NOT closed by SweepStream (caller owns the channel).
	SweepStream(ctx context.Context, targetHost string, ports []int, out chan<- common.ProbeResult) error
}

// Engine implements Sweeper using a concurrent worker pool and rate limiter.
type Engine struct {
	opts    SweepOptions
	limiter *TokenBucket
}

// NewEngine constructs a validated Engine instance.
func NewEngine(opts SweepOptions) *Engine {
	if opts.Concurrency < 1 {
		opts.Concurrency = common.DefaultConcurrency
	} else if opts.Concurrency > common.MaxConcurrency {
		opts.Concurrency = common.MaxConcurrency
	}
	if opts.Timeout <= 0 {
		opts.Timeout = common.DefaultTCPTimeout
	}
	if opts.Logger == nil {
		opts.Logger = common.GetLogger()
	}

	var limiter *TokenBucket
	if opts.RateLimit > 0 {
		limiter = NewTokenBucket(opts.RateLimit, opts.RateLimit)
	}

	return &Engine{
		opts:    opts,
		limiter: limiter,
	}
}

// Sweep runs a full sweep across targetHost and ports synchronously.
func (e *Engine) Sweep(ctx context.Context, targetHost string, ports []int) ([]common.ProbeResult, error) {
	if len(ports) == 0 {
		return []common.ProbeResult{}, nil
	}

	bufSize := len(ports)
	if e.opts.Mode == ModeBoth {
		bufSize = len(ports) * 2
	}
	out := make(chan common.ProbeResult, bufSize)
	results := make([]common.ProbeResult, 0, bufSize)

	errCh := make(chan error, 1)
	go func() {
		errCh <- e.SweepStream(ctx, targetHost, ports, out)
		close(out)
	}()

	for res := range out {
		results = append(results, res)
	}

	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		return results, err
	}
	return results, ctx.Err()
}

// SweepStream streams ProbeResults over out channel using a concurrent worker pool.
func (e *Engine) SweepStream(ctx context.Context, targetHost string, ports []int, out chan<- common.ProbeResult) error {
	if len(ports) == 0 {
		return nil
	}

	type sweepJob struct {
		port  int
		proto SweepMode
	}

	totalJobs := len(ports)
	if e.opts.Mode == ModeBoth {
		totalJobs = len(ports) * 2
	}
	jobs := make(chan sweepJob, totalJobs)

	// Populate jobs
	for _, p := range ports {
		if e.opts.Mode == ModeBoth {
			jobs <- sweepJob{port: p, proto: ModeTCP}
			jobs <- sweepJob{port: p, proto: ModeUDP}
		} else if e.opts.Mode == ModeUDP {
			jobs <- sweepJob{port: p, proto: ModeUDP}
		} else {
			jobs <- sweepJob{port: p, proto: ModeTCP}
		}
	}
	close(jobs)

	numWorkers := e.opts.Concurrency
	if numWorkers > totalJobs {
		numWorkers = totalJobs
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					// Rate limit enforcement
					if e.limiter != nil {
						if err := e.limiter.Wait(ctx); err != nil {
							return
						}
					}

					// Evasion jitter
					if err := ApplyJitter(ctx, e.opts.JitterMin, e.opts.JitterMax); err != nil {
						return
					}

					var result common.ProbeResult
					if job.proto == ModeUDP {
						result = ProbeUDP(ctx, targetHost, job.port, e.opts.Timeout, e.opts.RequireReflection)
					} else {
						result = ProbeTCP(ctx, targetHost, job.port, e.opts.Timeout, e.opts.RequireReflection)
					}

					select {
					case <-ctx.Done():
						return
					case out <- result:
					}
				}
			}
		}()
	}

	wg.Wait()
	return nil
}
