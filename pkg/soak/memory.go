package soak

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxHeapCeiling is the strict invariant ceiling (32 MB resident RAM).
	DefaultMaxHeapCeiling uint64 = 32 * 1024 * 1024
)

// MemoryStats carries point-in-time heap and memory statistics.
type MemoryStats struct {
	Timestamp      time.Time `json:"timestamp"`
	HeapAllocBytes uint64    `json:"heap_alloc_bytes"`
	HeapAllocMB    float64   `json:"heap_alloc_mb"`
	PeakHeapMB     float64   `json:"peak_heap_mb"`
	TotalAllocMB   float64   `json:"total_alloc_mb"`
	SysMB          float64   `json:"sys_mb"`
	NumGC          uint32    `json:"num_gc"`
	CeilingMB      float64   `json:"ceiling_mb"`
	Breached       bool      `json:"breached"`
}

// MemoryMonitor actively samples runtime heap memory to continuously verify
// that resident heap allocations remain strictly < 32MB over extended soak windows.
type MemoryMonitor struct {
	mu           sync.RWMutex
	ceilingBytes uint64
	interval     time.Duration
	peakAlloc    uint64
	currentAlloc uint64
	violations   int64
	samples      int64
	lastStats    MemoryStats
	onViolation  func(stats MemoryStats)
}

// NewMemoryMonitor creates a new MemoryMonitor with the specified ceiling and sample interval.
func NewMemoryMonitor(ceilingBytes uint64, interval time.Duration) *MemoryMonitor {
	if ceilingBytes == 0 {
		ceilingBytes = DefaultMaxHeapCeiling
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &MemoryMonitor{
		ceilingBytes: ceilingBytes,
		interval:     interval,
	}
}

// SetOnViolation registers a callback triggered whenever heap allocations breach the ceiling.
func (m *MemoryMonitor) SetOnViolation(cb func(stats MemoryStats)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onViolation = cb
}

// Start spawns the background monitoring goroutine.
func (m *MemoryMonitor) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Sample()
			}
		}
	}()
}

// Sample takes a memory snapshot, updates peak tracking, and enforces the invariant ceiling.
func (m *MemoryMonitor) Sample() MemoryStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	m.mu.Lock()
	defer m.mu.Unlock()

	atomic.AddInt64(&m.samples, 1)
	m.currentAlloc = ms.HeapAlloc

	if ms.HeapAlloc > m.peakAlloc {
		m.peakAlloc = ms.HeapAlloc
	}

	breached := ms.HeapAlloc >= m.ceilingBytes
	if breached {
		atomic.AddInt64(&m.violations, 1)
	}

	stats := MemoryStats{
		Timestamp:      time.Now().UTC(),
		HeapAllocBytes: ms.HeapAlloc,
		HeapAllocMB:    float64(ms.HeapAlloc) / (1024 * 1024),
		PeakHeapMB:     float64(m.peakAlloc) / (1024 * 1024),
		TotalAllocMB:   float64(ms.TotalAlloc) / (1024 * 1024),
		SysMB:          float64(ms.Sys) / (1024 * 1024),
		NumGC:          ms.NumGC,
		CeilingMB:      float64(m.ceilingBytes) / (1024 * 1024),
		Breached:       breached,
	}
	m.lastStats = stats

	if breached && m.onViolation != nil {
		go m.onViolation(stats)
	}

	return stats
}

// CurrentStats returns the most recently sampled MemoryStats.
func (m *MemoryMonitor) CurrentStats() MemoryStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastStats
}

// PeakHeapAllocMB returns peak resident heap allocation observed in MB.
func (m *MemoryMonitor) PeakHeapAllocMB() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return float64(m.peakAlloc) / (1024 * 1024)
}

// Violations returns the total count of ceiling breaches.
func (m *MemoryMonitor) Violations() int64 {
	return atomic.LoadInt64(&m.violations)
}

// FormatStatus returns a standardized one-line memory health summary.
func (m *MemoryMonitor) FormatStatus() string {
	s := m.CurrentStats()
	return fmt.Sprintf("Heap: %.2fMB / %.2fMB (Peak: %.2fMB, Violations: %d, GCs: %d)",
		s.HeapAllocMB, s.CeilingMB, s.PeakHeapMB, m.Violations(), s.NumGC)
}
