package traffic

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ProfilePreset names
const (
	PresetStealth = "stealth"
	PresetFast    = "fast"
	PresetCovert  = "covert"
	PresetBulk    = "bulk"
)

// TrafficProfile encapsulates complete operational parameters for client egress traffic.
type TrafficProfile struct {
	Name         string
	Throughput   float64          // Bytes/sec (0.0 = unlimited)
	Cadence      string           // burst, steady, jittered, office-hours, low-and-slow
	IntervalMin  time.Duration    // Minimum delay
	IntervalMax  time.Duration    // Maximum delay
	Jitter       float64          // 0.0 to 1.0
	Distribution DistributionType // uniform or gaussian
	Threads      int              // Worker concurrency (1–64)
	PacketGap    time.Duration    // Microsecond gap between packets
	BurstBytes   int64            // Maximum token burst capacity
}

// PresetStealthProfile returns the stealth egress preset.
// Rate: 50 KB/s, Interval: 5s–15s, Jitter: 30%, Gaussian distribution, 1 thread.
func PresetStealthProfile() *TrafficProfile {
	return &TrafficProfile{
		Name:         PresetStealth,
		Throughput:   50 * 1024,
		Cadence:      common.CadenceLowAndSlow,
		IntervalMin:  5 * time.Second,
		IntervalMax:  15 * time.Second,
		Jitter:       0.30,
		Distribution: DistributionGaussian,
		Threads:      1,
		PacketGap:    1000 * time.Microsecond,
		BurstBytes:   64 * 1024,
	}
}

// PresetFastProfile returns maximum throughput line rate preset.
// Rate: unlimited, 0 delay, 0 jitter, 16 threads.
func PresetFastProfile() *TrafficProfile {
	return &TrafficProfile{
		Name:         PresetFast,
		Throughput:   0.0, // unlimited
		Cadence:      common.CadenceBurst,
		IntervalMin:  0,
		IntervalMax:  0,
		Jitter:       0.0,
		Distribution: DistributionUniform,
		Threads:      16,
		PacketGap:    0,
		BurstBytes:   4 * 1024 * 1024,
	}
}

// PresetCovertProfile returns the covert beaconing preset.
// Rate: 200 KB/s, Interval: 1s–3s, Jitter: 25%, Gaussian distribution, 2 threads.
func PresetCovertProfile() *TrafficProfile {
	return &TrafficProfile{
		Name:         PresetCovert,
		Throughput:   200 * 1024,
		Cadence:      common.CadenceJittered,
		IntervalMin:  1 * time.Second,
		IntervalMax:  3 * time.Second,
		Jitter:       0.25,
		Distribution: DistributionGaussian,
		Threads:      2,
		PacketGap:    500 * time.Microsecond,
		BurstBytes:   128 * 1024,
	}
}

// PresetBulkProfile returns the bulk transfer preset.
// Rate: 10 MB/s, Interval: 10ms–50ms, Jitter: 5%, Uniform distribution, 8 threads.
func PresetBulkProfile() *TrafficProfile {
	return &TrafficProfile{
		Name:         PresetBulk,
		Throughput:   10 * 1024 * 1024,
		Cadence:      common.CadenceSteady,
		IntervalMin:  10 * time.Millisecond,
		IntervalMax:  50 * time.Millisecond,
		Jitter:       0.05,
		Distribution: DistributionUniform,
		Threads:      8,
		PacketGap:    50 * time.Microsecond,
		BurstBytes:   2 * 1024 * 1024,
	}
}

// FromConfig constructs a TrafficProfile from common.TrafficConfig.
func FromConfig(cfg common.TrafficConfig) (*TrafficProfile, error) {
	rate, err := common.ParseBandwidthRate(cfg.Throughput)
	if err != nil {
		return nil, fmt.Errorf("invalid profile throughput %q: %w", cfg.Throughput, err)
	}

	var minD, maxD time.Duration
	if cfg.IntervalMin != "" {
		minD, err = common.ParseDuration(cfg.IntervalMin)
		if err != nil {
			return nil, fmt.Errorf("invalid interval_min %q: %w", cfg.IntervalMin, err)
		}
	}
	if cfg.IntervalMax != "" {
		maxD, err = common.ParseDuration(cfg.IntervalMax)
		if err != nil {
			return nil, fmt.Errorf("invalid interval_max %q: %w", cfg.IntervalMax, err)
		}
	}

	jitter := cfg.Jitter
	if jitter > 1.0 {
		jitter = jitter / 100.0
	}

	threads := cfg.Threads
	if threads <= 0 {
		threads = common.DefaultThreads
	}

	cadence := strings.ToLower(cfg.Cadence)
	if cadence == "" {
		cadence = common.CadenceSteady
	}

	return &TrafficProfile{
		Name:         cadence,
		Throughput:   rate,
		Cadence:      cadence,
		IntervalMin:  minD,
		IntervalMax:  maxD,
		Jitter:       jitter,
		Distribution: DistributionGaussian,
		Threads:      threads,
		PacketGap:    100 * time.Microsecond,
	}, nil
}

// TrafficMetrics tracks lock-free cumulative and instantaneous traffic stats.
type TrafficMetrics struct {
	bytesSent       atomic.Int64
	bytesRecv       atomic.Int64
	packetsSent     atomic.Int64
	sleepDurationNs atomic.Int64
	startTime       time.Time

	mu      sync.RWMutex
	samples []rateSample
}

type rateSample struct {
	t     time.Time
	bytes int64
}

// NewTrafficMetrics initializes a new metrics tracker.
func NewTrafficMetrics() *TrafficMetrics {
	return &TrafficMetrics{
		startTime: time.Now(),
		samples:   make([]rateSample, 0, 128),
	}
}

func (m *TrafficMetrics) RecordBytesSent(n int64) {
	if n <= 0 {
		return
	}
	m.bytesSent.Add(n)

	m.mu.Lock()
	now := time.Now()
	m.samples = append(m.samples, rateSample{t: now, bytes: n})
	// Prune samples older than 5 seconds
	cutoff := now.Add(-5 * time.Second)
	idx := 0
	for idx < len(m.samples) && m.samples[idx].t.Before(cutoff) {
		idx++
	}
	if idx > 0 {
		m.samples = m.samples[idx:]
	}
	m.mu.Unlock()
}

func (m *TrafficMetrics) RecordBytesRecv(n int64) {
	if n > 0 {
		m.bytesRecv.Add(n)
	}
}

func (m *TrafficMetrics) RecordPacket() {
	m.packetsSent.Add(1)
}

func (m *TrafficMetrics) RecordSleep(d time.Duration) {
	if d > 0 {
		m.sleepDurationNs.Add(d.Nanoseconds())
	}
}

// CurrentThroughputBps returns instant throughput in bytes/sec over the last 1 second window.
func (m *TrafficMetrics) CurrentThroughputBps() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	windowStart := now.Add(-1 * time.Second)
	var windowBytes int64
	for i := len(m.samples) - 1; i >= 0; i-- {
		if m.samples[i].t.Before(windowStart) {
			break
		}
		windowBytes += m.samples[i].bytes
	}
	return float64(windowBytes)
}

// AverageThroughputBps returns overall average throughput since start.
func (m *TrafficMetrics) AverageThroughputBps() float64 {
	elapsed := time.Since(m.startTime).Seconds()
	if elapsed <= 0 {
		return 0.0
	}
	return float64(m.bytesSent.Load()) / elapsed
}

// TrafficStats represents an exported thread-safe snapshot.
type TrafficStats struct {
	BytesSent          int64   `json:"bytes_sent"`
	BytesRecv          int64   `json:"bytes_recv"`
	PacketsSent        int64   `json:"packets_sent"`
	TotalSleepMS       float64 `json:"total_sleep_ms"`
	CurrentRateString  string  `json:"current_rate"`
	AverageRateString  string  `json:"average_rate"`
	AverageRateBps     float64 `json:"average_rate_bps"`
	CurrentRateBps     float64 `json:"current_rate_bps"`
	ElapsedTimeSeconds float64 `json:"elapsed_seconds"`
}

// Snapshot returns an immutable point-in-time snapshot.
func (m *TrafficMetrics) Snapshot() TrafficStats {
	sent := m.bytesSent.Load()
	recv := m.bytesRecv.Load()
	pkts := m.packetsSent.Load()
	sleepNs := m.sleepDurationNs.Load()
	elapsed := time.Since(m.startTime).Seconds()

	currRate := m.CurrentThroughputBps()
	avgRate := m.AverageThroughputBps()

	return TrafficStats{
		BytesSent:          sent,
		BytesRecv:          recv,
		PacketsSent:        pkts,
		TotalSleepMS:       float64(sleepNs) / 1e6,
		CurrentRateString:  common.FormatBandwidthRate(currRate),
		AverageRateString:  common.FormatBandwidthRate(avgRate),
		AverageRateBps:     avgRate,
		CurrentRateBps:     currRate,
		ElapsedTimeSeconds: elapsed,
	}
}
