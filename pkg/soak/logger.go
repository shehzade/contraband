package soak

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// SoakLogger manages thread-safe, continuous append-only logging to the evidence soak test log.
// All durations, latencies, and timestamps are formatted in milliseconds (ms),
// with zero runtime microseconds.
type SoakLogger struct {
	mu       sync.Mutex
	filePath string
	file     *os.File
}

// NewSoakLogger initializes the soak logger, ensuring the destination directory exists.
func NewSoakLogger(filePath string) (*SoakLogger, error) {
	if filePath == "" {
		filePath = "evidence/soak_test.log"
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create soak log directory %q: %w", dir, err)
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open soak log file %q: %w", filePath, err)
	}

	return &SoakLogger{
		filePath: filePath,
		file:     f,
	}, nil
}

// Close flushes and closes the underlying log file.
func (l *SoakLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// writeLine handles formatting, timestamping, and flushing.
func (l *SoakLogger) writeLine(level, msg string) {
	now := time.Now().UTC()
	// Format timestamp with millisecond precision: YYYY-MM-DDTHH:MM:SS.mmmZ
	tsStr := now.Format("2006-01-02T15:04:05.000Z")
	line := fmt.Sprintf("[%s] [%s] %s\n", tsStr, level, msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		_, _ = l.file.WriteString(line)
		_ = l.file.Sync()
	}
}

// LogProbe records a completed or failed exfiltration probe with millisecond latency formatting.
func (l *SoakLogger) LogProbe(
	zone string,
	protocol string,
	volumeStr string,
	verdict common.Verdict,
	latencyMs float64,
	heapAllocMB float64,
	ceilingMB float64,
	payloadHash string,
	errMsg string,
) {
	level := "EXFIL"
	if verdict != common.VerdictSuccess {
		level = "WARN"
	}

	hashShort := payloadHash
	if len(hashShort) > 16 {
		hashShort = hashShort[:16] + "..."
	}

	var detail string
	if errMsg != "" {
		detail = fmt.Sprintf(" err=%q", errMsg)
	}

	msg := fmt.Sprintf("[ZONE=%s] [PROTO=%s] [VOL=%s] [VERDICT=%s] [LATENCY=%.2fms] [HEAP=%.2fMB/%.2fMB] [HASH=%s]%s",
		zone, protocol, volumeStr, verdict, latencyMs, heapAllocMB, ceilingMB, hashShort, detail)

	l.writeLine(level, msg)
}

// LogNegativeTest records a simulated disruption / negative test injection result.
func (l *SoakLogger) LogNegativeTest(
	negType string,
	zone string,
	target string,
	actualVerdict common.Verdict,
	expectedVerdict common.Verdict,
	latencyMs float64,
	passed bool,
) {
	level := "NEG_PASS"
	if !passed {
		level = "NEG_FAIL"
	}

	msg := fmt.Sprintf("[NEGATIVE_TEST=%s] [ZONE=%s] [TARGET=%s] [EXPECTED=%s] [ACTUAL=%s] [LATENCY=%.2fms] [PASSED=%t]",
		negType, zone, target, expectedVerdict, actualVerdict, latencyMs, passed)

	l.writeLine(level, msg)
}

// LogMemory records a memory health status or invariant check.
func (l *SoakLogger) LogMemory(stats MemoryStats) {
	level := "MEM_OK"
	if stats.Breached {
		level = "MEM_ALERT"
	}

	msg := fmt.Sprintf("[MEMORY_INVARIANT] [HEAP=%.2fMB/%.2fMB] [PEAK=%.2fMB] [SYS=%.2fMB] [TOTAL=%.2fMB] [NUM_GC=%d] [BREACHED=%t]",
		stats.HeapAllocMB, stats.CeilingMB, stats.PeakHeapMB, stats.SysMB, stats.TotalAllocMB, stats.NumGC, stats.Breached)

	l.writeLine(level, msg)
}

// LogReportUploaded records dashboard report synchronization.
func (l *SoakLogger) LogReportUploaded(reportID, zone string, eeiScore float64, posture string, durationMs float64) {
	msg := fmt.Sprintf("[REPORT_SYNC] [ID=%s] [ZONE=%s] [EEI=%.2f%%] [POSTURE=%s] [DURATION=%.2fms]",
		reportID, zone, eeiScore, posture, durationMs)
	l.writeLine("REPORT", msg)
}

// LogInfo records an operational information event.
func (l *SoakLogger) LogInfo(msg string) {
	l.writeLine("INFO", msg)
}

// LogAlert records a high-priority alert or failure.
func (l *SoakLogger) LogAlert(msg string) {
	l.writeLine("ALERT", msg)
}
