package traffic

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// RateLimiter defines the interface for token bucket bandwidth and packet pacing.
type RateLimiter interface {
	// WaitN blocks until n tokens (bytes) are available or context is cancelled.
	WaitN(ctx context.Context, n int) error

	// AllowN returns true if n tokens are immediately available and consumes them.
	AllowN(n int) bool

	// ReserveN reserves n tokens and returns wait duration before consumption is valid.
	ReserveN(n int) (time.Duration, bool)

	// Refund restores unused tokens (e.g. on short read or partial write).
	Refund(n int)

	// SetRate dynamically updates bandwidth rate in bytes per second.
	SetRate(rateBytesPerSec float64)

	// SetBurst dynamically updates burst capacity in bytes.
	SetBurst(burstBytes int64)

	// SetPacketGap sets minimum microsecond inter-packet gap.
	SetPacketGap(gap time.Duration)

	// Rate returns current rate in bytes per second (0.0 = unlimited).
	Rate() float64

	// Burst returns maximum burst capacity in bytes.
	Burst() int64

	// PacketGap returns minimum microsecond inter-packet gap.
	PacketGap() time.Duration

	// IsUnlimited returns true if bandwidth limiting is bypassed.
	IsUnlimited() bool
}

// TokenBucket implements RateLimiter with microsecond precision and burst control.
type TokenBucket struct {
	mu             sync.Mutex
	rate           float64       // Bytes per second (0.0 = unlimited)
	capacity       float64       // Burst capacity in bytes
	tokens         float64       // Current available tokens
	lastRefill     time.Time     // Monotonic timestamp of last refill
	packetGap      time.Duration // Microsecond inter-packet gap
	lastPacketTime time.Time     // Monotonic timestamp of last write
	isUnlimited    atomic.Bool   // Fast-path bypass flag
}

// NewTokenBucket creates a token bucket with given rate and burst capacity.
// If rateBytesPerSec <= 0, bucket operates in unlimited mode.
func NewTokenBucket(rateBytesPerSec float64, burstBytes int64, packetGap time.Duration) *TokenBucket {
	now := time.Now()
	if rateBytesPerSec <= 0.0 || math.IsNaN(rateBytesPerSec) || math.IsInf(rateBytesPerSec, 0) {
		tb := &TokenBucket{
			rate:           0.0,
			capacity:       float64(burstBytes),
			tokens:         float64(burstBytes),
			lastRefill:     now,
			packetGap:      packetGap,
			lastPacketTime: now,
		}
		tb.isUnlimited.Store(true)
		return tb
	}

	// Default burst capacity: 200ms worth of tokens or at least 64KB, max 4MB
	capFloat := float64(burstBytes)
	if capFloat <= 0 {
		capFloat = math.Max(64*1024, math.Min(rateBytesPerSec*0.2, 4*1024*1024))
	}

	tb := &TokenBucket{
		rate:           rateBytesPerSec,
		capacity:       capFloat,
		tokens:         capFloat, // start full
		lastRefill:     now,
		packetGap:      packetGap,
		lastPacketTime: now,
	}
	tb.isUnlimited.Store(false)
	return tb
}

// NewTokenBucketFromString initializes a TokenBucket using human rate string ("100KB/s", "unlimited").
func NewTokenBucketFromString(rateStr string, burstBytes int64, packetGap time.Duration) (*TokenBucket, error) {
	rate, err := common.ParseBandwidthRate(rateStr)
	if err != nil {
		return nil, err
	}
	return NewTokenBucket(rate, burstBytes, packetGap), nil
}

// WaitN blocks until n tokens are consumed or ctx is cancelled.
func (tb *TokenBucket) WaitN(ctx context.Context, n int) error {
	if n <= 0 || tb.isUnlimited.Load() {
		return nil
	}

	for {
		// Fast check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if tb.isUnlimited.Load() {
			return nil
		}

		tb.mu.Lock()
		tb.refill()

		if tb.isUnlimited.Load() || tb.rate <= 0.0 {
			tb.mu.Unlock()
			return nil
		}

		// Enforce microsecond packet gap if configured
		var gapWait time.Duration
		now := time.Now()
		if tb.packetGap > 0 {
			elapsedGap := now.Sub(tb.lastPacketTime)
			if elapsedGap < tb.packetGap {
				gapWait = tb.packetGap - elapsedGap
			}
		}

		needed := float64(n)
		if needed > tb.capacity {
			tb.capacity = needed * 2
		}
		if tb.tokens >= needed {
			// Tokens available immediately
			tb.tokens -= needed
			tb.lastPacketTime = now.Add(gapWait)
			tb.mu.Unlock()

			if gapWait > 0 {
				return sleepContext(ctx, gapWait)
			}
			return nil
		}

		// Calculate wait time for remaining deficit
		deficit := needed - tb.tokens
		waitSec := deficit / tb.rate
		waitDur := time.Duration(waitSec * float64(time.Second))
		if gapWait > waitDur {
			waitDur = gapWait
		}
		tb.mu.Unlock()

		// Sleep for required deficit duration
		if err := sleepContext(ctx, waitDur); err != nil {
			return err
		}
	}
}

// AllowN performs non-blocking token check and deduction.
func (tb *TokenBucket) AllowN(n int) bool {
	if n <= 0 || tb.isUnlimited.Load() {
		return true
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.isUnlimited.Load() || tb.rate <= 0.0 {
		return true
	}

	tb.refill()
	needed := float64(n)
	if tb.tokens >= needed {
		tb.tokens -= needed
		tb.lastPacketTime = time.Now()
		return true
	}
	return false
}

// ReserveN calculates how long caller must wait before consuming n tokens.
func (tb *TokenBucket) ReserveN(n int) (time.Duration, bool) {
	if n <= 0 || tb.isUnlimited.Load() {
		return 0, true
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.isUnlimited.Load() || tb.rate <= 0.0 {
		return 0, true
	}

	tb.refill()
	needed := float64(n)
	if needed > tb.capacity {
		tb.capacity = needed * 2
	}
	if tb.tokens >= needed {
		tb.tokens -= needed
		return 0, true
	}

	deficit := needed - tb.tokens
	waitSec := deficit / tb.rate
	waitDur := time.Duration(waitSec * float64(time.Second))
	tb.tokens = 0 // consume all currently available
	return waitDur, false
}

// Refund returns unconsumed tokens back to the bucket (clamped to capacity).
func (tb *TokenBucket) Refund(n int) {
	if n <= 0 || tb.isUnlimited.Load() {
		return
	}

	tb.mu.Lock()
	defer tb.mu.Unlock()

	if tb.isUnlimited.Load() || tb.rate <= 0.0 {
		return
	}

	tb.refill()
	tb.tokens = math.Min(tb.capacity, tb.tokens+float64(n))
}

func (tb *TokenBucket) SetRate(rateBytesPerSec float64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refill()
	if rateBytesPerSec <= 0.0 || math.IsNaN(rateBytesPerSec) || math.IsInf(rateBytesPerSec, 0) {
		tb.rate = 0.0
		tb.isUnlimited.Store(true)
	} else {
		tb.rate = rateBytesPerSec
		tb.isUnlimited.Store(false)
	}
}

func (tb *TokenBucket) SetBurst(burstBytes int64) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if burstBytes <= 0 {
		burstBytes = 64 * 1024
	}
	tb.capacity = float64(burstBytes)
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
}

func (tb *TokenBucket) SetPacketGap(gap time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.packetGap = gap
}

func (tb *TokenBucket) Rate() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.rate
}

func (tb *TokenBucket) Burst() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return int64(tb.capacity)
}

func (tb *TokenBucket) PacketGap() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.packetGap
}

func (tb *TokenBucket) IsUnlimited() bool {
	return tb.isUnlimited.Load()
}

func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	if elapsed > 0 {
		tb.tokens = math.Min(tb.capacity, tb.tokens+elapsed*tb.rate)
		tb.lastRefill = now
	}
}

// sleepContext executes a non-allocating timer sleep with immediate context cancellation.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
