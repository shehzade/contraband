package sweep

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

// TokenBucket implements a pure Go thread-safe token bucket rate limiter.
type TokenBucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	rate       float64 // tokens per second
	lastRefill time.Time
}

// NewTokenBucket creates a token bucket with capacity and refill rate in tokens/sec.
func NewTokenBucket(rate, capacity int) *TokenBucket {
	if rate < 1 {
		rate = 1
	}
	if capacity < 1 {
		capacity = 1
	}
	now := time.Now()
	return &TokenBucket{
		capacity:   float64(capacity),
		tokens:     float64(capacity),
		rate:       float64(rate),
		lastRefill: now,
	}
}

// Wait blocks until a token is available or ctx is canceled.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		tb.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(tb.lastRefill).Seconds()
		if elapsed > 0 {
			tb.tokens += elapsed * tb.rate
			if tb.tokens > tb.capacity {
				tb.tokens = tb.capacity
			}
			tb.lastRefill = now
		}

		if tb.tokens >= 1.0 {
			tb.tokens -= 1.0
			tb.mu.Unlock()
			return nil
		}

		// Calculate sleep time until 1 token is available
		missing := 1.0 - tb.tokens
		sleepSec := missing / tb.rate
		sleepDur := time.Duration(sleepSec * float64(time.Second))
		if sleepDur < time.Microsecond {
			sleepDur = time.Microsecond
		}
		tb.mu.Unlock()

		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// ApplyJitter sleeps for a random duration between min and max, respecting ctx.
func ApplyJitter(ctx context.Context, min, max time.Duration) error {
	if max <= 0 || min >= max {
		if min > 0 {
			timer := time.NewTimer(min)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return ctx.Err()
			case <-timer.C:
				return nil
			}
		}
		return nil
	}

	diff := max - min
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	var jitterDur time.Duration
	if err == nil {
		jitterDur = min + time.Duration(n.Int64())
	} else {
		jitterDur = min
	}

	timer := time.NewTimer(jitterDur)
	select {
	case <-ctx.Done():
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
