package traffic

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// DistributionType identifies probability distribution for jitter calculations.
type DistributionType string

const (
	DistributionUniform  DistributionType = "uniform"
	DistributionGaussian DistributionType = "gaussian"
)

// CadenceEngine generates delays and schedules pacing between chunks, probes, or sweeps.
type CadenceEngine struct {
	mu           sync.Mutex
	profile      string           // burst, steady, jittered, office-hours, low-and-slow
	intervalMin  time.Duration    // Minimum interval boundary
	intervalMax  time.Duration    // Maximum interval boundary
	jitterFactor float64          // 0.0 to 1.0 (or percentage 0 to 100)
	distribution DistributionType // uniform or gaussian
	packetGap    time.Duration    // Microsecond packet gap

	// Office-hours state machine
	burstCounter   int // Current consecutive chunk count
	burstThreshold int // Chunks before next idle pause (e.g. 5–15)
	inOfficeIdle   bool
}

// NewCadenceEngine initializes a CadenceEngine with given parameters.
func NewCadenceEngine(profile string, minDur, maxDur time.Duration, jitter float64, dist DistributionType) (*CadenceEngine, error) {
	if profile == "" {
		profile = common.CadenceSteady
	}

	// Normalize jitter factor
	if jitter > 1.0 {
		jitter = jitter / 100.0
	}
	if jitter < 0.0 {
		jitter = 0.0
	} else if jitter > 1.0 {
		jitter = 1.0
	}

	if minDur < 0 {
		minDur = 0
	}
	if maxDur < 0 {
		maxDur = 0
	}
	if maxDur > 0 && minDur > maxDur {
		return nil, fmt.Errorf("interval_min (%v) cannot be greater than interval_max (%v)", minDur, maxDur)
	}

	if dist == "" {
		dist = DistributionGaussian
	}

	return &CadenceEngine{
		profile:        profile,
		intervalMin:    minDur,
		intervalMax:    maxDur,
		jitterFactor:   jitter,
		distribution:   dist,
		burstThreshold: 8,
	}, nil
}

// NextDelay calculates the next pacing delay according to the configured cadence profile.
func (c *CadenceEngine) NextDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	switch c.profile {
	case common.CadenceBurst:
		return 0

	case common.CadenceSteady:
		return c.intervalMin

	case common.CadenceJittered:
		return c.sampleInterval(c.intervalMin, c.intervalMax)

	case common.CadenceOfficeHours:
		c.burstCounter++
		if c.burstCounter >= c.burstThreshold {
			// Trigger realistic user idle think time (10s to 60s)
			c.burstCounter = 0
			c.burstThreshold = 5 + int(c.randFloat64()*10.0) // 5 to 14 chunks
			idleMin := 10 * time.Second
			idleMax := 60 * time.Second
			return c.sampleInterval(idleMin, idleMax)
		}
		// Active work interval: short inter-packet delay (50ms to 200ms)
		return c.sampleInterval(50*time.Millisecond, 200*time.Millisecond)

	case common.CadenceLowAndSlow:
		// Enforce long drip delays (e.g. 30s to 120s if not specified)
		minD := c.intervalMin
		maxD := c.intervalMax
		if minD == 0 && maxD == 0 {
			minD = 30 * time.Second
			maxD = 120 * time.Second
		}
		return c.sampleInterval(minD, maxD)

	default:
		return c.intervalMin
	}
}

// sampleInterval calculates a random delay between min and max using configured distribution.
func (c *CadenceEngine) sampleInterval(minD, maxD time.Duration) time.Duration {
	if minD == maxD || maxD == 0 {
		if c.jitterFactor > 0 {
			// Apply jitter factor around base interval: [base*(1-J), base*(1+J)]
			base := float64(minD)
			halfRange := base * c.jitterFactor
			low := math.Max(0, base-halfRange)
			high := base + halfRange
			return time.Duration(low + c.randFloat64()*(high-low))
		}
		return minD
	}

	if c.distribution == DistributionUniform {
		delta := float64(maxD - minD)
		return minD + time.Duration(c.randFloat64()*delta)
	}

	// Gaussian distribution: Box-Muller transform
	// Midpoint mu, standard deviation sigma = (max - min) / 6
	mu := float64(minD+maxD) / 2.0
	sigma := float64(maxD-minD) / 6.0

	// Box-Muller transform
	u1 := c.randFloat64()
	if u1 <= 0.0 {
		u1 = 1e-9
	}
	u2 := c.randFloat64()
	z0 := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)

	sampled := mu + z0*sigma
	// Clamp to [minD, maxD]
	clamped := math.Max(float64(minD), math.Min(float64(maxD), sampled))
	return time.Duration(clamped)
}

// randFloat64 generates a cryptographically secure pseudo-random float in [0.0, 1.0).
func (c *CadenceEngine) randFloat64() float64 {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to nanosecond epoch
		return float64(time.Now().UnixNano()%1000000) / 1000000.0
	}
	val := binary.BigEndian.Uint64(buf[:])
	return float64(val>>11) / float64(1<<53)
}

// Sleep calculates NextDelay and blocks with context cancellation.
func (c *CadenceEngine) Sleep(ctx context.Context) error {
	d := c.NextDelay()
	return sleepContext(ctx, d)
}

// SleepDuration executes context-aware sleep for an explicit duration.
func (c *CadenceEngine) SleepDuration(ctx context.Context, d time.Duration) error {
	return sleepContext(ctx, d)
}
