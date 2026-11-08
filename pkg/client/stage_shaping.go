package client

import (
	"context"
	"math"
	"time"

	"github.com/shehzade/contraband/pkg/client/traffic"
	"github.com/shehzade/contraband/pkg/common"
)

func runStage3Shaping(ctx context.Context, cfg ClientConfig, logger common.Logger) (*traffic.TokenBucket, *traffic.CadenceEngine) {
	rateBytes, _ := common.ParseBandwidthRate(cfg.Throughput)
	chunkSizeBytes, _ := common.ParseBytes(cfg.ChunkSize)
	if chunkSizeBytes <= 0 {
		chunkSizeBytes = common.DefaultChunkSize
	}
	burstBytes := int64(math.Max(4*1024*1024, float64(chunkSizeBytes)*2))
	shaper := traffic.NewTokenBucket(rateBytes, burstBytes, 0)

	minDur, _ := common.ParseDuration(cfg.IntervalMin)
	if minDur <= 0 {
		minDur = 500 * time.Millisecond
	}
	maxDur, _ := common.ParseDuration(cfg.IntervalMax)
	if maxDur <= 0 {
		maxDur = 4 * time.Second
	}
	cadenceEngine, _ := traffic.NewCadenceEngine(cfg.Cadence, minDur, maxDur, 0.2, traffic.DistributionUniform)

	return shaper, cadenceEngine
}
