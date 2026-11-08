package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/shehzade/contraband/pkg/client/dlp"
	"github.com/shehzade/contraband/pkg/common"
)

type stage4Result struct {
	TargetBytes   int64
	EffectiveSeed int64
	ExpectedHash  string
	DLPConfig     dlp.GeneratorConfig
}

func runStage4DLP(ctx context.Context, cfg *ClientConfig, logger common.Logger) (*stage4Result, error) {
	targetBytes, err := common.ParseBytes(cfg.Size)
	if err != nil || targetBytes <= 0 {
		targetBytes = 1024 * 1024 // 1MB default
	}

	effectiveSeed := cfg.Seed
	if effectiveSeed == 0 {
		effectiveSeed = time.Now().UnixNano()
		cfg.Seed = effectiveSeed
	}

	dlpConfig := dlp.GeneratorConfig{
		DLPType:     cfg.DLPPayloads,
		CarrierType: cfg.CarrierType,
		Seed:        effectiveSeed,
	}

	// Streaming Invariant:
	// Compute pre-flight rolling SHA-256 with bounded 64KB buffer (<200KB heap)
	hasher := sha256.New()
	preStreamer := dlp.NewDLPStreamer(targetBytes, dlpConfig)
	copyBuf := make([]byte, 64*1024)
	if _, err := io.CopyBuffer(hasher, preStreamer, copyBuf); err != nil {
		preStreamer.Close()
		return nil, fmt.Errorf("failed to compute pre-flight payload hash: %w", err)
	}
	preStreamer.Close()
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	logger.Info(fmt.Sprintf("Stage 4 Complete: Synthesized %d bytes of DLP payload (type: %s, sha256: %s)",
		targetBytes, cfg.DLPPayloads, expectedHash[:12]+"..."))

	return &stage4Result{
		TargetBytes:   targetBytes,
		EffectiveSeed: effectiveSeed,
		ExpectedHash:  expectedHash,
		DLPConfig:     dlpConfig,
	}, nil
}
