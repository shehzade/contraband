package client

import (
	"strings"

	"github.com/shehzade/contraband/pkg/client/evasion"
)

func runStage5Evasion(cfg ClientConfig, effectiveSeed int64) (*evasion.Pipeline, bool) {
	pipeCfg := evasion.PipelineConfig{
		Carrier:    evasion.CarrierType(cfg.Stego),
		Passphrase: cfg.Passphrase,
		Seed:       effectiveSeed,
		Transforms: cfg.Transforms,
	}
	if strings.Contains(cfg.Transforms, "zstd") {
		pipeCfg.Compression = evasion.CompressZstd
	} else if strings.Contains(cfg.Transforms, "gzip") {
		pipeCfg.Compression = evasion.CompressGzip
	} else if strings.Contains(cfg.Transforms, "zlib") {
		pipeCfg.Compression = evasion.CompressZlib
	}
	if strings.Contains(cfg.Transforms, "aes") || cfg.Passphrase != "" {
		pipeCfg.Encrypt = true
	}

	pipeline, pipeErr := evasion.NewPipeline(pipeCfg)
	hasEvasion := pipeErr == nil && pipeline != nil && (pipeCfg.Compression != evasion.CompressNone || pipeCfg.Encrypt || pipeCfg.Carrier != "" || (pipeCfg.Transforms != "" && pipeCfg.Transforms != "raw" && pipeCfg.Transforms != "none"))
	return pipeline, hasEvasion
}
