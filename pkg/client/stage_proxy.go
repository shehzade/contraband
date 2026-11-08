package client

import (
	"context"
	"fmt"
	"time"

	"github.com/shehzade/contraband/pkg/client/proxy"
	"github.com/shehzade/contraband/pkg/common"
)

func runStage2Proxy(ctx context.Context, cfg ClientConfig, logger common.Logger) *proxy.FallbackEngine {
	logger.Info(fmt.Sprintf("Stage 2: Evaluating proxy traversal path (mode: %s, auth: %s)", cfg.Proxy, cfg.ProxyAuth))
	proxyOpts := proxy.Options{
		Mode:     cfg.Proxy,
		AuthType: proxy.AuthType(cfg.ProxyAuth),
		Timeout:  10 * time.Second,
		Logger:   logger,
	}
	return proxy.NewFallbackEngine(proxyOpts)
}
