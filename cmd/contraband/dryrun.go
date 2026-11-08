package main

import (
	"time"

	"github.com/shehzade/contraband/pkg/client"
	"github.com/shehzade/contraband/pkg/dryrun"
	"github.com/shehzade/contraband/pkg/server"
)

// RunSweepDryRun forwards to dryrun.RunSweepDryRun for backward compatibility
func RunSweepDryRun(target string, ports []int, protocol string, rate int, concurrency int, timeout time.Duration) error {
	return dryrun.RunSweepDryRun(target, ports, protocol, rate, concurrency, timeout)
}

// RunListenDryRun forwards to dryrun.RunListenDryRun for backward compatibility
func RunListenDryRun(bindIP string, ports []int, enableTCP bool, enableUDP bool) error {
	return dryrun.RunListenDryRun(bindIP, ports, enableTCP, enableUDP)
}

// RunGenerateDryRun forwards to dryrun.RunGenerateDryRun for backward compatibility
func RunGenerateDryRun(dlpType string, size int64, carrier string, outputPath string, compress string, encrypt string) error {
	return dryrun.RunGenerateDryRun(dlpType, size, carrier, outputPath, compress, encrypt)
}

// RunClientDryRun forwards to dryrun.RunClientDryRun for backward compatibility
func RunClientDryRun(cfg client.ClientConfig) error {
	return dryrun.RunClientDryRun(cfg)
}

// RunServerDryRun forwards to dryrun.RunServerDryRun for backward compatibility
func RunServerDryRun(cfg server.ServerConfig) error {
	return dryrun.RunServerDryRun(cfg)
}
