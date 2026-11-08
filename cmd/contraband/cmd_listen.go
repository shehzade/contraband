package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/multiplexer"
	"github.com/spf13/cobra"
)

var (
	listenBind   string
	listenPorts  string
	listenDB     string
	listenBanner string
	listenTCP    bool
	listenUDP    bool
	listenEBPF   bool
)

var listenCmd = &cobra.Command{
	Use: "listen",
	// Aliases: []string{"server"},
	Short: "Start multi-port reflection listener and session ledger",
	Long: `Bind multi-port reflection listeners across designated port matrices,
respond to probe handshakes with authenticated JSON banners, and reassemble incoming chunks.`,
	RunE: runListen,
}

func init() {
	listenCmd.Flags().StringVarP(&listenBind, "bind", "b", "0.0.0.0", "Bind IP address")
	listenCmd.Flags().StringVarP(&listenPorts, "ports", "p", "quick", "Ports to bind: 'quick', 'standard', or comma-separated ranges")
	listenCmd.Flags().StringVar(&listenDB, "db", ":memory:", "SQLite database path for persistent session ledger (default: :memory:)")
	listenCmd.Flags().StringVar(&listenBanner, "banner", "", "Custom reflection banner format")
	listenCmd.Flags().BoolVar(&listenTCP, "tcp", true, "Enable TCP reflection listeners")
	listenCmd.Flags().BoolVar(&listenUDP, "udp", true, "Enable UDP reflection listeners")
	listenCmd.Flags().BoolVar(&listenEBPF, "ebpf", false, "Enable optional Linux eBPF/nftables full-spectrum redirection (requires root)")

	// rootCmd.AddCommand(listenCmd) -- superseded by serverCmd in cmd_server.go
}

func runListen(cmd *cobra.Command, args []string) error {
	ports, err := common.ParsePortsField(listenPorts)
	if err != nil {
		return fmt.Errorf("invalid --ports specification: %w", err)
	}

	// Pre-Flight Dry Run Check
	if flagDryRun {
		return RunListenDryRun(listenBind, ports, listenTCP, listenUDP)
	}

	ledger, err := server.NewLedger(listenDB)
	if err != nil {
		return fmt.Errorf("failed to initialize session ledger: %w", err)
	}
	defer ledger.Close()

	cfg := multiplexer.MultiplexerConfig{
		BindIP:     listenBind,
		Ports:      listenPorts,
		EnableTCP:  listenTCP,
		EnableUDP:  listenUDP,
		EnableEBPF: listenEBPF,
	}

	mux, err := multiplexer.NewUserspaceMultiplexer(cfg, ledger, appLogger)
	if err != nil {
		return fmt.Errorf("failed to create userspace multiplexer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		appLogger.Info("Shutdown signal received, closing listeners...")
		cancel()
	}()

	appLogger.Info(fmt.Sprintf("Starting Contraband reflection listener on %s (%d ports requested)", listenBind, len(ports)))
	if err := mux.Start(ctx); err != nil {
		return fmt.Errorf("listener startup failed: %w", err)
	}

	<-ctx.Done()
	return mux.Shutdown(context.Background())
}
