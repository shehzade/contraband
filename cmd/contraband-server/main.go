package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/dryrun"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/listeners"
	"github.com/shehzade/contraband/pkg/server/multiplexer"
	"github.com/spf13/cobra"
)

var (
	flagConfig  string
	flagVerbose bool
	flagJSON    bool
	flagSeed    int64
	flagDryRun  bool

	serverBind        string
	serverDomain      string
	serverPorts       string
	serverProtocols   string
	serverSMBMode     string
	serverCert        string
	serverKey         string
	serverEnableEBPF  bool
	serverDB          string
	serverSavePayload bool
	serverEvidenceDir string
	serverTCP         bool
	serverUDP         bool
	serverBanner      string
	serverPortAlias   string
	serverDashboard   string

	loadedConfig *common.ProfileConfig
	appLogger    common.Logger
)

var rootCmd = &cobra.Command{
	Use:   "contraband-server",
	Short: "Contraband Standalone Reflection Server & Session Ledger",
	Long: `Dedicated standalone server binary for multi-port reflection,
multi-protocol listener coordination, and session ledger reassembly.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		appLogger = common.GetLogger()
		if flagJSON {
			appLogger.SetMode(common.LogModeJSON)
		}
		if flagVerbose {
			appLogger.SetLevel(common.LogLevelDebug)
		}
		if flagSeed != 0 {
			rand.Seed(flagSeed)
			appLogger.Debug(fmt.Sprintf("Initialized deterministic random seed: %d", flagSeed))
		}
		if flagConfig != "" {
			cfg, err := common.LoadProfileConfig(flagConfig)
			if err != nil {
				return fmt.Errorf("failed to load configuration profile: %w", err)
			}
			loadedConfig = cfg
		}
		return nil
	},
	RunE: runServerStandalone,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "Path to YAML/JSON configuration profile")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose debug logging")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output results in structured JSON format")
	rootCmd.PersistentFlags().Int64Var(&flagSeed, "seed", 0, "Deterministic random seed for reproducible runs")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "Pre-flight validation without transmitting live network traffic")

	rootCmd.Flags().StringVarP(&serverBind, "bind", "b", "0.0.0.0", "Server IP interface to bind listeners")
	rootCmd.Flags().StringVarP(&serverDomain, "domain", "d", "contraband.example.com", "Authoritative domain for DNS tunneling reassembly")
	rootCmd.Flags().StringVarP(&serverPorts, "ports", "p", "quick", "Port matrix for multiplexer: 'quick', 'standard', or ranges")
	rootCmd.Flags().StringVar(&serverPortAlias, "port", "", "Alias for --ports")
	rootCmd.Flags().StringVar(&serverProtocols, "protocols", "all", "Server protocol listeners to activate ('all', 'web', 'dns', etc.)")
	rootCmd.Flags().StringVar(&serverSMBMode, "smb-mode", "hash-capture", "SMB server operational mode: 'hash-capture' or 'file-transfer'")
	rootCmd.Flags().StringVar(&serverCert, "cert", "", "Custom TLS certificate path (auto-generates dynamic CA if omitted)")
	rootCmd.Flags().StringVar(&serverKey, "key", "", "Custom TLS private key path")
	rootCmd.Flags().BoolVar(&serverEnableEBPF, "enable-ebpf", false, "Enable Linux eBPF/nftables full-spectrum port redirection (requires root)")
	rootCmd.Flags().StringVar(&serverDB, "db", ":memory:", "SQLite database path for session ledger (:memory: for in-memory)")
	rootCmd.Flags().BoolVar(&serverSavePayload, "save-payload", false, "Physically reconstruct and save received payload files to disk")
	rootCmd.Flags().StringVar(&serverEvidenceDir, "evidence-dir", "evidence", "Destination directory for physical session payloads")
	rootCmd.Flags().BoolVar(&serverTCP, "tcp", true, "Enable TCP reflection in port multiplexer")
	rootCmd.Flags().BoolVar(&serverUDP, "udp", true, "Enable UDP reflection in port multiplexer")
	rootCmd.Flags().StringVar(&serverBanner, "banner", "", "Custom JSON reflection banner format string")
	rootCmd.Flags().StringVar(&serverDashboard, "dashboard", "", "Address to bind live command center dashboard and report server (e.g. :8080)")
	rootCmd.Flags().StringVar(&serverDashboard, "live-dashboard", "", "Alias for --dashboard")

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print server version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Contraband Server v%s (Pure Go, CGO_ENABLED=0)\n", common.Version)
		},
	})
}

func runServerStandalone(cmd *cobra.Command, args []string) error {
	if serverPortAlias != "" && (serverPorts == "quick" || serverPorts == "") {
		serverPorts = serverPortAlias
	}

	cfg := server.DefaultServerConfig()
	cfg.BindIP = serverBind
	cfg.Domain = serverDomain
	cfg.Ports = serverPorts
	cfg.Protocols = serverProtocols
	cfg.SMBMode = serverSMBMode
	cfg.CertPath = serverCert
	cfg.KeyPath = serverKey
	cfg.EnableEBPF = serverEnableEBPF
	cfg.DBPath = serverDB
	cfg.SavePayload = serverSavePayload
	cfg.EvidenceDir = serverEvidenceDir
	cfg.DashboardAddr = serverDashboard
	cfg.EnableTCP = serverTCP
	cfg.EnableUDP = serverUDP
	cfg.Banner = serverBanner

	if flagDryRun {
		return dryrun.RunServerDryRun(cfg)
	}

	engine, err := server.NewServerEngine(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize server engine: %w", err)
	}

	requestedPorts, err := common.ParsePortsField(cfg.Ports)
	if err != nil {
		return fmt.Errorf("invalid ports specification %q: %w", cfg.Ports, err)
	}

	registry := listeners.NewListenerRegistry(appLogger)
	logger := common.GetLogger()
	tlsConfig := engine.GetTLSConfig()
	sshHostKey := engine.GetSSHHostKey()

	protoLower := strings.ToLower(cfg.Protocols)
	isCustomPorts := cfg.Ports != "quick" && cfg.Ports != "standard" && cfg.Ports != "full"

	dashPort := 0
	if cfg.DashboardAddr != "" {
		parts := strings.Split(cfg.DashboardAddr, ":")
		if len(parts) > 1 {
			if dp, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				dashPort = dp
			}
		}
	}

	if protoLower != "none" && protoLower != "reflector" {
		if isCustomPorts {
			hasPort := func(target int) bool {
				for _, p := range requestedPorts {
					if p == target {
						return true
					}
				}
				return false
			}
			if protoLower == "all" || strings.Contains(protoLower, "web") || strings.Contains(protoLower, "http") {
				var webPorts []int
				for _, p := range requestedPorts {
					if (p == 8443 || p == 9443 || p == 10443 || p == 80 || p == 443 || p == 8080) && p != dashPort {
						webPorts = append(webPorts, p)
					}
				}
				if len(webPorts) > 0 {
					_ = registry.Register(listeners.NewHTTPServerListener(cfg.BindIP, webPorts, webPorts[0], tlsConfig))
				}
			}
			if (protoLower == "all" || strings.Contains(protoLower, "dns")) && hasPort(53) {
				_ = registry.Register(listeners.NewDNSServerListener(cfg.BindIP, 53, 53, 853, 8443, tlsConfig))
			}
		} else {
			defaultWebPorts := []int{80, 443, 8080}
			if dashPort > 0 {
				var filtered []int
				for _, p := range defaultWebPorts {
					if p != dashPort {
						filtered = append(filtered, p)
					}
				}
				defaultWebPorts = filtered
			}

			dohPort := 8443
			for _, p := range defaultWebPorts {
				if p == dohPort {
					dohPort = 8444
					break
				}
			}

			if err := registry.Register(listeners.NewHTTPServerListener(cfg.BindIP, defaultWebPorts, 443, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register HTTPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewGRPCServerListener(cfg.BindIP, []int{50051}, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register GRPCServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewDNSServerListener(cfg.BindIP, 53, 53, 853, dohPort, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register DNSServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewFTPServerListener(cfg.BindIP, 21, 990, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register FTPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewSFTPServerListener(cfg.BindIP, 22, sshHostKey)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register SFTPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewSMTPServerListener(cfg.BindIP, 25, 465, 587, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register SMTPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewSMBServerListener(cfg.BindIP, 445, cfg.SMBMode)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register SMBServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewSMBQUICServerListener(cfg.BindIP, 4430, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register SMBQUICServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewICMPServerListener(cfg.BindIP)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register ICMPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewNTPServerListener(cfg.BindIP, 123)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register NTPServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewSyslogServerListener(cfg.BindIP, 514, 5140, 6514, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register SyslogServerListener: %v", err))
			}
			if err := registry.Register(listeners.NewMQTTServerListener(cfg.BindIP, 1883, 8883, tlsConfig)); err != nil {
				logger.Warn(fmt.Sprintf("Failed to register MQTTServerListener: %v", err))
			}
		}
	}

	for _, l := range registry.GetAllListeners() {
		engine.RegisterListener(l)
	}

	multiplexPorts := registry.FilterMultiplexPorts(requestedPorts)
	if len(multiplexPorts) > 0 {
		portStrList := make([]string, len(multiplexPorts))
		for i, p := range multiplexPorts {
			portStrList[i] = fmt.Sprintf("%d", p)
		}
		muxPorts := strings.Join(portStrList, ",")

		muxCfg := multiplexer.MultiplexerConfig{
			BindIP:        cfg.BindIP,
			Ports:         muxPorts,
			EnableTCP:     cfg.EnableTCP,
			EnableUDP:     cfg.EnableUDP,
			EnableEBPF:    cfg.EnableEBPF,
			PeekTimeout:   cfg.PeekTimeout,
			SocketTimeout: cfg.SocketTimeout,
		}
		mux, err := multiplexer.NewUserspaceMultiplexer(muxCfg, engine.GetLedger(), appLogger)
		if err != nil {
			return fmt.Errorf("failed to create userspace multiplexer: %w", err)
		}
		engine.SetMultiplexer(mux)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigChan
		appLogger.Info("Shutdown signal received, gracefully terminating server...")
		cancel()
	}()

	if err := engine.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	<-ctx.Done()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	return engine.Shutdown(shutdownCtx)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
