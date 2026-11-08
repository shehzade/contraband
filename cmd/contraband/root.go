package main

import (
	"fmt"
	"math/rand"
	"os"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/spf13/cobra"
)

var (
	flagConfig  string
	flagVerbose bool
	flagJSON    bool
	flagSeed    int64
	flagDryRun  bool

	loadedConfig *common.ProfileConfig
	appLogger    common.Logger
)

var rootCmd = &cobra.Command{
	Use:   "contraband",
	Short: "Contraband: Standalone Egress Assessment & Data Smuggling Framework",
	Long: `Contraband is a production-grade, single-binary Go framework for automated
network egress assessment, multi-protocol data smuggling, corporate proxy traversal,
synthetic DLP verification, and forensic reporting.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize terminal or JSON logger
		appLogger = common.GetLogger()
		if flagJSON {
			appLogger.SetMode(common.LogModeJSON)
		}
		if flagVerbose {
			appLogger.SetLevel(common.LogLevelDebug)
		}

		// Initialize deterministic PRNG if seed is provided
		if flagSeed != 0 {
			rand.Seed(flagSeed)
			appLogger.Debug(fmt.Sprintf("Initialized deterministic random seed: %d", flagSeed))
		}

		// Load optional configuration profile
		if flagConfig != "" {
			cfg, err := common.LoadProfileConfig(flagConfig)
			if err != nil {
				return fmt.Errorf("failed to load configuration profile: %w", err)
			}
			loadedConfig = cfg
			appLogger.Debug(fmt.Sprintf("Loaded configuration profile from %s", flagConfig))
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&flagConfig, "config", "c", "", "Path to YAML/JSON configuration profile")
	rootCmd.PersistentFlags().BoolVarP(&flagVerbose, "verbose", "v", false, "Enable verbose debug logging")
	rootCmd.PersistentFlags().BoolVar(&flagJSON, "json", false, "Output results in structured JSON format")
	rootCmd.PersistentFlags().Int64Var(&flagSeed, "seed", 0, "Deterministic random seed for reproducible runs (0 = random)")
	rootCmd.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "Pre-flight check: validate configuration and reachability without emitting live test traffic")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
