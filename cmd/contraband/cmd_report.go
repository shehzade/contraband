package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/shehzade/contraband/pkg/report"
	"github.com/spf13/cobra"
)

var (
	reportInput       string
	reportOutputHTML  string
	reportOutputSARIF string
	reportOutputRules string
	reportServe       string
	reportOpen        bool
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate forensic reports, SARIF exports, firewall rules, or launch dashboard",
	Long: `Process assessment results from JSON to produce interactive Zero-CDN HTML dashboards,
OASIS SARIF v2.1.0 vulnerability reports, multi-vendor firewall remediation scripts,
or launch an embedded lightweight report server with live REST APIs.`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringVarP(&reportInput, "input", "i", "", "Path to input assessment results JSON file (required)")
	reportCmd.Flags().StringVar(&reportOutputHTML, "output-html", "", "Output path for standalone Zero-CDN HTML dashboard")
	reportCmd.Flags().StringVar(&reportOutputSARIF, "output-sarif", "", "Output path for OASIS SARIF v2.1.0 vulnerability report")
	reportCmd.Flags().StringVar(&reportOutputRules, "output-rules", "", "Output path for generated vendor firewall remediation rules")
	reportCmd.Flags().StringVar(&reportServe, "serve", "", "Host address and port for embedded report web server (e.g. ':8088')")
	reportCmd.Flags().BoolVar(&reportOpen, "open", false, "Automatically launch default desktop web browser when serving report")

	// Operator flag aliases
	reportCmd.Flags().StringVarP(&reportOutputHTML, "output", "o", "", "Alias for --output-html")
	reportCmd.Flags().StringVar(&reportOutputSARIF, "sarif", "", "Alias for --output-sarif")
	reportCmd.Flags().StringVar(&reportOutputRules, "rules", "", "Alias for --output-rules")

	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	if reportInput == "" {
		return fmt.Errorf("--input (-i) results JSON file path is required")
	}

	rep, err := report.LoadReport(reportInput)
	if err != nil {
		return fmt.Errorf("failed to load assessment report from %s: %w", reportInput, err)
	}

	// 1. Generate HTML if requested
	if reportOutputHTML != "" {
		f, err := os.Create(reportOutputHTML)
		if err != nil {
			return fmt.Errorf("failed to create HTML output file %s: %w", reportOutputHTML, err)
		}
		defer f.Close()
		if err := report.WriteHTML(f, rep); err != nil {
			return fmt.Errorf("failed to write HTML report: %w", err)
		}
		appLogger.Success(fmt.Sprintf("HTML dashboard written to %s", reportOutputHTML))
	}

	// 2. Generate SARIF if requested
	if reportOutputSARIF != "" {
		sarifBytes, err := report.ExportSARIF(rep)
		if err != nil {
			return fmt.Errorf("failed to export SARIF report: %w", err)
		}
		if err := os.WriteFile(reportOutputSARIF, sarifBytes, 0644); err != nil {
			return fmt.Errorf("failed to write SARIF output file %s: %w", reportOutputSARIF, err)
		}
		appLogger.Success(fmt.Sprintf("SARIF v2.1.0 report written to %s", reportOutputSARIF))
	}

	// 3. Generate multi-vendor firewall remediation rules if requested
	if reportOutputRules != "" {
		rules := report.GenerateRemediation(rep.Probes, rep.TargetHost)
		formatted := rules.FormatAll()
		if err := os.WriteFile(reportOutputRules, []byte(formatted), 0644); err != nil {
			return fmt.Errorf("failed to write firewall remediation rules: %w", err)
		}
		appLogger.Success(fmt.Sprintf("Firewall remediation rules written to %s", reportOutputRules))
	}

	// 4. Launch embedded HTTP mini-server if requested
	if reportServe != "" {
		opts := report.ServerOptions{
			BindAddr: reportServe,
			Report:   rep,
			AutoOpen: reportOpen,
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sigChan
			appLogger.Info("Shutdown signal received, closing report server...")
			cancel()
		}()

		appLogger.Info(fmt.Sprintf("Launching embedded report server at %s...", reportServe))
		return report.ServeReport(ctx, opts)
	}

	// If no specific output or server was requested, print summary and default to report.html
	if reportOutputHTML == "" && reportOutputSARIF == "" && reportOutputRules == "" && reportServe == "" {
		defaultHTML := "report.html"
		f, err := os.Create(defaultHTML)
		if err != nil {
			return fmt.Errorf("failed to create default HTML report: %w", err)
		}
		defer f.Close()
		if err := report.WriteHTML(f, rep); err != nil {
			return fmt.Errorf("failed to write default HTML report: %w", err)
		}
		appLogger.Success(fmt.Sprintf("Generated %s (EEI Score: %.2f%%, Posture: %s)",
			defaultHTML, rep.Summary.EEIScore, rep.Summary.Posture))
	}

	return nil
}
