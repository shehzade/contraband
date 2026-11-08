package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/report"
	"github.com/shehzade/contraband/pkg/server/live"
)

// runStage7Reporting synthesizes assessment probe results into a standardized AssessmentReport,
// prints the headless ANSI summary table, writes file outputs, and syncs to a live dashboard if configured.
func runStage7Reporting(
	ctx context.Context,
	cfg ClientConfig,
	logger common.Logger,
	allProbes []common.ProbeResult,
	startTime time.Time,
) (*report.AssessmentReport, error) {
	duration := time.Since(startTime)
	rep := report.NewAssessmentReport(cfg.Server, allProbes, nil, nil, duration)

	// Format latency strictly in milliseconds
	logger.Info(fmt.Sprintf("Stage 7 Complete: EEI Score = %.2f%% (%s Posture) [Duration: %.2fms]",
		rep.Summary.EEIScore, rep.Summary.Posture, rep.Summary.TotalDurationMS))

	// Headless terminal ANSI summary output (stdout)
	if !cfg.JSON {
		printHeadlessTerminalSummary(rep, cfg.NoColor)
	}

	// Export files if requested
	var rawJSON, rawHTML, rawSARIF, remediationScript []byte

	if cfg.OutputJSON != "" {
		jsonData, err := report.ExportJSON(rep)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to generate JSON report: %v", err))
		} else {
			rawJSON = jsonData
			if err := os.WriteFile(cfg.OutputJSON, jsonData, 0644); err != nil {
				logger.Error(fmt.Sprintf("Failed to write JSON output to %s: %v", cfg.OutputJSON, err))
			} else {
				logger.Info(fmt.Sprintf("Exported JSON report to %s", cfg.OutputJSON))
			}
		}
	}

	if cfg.OutputHTML != "" {
		htmlContent, err := report.GenerateHTML(rep)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to generate HTML report: %v", err))
		} else {
			rawHTML = []byte(htmlContent)
			if err := os.WriteFile(cfg.OutputHTML, rawHTML, 0644); err != nil {
				logger.Error(fmt.Sprintf("Failed to write HTML report to %s: %v", cfg.OutputHTML, err))
			} else {
				logger.Info(fmt.Sprintf("Exported interactive HTML report to %s", cfg.OutputHTML))
			}
		}
	}

	if cfg.OutputSARIF != "" {
		sarifData, err := report.ExportSARIF(rep)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to generate SARIF report: %v", err))
		} else {
			rawSARIF = sarifData
			if err := os.WriteFile(cfg.OutputSARIF, sarifData, 0644); err != nil {
				logger.Error(fmt.Sprintf("Failed to write SARIF output to %s: %v", cfg.OutputSARIF, err))
			} else {
				logger.Info(fmt.Sprintf("Exported SARIF report to %s", cfg.OutputSARIF))
			}
		}
	}

	// Prepare remediation script
	remediationSet := report.GenerateRemediation(allProbes, cfg.Server)
	if remediationSet != nil {
		remediationScript = []byte(remediationSet.FormatAll())
	}

	// Dashboard Synchronization (--sync-report)
	if cfg.SyncReport != "" {
		// Ensure HTML, JSON, SARIF payloads are populated for upload even if not written to disk
		if len(rawJSON) == 0 {
			rawJSON, _ = report.ExportJSON(rep)
		}
		if len(rawHTML) == 0 {
			htmlContent, _ := report.GenerateHTML(rep)
			rawHTML = []byte(htmlContent)
		}
		if len(rawSARIF) == 0 {
			rawSARIF, _ = report.ExportSARIF(rep)
		}

		err := syncReportToDashboard(ctx, cfg.SyncReport, cfg.Zone, rep, rawHTML, rawJSON, rawSARIF, remediationScript, logger)
		if err != nil {
			logger.Warn(fmt.Sprintf("Failed to sync report to dashboard (%s): %v", cfg.SyncReport, err))
		}
	}

	return rep, nil
}

// syncReportToDashboard transmits report artifacts to the contraband live command center server.
func syncReportToDashboard(
	ctx context.Context,
	dashboardURL string,
	zone string,
	rep *report.AssessmentReport,
	rawHTML, rawJSON, rawSARIF, remediation []byte,
	logger common.Logger,
) error {
	baseURL := strings.TrimRight(dashboardURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	targetURL := baseURL + "/api/v1/reports"

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "contraband-client"
	}
	if zone == "" {
		zone = "corporate-default"
	}

	payload := live.UploadReportPayload{
		Report:      rep,
		RawHTML:     string(rawHTML),
		RawJSON:     string(rawJSON),
		RawSARIF:    string(rawSARIF),
		Remediation: string(remediation),
		NetworkZone: zone,
		ClientHost:  hostname,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode upload payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create upload request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)

	logger.Success(fmt.Sprintf("Report synchronized to dashboard at %s (Report ID: %s, View: %s/reports)",
		baseURL, rep.ID, baseURL))
	return nil
}

// printHeadlessTerminalSummary renders a rich ANSI terminal dashboard to stdout for headless environments.
func printHeadlessTerminalSummary(rep *report.AssessmentReport, noColor bool) {
	// Colors
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"
	cyan := "\033[36m"
	boldCyan := "\033[1;36m"
	green := "\033[32m"
	boldGreen := "\033[1;32m"
	yellow := "\033[33m"
	boldYellow := "\033[1;33m"
	red := "\033[31m"
	boldRed := "\033[1;31m"

	if noColor {
		reset = ""
		bold = ""
		dim = ""
		cyan = ""
		boldCyan = ""
		green = ""
		boldGreen = ""
		yellow = ""
		boldYellow = ""
		red = ""
		boldRed = ""
	}

	// Posture color mapping
	postureColor := boldGreen
	switch strings.ToLower(string(rep.Summary.Posture)) {
	case "critical":
		postureColor = boldRed
	case "high":
		postureColor = red
	case "medium":
		postureColor = boldYellow
	case "low":
		postureColor = yellow
	default:
		postureColor = boldGreen
	}

	divider := strings.Repeat("═", 82)
	thinDivider := strings.Repeat("─", 82)

	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", boldCyan, divider, reset)
	fmt.Fprintf(os.Stdout, "%s %sCONTRABAND%s %s:: EGRESS POSTURE ASSESSMENT COMMAND CENTER%s\n",
		boldCyan, bold, reset, dim, reset)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", boldCyan, divider, reset)

	fmt.Fprintf(os.Stdout, " Target Server     : %s%-30s%s Generated At    : %s\n",
		bold, rep.TargetHost, reset, rep.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(os.Stdout, " Assessment ID     : %s%-30s%s Total Duration  : %s%.2fms%s\n",
		dim, rep.ID, reset, boldCyan, rep.Summary.TotalDurationMS, reset)
	fmt.Fprintf(os.Stdout, " Total Probes      : %s%-30d%s Total Data Sent : %s%s%s\n",
		bold, rep.Summary.TotalProbes, reset, cyan, common.FormatBytes(rep.Summary.TotalBytesSent), reset)
	fmt.Fprintf(os.Stdout, " Success / Egress  : %s%-30d%s Blocked L4 / L7 : %s%d / %d%s\n",
		boldGreen, rep.Summary.SuccessCount, reset, yellow, rep.Summary.BlockedL4, rep.Summary.BlockedL7, reset)

	fmt.Fprintf(os.Stdout, "\n %sEGRESS EXPOSURE INDEX (EEI)%s: %s%6.2f%%%s  [%s%s%s]\n",
		bold, reset, postureColor, rep.Summary.EEIScore, reset, postureColor, strings.ToUpper(string(rep.Summary.Posture)), reset)
	fmt.Fprintf(os.Stdout, " [Port Subscore: %.2f | Protocol Subscore: %.2f | DLP Subscore: %.2f]\n",
		rep.Summary.Sport, rep.Summary.Sproto, rep.Summary.Sdlp)

	// L7 Smuggling & Exfiltration Matrix
	fmt.Fprintf(os.Stdout, "\n%s%s%s\n", dim, thinDivider, reset)
	fmt.Fprintf(os.Stdout, "%s %-16s %-8s %-12s %-12s %-16s %-12s%s\n",
		bold, "PROTOCOL", "PORT", "VERDICT", "LATENCY", "BYTES SENT", "DETAILS", reset)
	fmt.Fprintf(os.Stdout, "%s%s%s\n", dim, thinDivider, reset)

	var exfilProbes []common.ProbeResult
	var openPorts []int
	seenPorts := make(map[int]bool)

	for _, p := range rep.Probes {
		if p.Stage == "exfil" {
			exfilProbes = append(exfilProbes, p)
		} else if p.Stage == "sweep" && p.Verdict == common.VerdictSuccess {
			if !seenPorts[p.TargetPort] {
				seenPorts[p.TargetPort] = true
				openPorts = append(openPorts, p.TargetPort)
			}
		}
	}

	sort.Slice(exfilProbes, func(i, j int) bool {
		return exfilProbes[i].Protocol < exfilProbes[j].Protocol
	})

	for _, p := range exfilProbes {
		verdictColor := green
		switch p.Verdict {
		case common.VerdictSuccess:
			verdictColor = boldGreen
		case common.VerdictBlockedL4, common.VerdictBlockedL7, common.VerdictBlockedDLP:
			verdictColor = boldRed
		default:
			verdictColor = yellow
		}

		latMs := float64(p.Timestamps.TotalDuration.Microseconds()) / 1000.0
		if latMs <= 0 && p.Timestamps.TCPDuration > 0 {
			latMs = float64(p.Timestamps.TCPDuration.Microseconds()) / 1000.0
		}

		details := ""
		if p.Verdict != common.VerdictSuccess && p.ErrorMessage != "" {
			details = p.ErrorMessage
			if len(details) > 20 {
				details = details[:17] + "..."
			}
		} else if p.Verdict == common.VerdictSuccess {
			details = "Smuggled"
		}

		fmt.Fprintf(os.Stdout, " %-16s %-8d %s%-12s%s %8.2fms   %-16s %s%-12s%s\n",
			p.Protocol,
			p.TargetPort,
			verdictColor, p.Verdict, reset,
			latMs,
			common.FormatBytes(p.BytesSent),
			dim, details, reset,
		)
	}

	if len(openPorts) > 0 {
		sort.Ints(openPorts)
		var portStrs []string
		for _, pt := range openPorts {
			portStrs = append(portStrs, fmt.Sprintf("%d", pt))
		}
		fmt.Fprintf(os.Stdout, "\n %sOpen Egress Ports (%d)%s: %s%s%s\n",
			bold, len(openPorts), reset, boldGreen, strings.Join(portStrs, ", "), reset)
	}

	// Security Findings
	if len(rep.Findings) > 0 {
		fmt.Fprintf(os.Stdout, "\n%s%s%s\n", dim, thinDivider, reset)
		fmt.Fprintf(os.Stdout, "%s KEY SECURITY FINDINGS (%d)%s\n", boldRed, len(rep.Findings), reset)
		for i, f := range rep.Findings {
			if i >= 5 {
				fmt.Fprintf(os.Stdout, "  %s... and %d more findings (see report for full details)%s\n",
					dim, len(rep.Findings)-5, reset)
				break
			}
			lvlColor := yellow
			if f.Level == "critical" || f.Level == "high" {
				lvlColor = boldRed
			}
			fmt.Fprintf(os.Stdout, "  [%s%-8s%s] %s%s%s: %s\n",
				lvlColor, strings.ToUpper(f.Level), reset, bold, f.RuleID, reset, f.Message)
		}
	}

	fmt.Fprintf(os.Stdout, "%s%s%s\n\n", boldCyan, divider, reset)
}
