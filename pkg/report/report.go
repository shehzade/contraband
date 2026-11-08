package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// AssessmentSummary aggregates high-level metrics for report headers and summaries.
type AssessmentSummary struct {
	EEIScore          float64        `json:"eei_score"`
	Posture           PostureLevel   `json:"posture"`
	PostureColor      string         `json:"posture_color"`
	Sport             float64        `json:"sport"`
	Sproto            float64        `json:"sproto"`
	Sdlp              float64        `json:"sdlp"`
	TotalProbes       int            `json:"total_probes"`
	SuccessCount      int            `json:"success_count"`
	BlockedL4         int            `json:"blocked_l4_count"`
	BlockedL7         int            `json:"blocked_l7_count"`
	BlockedDLP        int            `json:"blocked_dlp_count"`
	TotalSessions     int            `json:"total_sessions"`
	TotalCredentials  int            `json:"total_credentials"`
	VerdictCounts     map[string]int `json:"verdict_counts"`
	TotalBytesSent    int64          `json:"total_bytes_sent"`
	TotalBytesRecv    int64          `json:"total_bytes_recv"`
	TotalDurationMS   float64        `json:"total_duration_ms"`
	DurationFormatted string         `json:"duration_formatted"`
	AvgLatencyMS      float64        `json:"avg_latency_ms"`
}

// AssessmentReport is the unified container for all reporting, export, and serving functions.
type AssessmentReport struct {
	ID           string                      `json:"id"`
	ToolName     string                      `json:"tool_name"`
	Version      string                      `json:"version"`
	Commit       string                      `json:"commit"`
	GeneratedAt  time.Time                   `json:"generated_at"`
	TargetHost   string                      `json:"target_host"`
	DurationMS   float64                     `json:"duration_ms"`
	DurationText string                      `json:"duration_text"`
	EEI          *EEIReport                  `json:"eei"`
	Summary      AssessmentSummary           `json:"summary"`
	Probes       []common.ProbeResult        `json:"probes"`
	Findings     []common.Finding            `json:"findings"`
	Remediation  RemediationRuleSet          `json:"remediation"`
	Sessions     []*common.Session           `json:"sessions,omitempty"`
	Credentials  []common.CapturedCredential `json:"credentials,omitempty"`
}

// CalculateScoringSummary generates high-level summary metrics from probe results.
func CalculateScoringSummary(probes []common.ProbeResult) AssessmentSummary {
	eei := CalculateEEI(probes)

	summary := AssessmentSummary{
		EEIScore:      eei.Score,
		Posture:       eei.Posture,
		PostureColor:  eei.PostureColor,
		Sport:         eei.PortScore.RawScore,
		Sproto:        eei.ProtoScore.RawScore,
		Sdlp:          eei.DLPScore.RawScore,
		TotalProbes:   len(probes),
		VerdictCounts: make(map[string]int),
	}

	var totalLatency time.Duration
	for _, p := range probes {
		summary.VerdictCounts[string(p.Verdict)]++
		summary.TotalBytesSent += p.BytesSent
		summary.TotalBytesRecv += p.BytesRecv

		switch p.Verdict {
		case common.VerdictSuccess:
			summary.SuccessCount++
		case common.VerdictBlockedL4:
			summary.BlockedL4++
		case common.VerdictBlockedL7:
			summary.BlockedL7++
		case common.VerdictBlockedDLP:
			summary.BlockedDLP++
		}

		totalLatency += p.Timestamps.TotalDuration
	}

	if len(probes) > 0 {
		avgMs := float64(totalLatency.Microseconds()) / (1000.0 * float64(len(probes)))
		summary.AvgLatencyMS = avgMs
		summary.TotalDurationMS = float64(totalLatency.Microseconds()) / 1000.0
		summary.DurationFormatted = fmt.Sprintf("%.2fms", summary.TotalDurationMS)
	}

	return summary
}

// GenerateFindings maps assessment results to standard Contraband findings rules (CTRB-001 through CTRB-004).
func GenerateFindings(probes []common.ProbeResult, credentials []common.CapturedCredential) []common.Finding {
	var findings []common.Finding
	seenPorts := make(map[int]bool)
	seenProtos := make(map[string]bool)

	// Check credentials for CTRB-004
	for _, cred := range credentials {
		findings = append(findings, common.Finding{
			RuleID:          "CTRB-004",
			Level:           "critical",
			Message:         fmt.Sprintf("NetNTLMv2 hash captured for user '%s' domain '%s' via %s", cred.Username, cred.Domain, cred.Protocol),
			Protocol:        cred.Protocol,
			EEIContribution: 10.0,
			Remediation:     "Disable outbound SMB/WebDAV NTLMSSP authentication and enforce Extended Protection for Authentication (EPA).",
		})
	}

	for _, p := range probes {
		if p.CapturedHash != "" {
			findings = append(findings, common.Finding{
				RuleID:          "CTRB-004",
				Level:           "critical",
				Message:         fmt.Sprintf("Cleartext NetNTLMv2 authentication hash exposed via %s on port %d", p.Protocol, p.TargetPort),
				Port:            p.TargetPort,
				Protocol:        p.Protocol,
				EEIContribution: 10.0,
				Remediation:     "Block outbound SMB (TCP 445) and enforce SMB signing / EPA.",
			})
		}

		if p.Verdict != common.VerdictSuccess {
			continue
		}

		// DLP Interception Failure (CTRB-003)
		if p.PayloadType != "" {
			findings = append(findings, common.Finding{
				RuleID:          "CTRB-003",
				Level:           "critical",
				Message:         fmt.Sprintf("DLP failure: %s secret exfiltrated uninspected over %s on port %d", strings.ToUpper(p.PayloadType), p.Protocol, p.TargetPort),
				Port:            p.TargetPort,
				Protocol:        p.Protocol,
				EEIContribution: 5.0,
				Remediation:     fmt.Sprintf("Configure deep content inspection to inspect and block %s secrets.", p.PayloadType),
			})
			continue
		}

		// Layer 4 Unfiltered Port (CTRB-001)
		if p.Stage == "sweep" || p.Protocol == "tcp" || p.Protocol == "udp" {
			if !seenPorts[p.TargetPort] {
				seenPorts[p.TargetPort] = true
				level := "warning"
				switch p.TargetPort {
				case 22, 23, 135, 139, 445, 1433, 3389:
					level = "error"
				}
				findings = append(findings, common.Finding{
					RuleID:          "CTRB-001",
					Level:           level,
					Message:         fmt.Sprintf("Unfiltered outbound port %d/%s accessible through perimeter firewall", p.TargetPort, p.Protocol),
					Port:            p.TargetPort,
					Protocol:        p.Protocol,
					EEIContribution: 2.0,
					Remediation:     fmt.Sprintf("Apply egress firewall rule to drop outbound traffic on port %d.", p.TargetPort),
				})
			}
			continue
		}

		// Layer 7 Smuggling Success (CTRB-002)
		if !seenProtos[p.Protocol] {
			seenProtos[p.Protocol] = true
			findings = append(findings, common.Finding{
				RuleID:          "CTRB-002",
				Level:           "error",
				Message:         fmt.Sprintf("Layer 7 exfiltration channel %s succeeded on port %d", p.Protocol, p.TargetPort),
				Port:            p.TargetPort,
				Protocol:        p.Protocol,
				EEIContribution: 4.0,
				Remediation:     fmt.Sprintf("Enable deep application inspection and proxy decryption for %s.", p.Protocol),
			})
		}
	}

	return findings
}

// NewAssessmentReport builds a complete, populated AssessmentReport.
func NewAssessmentReport(targetHost string, probes []common.ProbeResult, sessions []*common.Session, credentials []common.CapturedCredential, duration time.Duration) *AssessmentReport {
	id, err := common.GenerateUUIDv4()
	if err != nil {
		id = fmt.Sprintf("ctrb-%d", time.Now().UnixNano())
	}

	eei := CalculateEEI(probes)
	summary := CalculateScoringSummary(probes)
	summary.TotalSessions = len(sessions)
	summary.TotalCredentials = len(credentials)

	durationMs := float64(duration.Microseconds()) / 1000.0
	summary.TotalDurationMS = durationMs
	summary.DurationFormatted = fmt.Sprintf("%.2fms", durationMs)

	remediation := GenerateRemediation(probes, targetHost)
	findings := GenerateFindings(probes, credentials)

	return &AssessmentReport{
		ID:           id,
		ToolName:     "Contraband",
		Version:      common.Version,
		Commit:       common.Commit,
		GeneratedAt:  time.Now().UTC(),
		TargetHost:   targetHost,
		DurationMS:   durationMs,
		DurationText: fmt.Sprintf("%.2fms", durationMs),
		EEI:          eei,
		Summary:      summary,
		Probes:       probes,
		Findings:     findings,
		Remediation:  *remediation,
		Sessions:     sessions,
		Credentials:  credentials,
	}
}

// LoadReport reads and deserializes an assessment report file from disk.
func LoadReport(filePath string) (*AssessmentReport, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read report file %s: %w", filePath, err)
	}
	return ParseReport(data)
}

// ParseReport deserializes JSON data into an AssessmentReport, accommodating multiple schema variations.
func ParseReport(data []byte) (*AssessmentReport, error) {
	// 1. Full AssessmentReport
	var rep AssessmentReport
	if err := json.Unmarshal(data, &rep); err == nil && (len(rep.Probes) > 0 || rep.Summary.TotalProbes > 0 || rep.EEI != nil) {
		if rep.EEI == nil {
			rep.EEI = CalculateEEI(rep.Probes)
		}
		if rep.Summary.TotalProbes == 0 {
			rep.Summary = CalculateScoringSummary(rep.Probes)
			rep.Summary.TotalSessions = len(rep.Sessions)
			rep.Summary.TotalCredentials = len(rep.Credentials)
		}
		if rep.Remediation.PANOSRules == "" && len(rep.Probes) > 0 {
			rep.Remediation = *GenerateRemediation(rep.Probes, rep.TargetHost)
		}
		if len(rep.Findings) == 0 && len(rep.Probes) > 0 {
			rep.Findings = GenerateFindings(rep.Probes, rep.Credentials)
		}
		return &rep, nil
	}

	// 2. Ledger ExportJSON format
	var stateExport struct {
		GeneratedAt   time.Time                   `json:"generated_at"`
		TotalProbes   int                         `json:"total_probes"`
		Probes        []common.ProbeResult        `json:"probes"`
		TotalSessions int                         `json:"total_sessions"`
		Sessions      []*common.Session           `json:"sessions"`
		Credentials   []common.CapturedCredential `json:"credentials"`
	}
	if err := json.Unmarshal(data, &stateExport); err == nil && len(stateExport.Probes) > 0 {
		targetHost := "127.0.0.1"
		if len(stateExport.Probes) > 0 && stateExport.Probes[0].TargetHost != "" {
			targetHost = stateExport.Probes[0].TargetHost
		}
		return NewAssessmentReport(targetHost, stateExport.Probes, stateExport.Sessions, stateExport.Credentials, 0), nil
	}

	// 3. Raw ProbeResult array
	var rawProbes []common.ProbeResult
	if err := json.Unmarshal(data, &rawProbes); err == nil && len(rawProbes) > 0 {
		targetHost := "127.0.0.1"
		if rawProbes[0].TargetHost != "" {
			targetHost = rawProbes[0].TargetHost
		}
		return NewAssessmentReport(targetHost, rawProbes, nil, nil, 0), nil
	}

	return nil, fmt.Errorf("unrecognized or invalid assessment report JSON")
}
