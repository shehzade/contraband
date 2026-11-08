package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/shehzade/contraband/pkg/common"
)

// ExportJSON generates a full machine-readable JSON document of the assessment.
func ExportJSON(report *AssessmentReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report provided")
	}
	return json.MarshalIndent(report, "", "  ")
}

// -----------------------------------------------------------------------------
// OASIS SARIF v2.1.0 Data Structures
// -----------------------------------------------------------------------------

type SARIFLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool      SARIFTool       `json:"tool"`
	Artifacts []SARIFArtifact `json:"artifacts,omitempty"`
	Results   []SARIFResult   `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	FullName       string      `json:"fullName"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	FullDescription      SARIFMessage           `json:"fullDescription"`
	DefaultConfiguration SARIFRuleConfiguration `json:"defaultConfiguration"`
	HelpURI              string                 `json:"helpUri,omitempty"`
}

type SARIFRuleConfiguration struct {
	Level string `json:"level"` // "error", "warning", "note"
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// GetStandardSARIFRules returns the canonical rule catalog for Contraband.
func GetStandardSARIFRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "CTRB-001",
			Name: "UnfilteredOutboundPort",
			ShortDescription: SARIFMessage{
				Text: "Unfiltered Outbound Layer 4 Port",
			},
			FullDescription: SARIFMessage{
				Text: "An outbound Layer 4 TCP or UDP port is unfiltered by the perimeter firewall, permitting arbitrary egress traffic.",
			},
			DefaultConfiguration: SARIFRuleConfiguration{
				Level: "warning",
			},
			HelpURI: "https://github.com/shehzade/contraband#remediation",
		},
		{
			ID:   "CTRB-002",
			Name: "L7SmugglingSuccess",
			ShortDescription: SARIFMessage{
				Text: "Layer 7 Protocol Smuggling / Evasion Success",
			},
			FullDescription: SARIFMessage{
				Text: "Data exfiltration succeeded over a non-standard Layer 7 protocol, uTLS masquerader, or covert channel, bypassing proxy and deep packet inspection.",
			},
			DefaultConfiguration: SARIFRuleConfiguration{
				Level: "error",
			},
			HelpURI: "https://github.com/shehzade/contraband#remediation",
		},
		{
			ID:   "CTRB-003",
			Name: "UninspectedDLPLeakage",
			ShortDescription: SARIFMessage{
				Text: "Uninspected Sensitive Data Exfiltration (DLP Interception Failure)",
			},
			FullDescription: SARIFMessage{
				Text: "Mathematically valid sensitive secrets (PCI credit cards, PII SSNs, HIPAA records, or cloud API tokens) were exfiltrated without DLP interception.",
			},
			DefaultConfiguration: SARIFRuleConfiguration{
				Level: "error",
			},
			HelpURI: "https://github.com/shehzade/contraband#remediation",
		},
		{
			ID:   "CTRB-004",
			Name: "CleartextNetNTLMv2Exposure",
			ShortDescription: SARIFMessage{
				Text: "Outbound NetNTLMv2 Authentication Hash Exposure",
			},
			FullDescription: SARIFMessage{
				Text: "Outbound SMB or WebDAV connection initiated an NTLMSSP handshake, leaking cleartext NetNTLMv2 authentication challenge-response hashes to an external collector.",
			},
			DefaultConfiguration: SARIFRuleConfiguration{
				Level: "error",
			},
			HelpURI: "https://github.com/shehzade/contraband#remediation",
		},
	}
}

// ExportSARIF converts assessment findings into OASIS SARIF v2.1.0 standard format.
func ExportSARIF(report *AssessmentReport) ([]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("nil report provided")
	}

	version := report.Version
	if version == "" {
		version = common.Version
	}

	log := SARIFLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Contraband",
						FullName:       "Contraband Network Egress Assessment Framework",
						Version:        version,
						InformationURI: "https://github.com/shehzade/contraband",
						Rules:          GetStandardSARIFRules(),
					},
				},
				Results: make([]SARIFResult, 0),
			},
		},
	}

	for _, probe := range report.Probes {
		targetHost := probe.TargetHost
		if targetHost == "" {
			targetHost = report.TargetHost
		}

		// 1. Check for NetNTLMv2 Hash Exposure (CTRB-004)
		if probe.CapturedHash != "" || probe.Protocol == "smb_hash" {
			res := SARIFResult{
				RuleID: "CTRB-004",
				Level:  "error",
				Message: SARIFMessage{
					Text: fmt.Sprintf("Outbound NetNTLMv2 authentication hash exposed via %s on port %d", probe.Protocol, probe.TargetPort),
				},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: fmt.Sprintf("network://%s:%d/%s", targetHost, probe.TargetPort, probe.Protocol),
							},
						},
					},
				},
				Properties: map[string]interface{}{
					"captured_hash": probe.CapturedHash,
					"stage":         probe.Stage,
					"verdict":       string(probe.Verdict),
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, res)
		}

		// Only generate vulnerability results for successful vectors
		if probe.Verdict != common.VerdictSuccess {
			continue
		}

		durationMs := float64(probe.Timestamps.TotalDuration.Microseconds()) / 1000.0
		durationFormatted := fmt.Sprintf("%.2fms", durationMs)

		// 2. DLP Secret Leakage (CTRB-003)
		if probe.PayloadType != "" {
			res := SARIFResult{
				RuleID: "CTRB-003",
				Level:  "error",
				Message: SARIFMessage{
					Text: fmt.Sprintf("DLP failure: %s secret exfiltrated uninspected over %s port %d (%d bytes)",
						strings.ToUpper(probe.PayloadType), probe.Protocol, probe.TargetPort, probe.BytesSent),
				},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: fmt.Sprintf("network://%s:%d/%s", targetHost, probe.TargetPort, probe.Protocol),
							},
						},
					},
				},
				Properties: map[string]interface{}{
					"payload_type": probe.PayloadType,
					"carrier_type": probe.CarrierType,
					"payload_hash": probe.PayloadHash,
					"wire_hash":    probe.WireHash,
					"bytes_sent":   probe.BytesSent,
					"duration_ms":  durationFormatted,
					"ja4_string":   probe.JA4String,
					"raw_evidence": probe.RawEvidence,
					"verdict":      string(probe.Verdict),
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, res)
			continue
		}

		// 3. Port Sweep Exposure (CTRB-001)
		if probe.Stage == "sweep" || probe.Protocol == "tcp" || probe.Protocol == "udp" {
			level := "warning"
			switch probe.TargetPort {
			case 22, 23, 135, 139, 445, 1433, 3389:
				level = "error"
			}

			res := SARIFResult{
				RuleID: "CTRB-001",
				Level:  level,
				Message: SARIFMessage{
					Text: fmt.Sprintf("Unfiltered outbound port %d/%s accessible through perimeter firewall (Latency: %s)",
						probe.TargetPort, probe.Protocol, durationFormatted),
				},
				Locations: []SARIFLocation{
					{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{
								URI: fmt.Sprintf("network://%s:%d/%s", targetHost, probe.TargetPort, probe.Protocol),
							},
						},
					},
				},
				Properties: map[string]interface{}{
					"target_port": probe.TargetPort,
					"protocol":    probe.Protocol,
					"duration_ms": durationFormatted,
					"verdict":     string(probe.Verdict),
				},
			}
			log.Runs[0].Results = append(log.Runs[0].Results, res)
			continue
		}

		// 4. Layer 7 Smuggling / Evasion (CTRB-002)
		res := SARIFResult{
			RuleID: "CTRB-002",
			Level:  "error",
			Message: SARIFMessage{
				Text: fmt.Sprintf("Layer 7 exfiltration channel %s succeeded on port %d (TLS: %s, JA4: %s)",
					probe.Protocol, probe.TargetPort, probe.TLSProfile, probe.JA4String),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: fmt.Sprintf("network://%s:%d/%s", targetHost, probe.TargetPort, probe.Protocol),
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"protocol":     probe.Protocol,
				"tls_profile":  probe.TLSProfile,
				"ja3_string":   probe.JA3String,
				"ja4_string":   probe.JA4String,
				"payload_hash": probe.PayloadHash,
				"bytes_sent":   probe.BytesSent,
				"duration_ms":  durationFormatted,
				"verdict":      string(probe.Verdict),
			},
		}
		log.Runs[0].Results = append(log.Runs[0].Results, res)
	}

	for _, cred := range report.Credentials {
		res := SARIFResult{
			RuleID: "CTRB-004",
			Level:  "error",
			Message: SARIFMessage{
				Text: fmt.Sprintf("Outbound NetNTLMv2 authentication hash exposed for user %s\\%s", cred.Domain, cred.Username),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: fmt.Sprintf("network://%s:445/%s", report.TargetHost, cred.Protocol),
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"username": cred.Username,
				"domain":   cred.Domain,
				"hash":     cred.Hash,
				"protocol": cred.Protocol,
			},
		}
		log.Runs[0].Results = append(log.Runs[0].Results, res)
	}

	return json.MarshalIndent(log, "", "  ")
}
