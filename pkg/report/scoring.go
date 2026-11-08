package report

import (
	"math"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// PostureLevel classifies enterprise egress exposure risk.
type PostureLevel string

const (
	PostureHardened PostureLevel = "Hardened" // 0.0% – 19.9%
	PostureModerate PostureLevel = "Moderate" // 20.0% – 59.9%
	PostureCritical PostureLevel = "Critical" // 60.0% – 100.0%
)

// PostureColor returns the associated hex color code for executive dashboards.
func (p PostureLevel) PostureColor() string {
	switch p {
	case PostureHardened:
		return "#22c55e" // Green
	case PostureModerate:
		return "#eab308" // Yellow / Amber
	case PostureCritical:
		return "#ef4444" // Red
	default:
		return "#6b7280" // Gray
	}
}

// CategoryScore tracks metrics and calculated exposure for an individual assessment category.
type CategoryScore struct {
	Category      string  `json:"category"`
	Weight        float64 `json:"weight"`         // 0.30 for Port/DLP, 0.40 for Proto
	TestedCount   int     `json:"tested_count"`   // Total items tested
	SuccessCount  int     `json:"success_count"`  // Unfiltered / succeeded / leaked
	BlockedCount  int     `json:"blocked_count"`  // Blocked by L4/L7/DLP
	RawScore      float64 `json:"raw_score"`      // Percentage 0.0 – 100.0
	WeightedScore float64 `json:"weighted_score"` // RawScore * Weight
	Tested        bool    `json:"tested"`         // True if TestedCount > 0
}

// EEIReport encapsulates the complete Egress Exposure Index calculation.
type EEIReport struct {
	Score         float64       `json:"eei_score"`     // Normalized EEI (0.0 – 100.0)
	RawScore      float64       `json:"raw_eei_score"` // Unnormalized EEI
	Posture       PostureLevel  `json:"posture"`       // Hardened, Moderate, Critical
	PostureColor  string        `json:"posture_color"` // Hex color code
	PortScore     CategoryScore `json:"port_score"`    // Sport (0.30)
	ProtoScore    CategoryScore `json:"proto_score"`   // Sproto (0.40)
	DLPScore      CategoryScore `json:"dlp_score"`     // Sdlp (0.30)
	TotalProbes   int           `json:"total_probes"`
	SuccessProbes int           `json:"success_probes"`
	BlockedProbes int           `json:"blocked_probes"`
	GeneratedAt   time.Time     `json:"generated_at"`
}

const (
	WeightPort  = 0.30
	WeightProto = 0.40
	WeightDLP   = 0.30

	ThresholdHardenedMax = 19.99
	ThresholdModerateMax = 59.99
)

// ClassifyPosture maps an exposure score to its posture classification.
func ClassifyPosture(score float64) PostureLevel {
	if score < 0.0 {
		score = 0.0
	}
	if score > 100.0 {
		score = 100.0
	}
	rounded := math.Round(score*100) / 100

	if rounded <= ThresholdHardenedMax {
		return PostureHardened
	}
	if rounded <= ThresholdModerateMax {
		return PostureModerate
	}
	return PostureCritical
}

// CalculateEEI processes a list of probe results and calculates the Egress Exposure Index.
// It mitigates division-by-zero when categories are untested using Normalized Active Weighting.
func CalculateEEI(probes []common.ProbeResult) *EEIReport {
	report := &EEIReport{
		GeneratedAt: time.Now().UTC(),
		PortScore: CategoryScore{
			Category: "ports",
			Weight:   WeightPort,
		},
		ProtoScore: CategoryScore{
			Category: "protocols",
			Weight:   WeightProto,
		},
		DLPScore: CategoryScore{
			Category: "dlp",
			Weight:   WeightDLP,
		},
	}

	report.TotalProbes = len(probes)
	if len(probes) == 0 {
		report.Score = 0.0
		report.RawScore = 0.0
		report.Posture = PostureHardened
		report.PostureColor = report.Posture.PostureColor()
		return report
	}

	// 1. Accumulate Port Sweep Metrics
	testedPorts := make(map[int]bool)
	unfilteredPorts := make(map[int]bool)

	// 2. Accumulate Protocol Metrics
	testedProtos := make(map[string]bool)
	successfulProtos := make(map[string]bool)

	// 3. Accumulate DLP Metrics
	dlpTested := 0
	dlpUninspected := 0
	dlpBlocked := 0

	for _, p := range probes {
		if p.Verdict.IsSuccess() {
			report.SuccessProbes++
		} else {
			report.BlockedProbes++
		}

		// Port Sweep Stage
		if p.Stage == "sweep" || (p.Stage == "" && p.PayloadType == "" && p.TargetPort > 0) || p.Protocol == "tcp" || p.Protocol == "udp" {
			if p.TargetPort > 0 {
				testedPorts[p.TargetPort] = true
				if p.Verdict.IsSuccess() {
					unfilteredPorts[p.TargetPort] = true
				}
			}
		}

		// Protocol Exfiltration Stage
		if p.Stage == "exfil" || (p.Stage != "sweep" && p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp") {
			testedProtos[p.Protocol] = true
			if p.Verdict.IsSuccess() {
				successfulProtos[p.Protocol] = true
			}
		}

		// Procedural DLP Stage
		if p.PayloadType != "" || p.Stage == "dlp" {
			dlpTested++
			if p.Verdict.IsSuccess() {
				dlpUninspected++
			} else {
				dlpBlocked++
			}
		}
	}

	// Calculate Category 1: Sport
	report.PortScore.TestedCount = len(testedPorts)
	report.PortScore.SuccessCount = len(unfilteredPorts)
	report.PortScore.BlockedCount = len(testedPorts) - len(unfilteredPorts)
	if report.PortScore.TestedCount > 0 {
		report.PortScore.Tested = true
		report.PortScore.RawScore = (float64(report.PortScore.SuccessCount) / float64(report.PortScore.TestedCount)) * 100.0
		report.PortScore.WeightedScore = report.PortScore.RawScore * WeightPort
	}

	// Calculate Category 2: Sproto
	report.ProtoScore.TestedCount = len(testedProtos)
	report.ProtoScore.SuccessCount = len(successfulProtos)
	report.ProtoScore.BlockedCount = len(testedProtos) - len(successfulProtos)
	if report.ProtoScore.TestedCount > 0 {
		report.ProtoScore.Tested = true
		report.ProtoScore.RawScore = (float64(report.ProtoScore.SuccessCount) / float64(report.ProtoScore.TestedCount)) * 100.0
		report.ProtoScore.WeightedScore = report.ProtoScore.RawScore * WeightProto
	}

	// Calculate Category 3: Sdlp
	report.DLPScore.TestedCount = dlpTested
	report.DLPScore.SuccessCount = dlpUninspected
	report.DLPScore.BlockedCount = dlpBlocked
	if report.DLPScore.TestedCount > 0 {
		report.DLPScore.Tested = true
		report.DLPScore.RawScore = (float64(report.DLPScore.SuccessCount) / float64(report.DLPScore.TestedCount)) * 100.0
		report.DLPScore.WeightedScore = report.DLPScore.RawScore * WeightDLP
	}

	// Raw EEI: direct sum of weighted components
	rawEEI := report.PortScore.WeightedScore + report.ProtoScore.WeightedScore + report.DLPScore.WeightedScore
	report.RawScore = math.Round(rawEEI*100) / 100

	// Normalized Active EEI (rebalancing when some categories are untested)
	activeWeight := 0.0
	if report.PortScore.Tested {
		activeWeight += WeightPort
	}
	if report.ProtoScore.Tested {
		activeWeight += WeightProto
	}
	if report.DLPScore.Tested {
		activeWeight += WeightDLP
	}

	if activeWeight > 0.0 {
		normalizedScore := rawEEI / activeWeight
		if normalizedScore < 0.0 {
			normalizedScore = 0.0
		}
		if normalizedScore > 100.0 {
			normalizedScore = 100.0
		}
		report.Score = math.Round(normalizedScore*100) / 100
	} else {
		report.Score = 0.0
	}

	report.Posture = ClassifyPosture(report.Score)
	report.PostureColor = report.Posture.PostureColor()

	return report
}
