package report

import (
	"fmt"
	"html/template"
	"io"
	"math"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/report/templates"
)

// HTMLTemplateFuncs provides custom helper functions for formatting dashboard components.
var HTMLTemplateFuncs = template.FuncMap{
	"formatMS": func(v interface{}) string {
		switch val := v.(type) {
		case float64:
			return fmt.Sprintf("%.2fms", val)
		case float32:
			return fmt.Sprintf("%.2fms", float64(val))
		case int:
			return fmt.Sprintf("%.2fms", float64(val))
		case int64:
			return fmt.Sprintf("%.2fms", float64(val))
		case time.Duration:
			return fmt.Sprintf("%.2fms", float64(val.Microseconds())/1000.0)
		default:
			return fmt.Sprintf("%vms", val)
		}
	},
	"divDurMS": func(d time.Duration) float64 {
		return float64(d.Microseconds()) / 1000.0
	},
	"formatBytes": func(b int64) string {
		return common.FormatBytes(b)
	},
	"formatRFC3339MS": func(t time.Time) string {
		return t.UTC().Format("2006-01-02 15:04:05.000")
	},
	"verdictClass": func(v common.Verdict) string {
		switch v {
		case common.VerdictSuccess:
			return "verdict-success"
		case common.VerdictBlockedL4:
			return "verdict-blocked-l4"
		case common.VerdictBlockedL7:
			return "verdict-blocked-l7"
		case common.VerdictBlockedDLP:
			return "verdict-blocked-dlp"
		default:
			return "verdict-unknown"
		}
	},
	"verdictBadge": func(v common.Verdict) template.HTML {
		switch v {
		case common.VerdictSuccess:
			return template.HTML(`<span class="badge badge-success">EXFIL_SUCCESS</span>`)
		case common.VerdictBlockedL4:
			return template.HTML(`<span class="badge badge-blocked-l4">BLOCKED_L4</span>`)
		case common.VerdictBlockedL7:
			return template.HTML(`<span class="badge badge-blocked-l7">BLOCKED_L7</span>`)
		case common.VerdictBlockedDLP:
			return template.HTML(`<span class="badge badge-blocked-dlp">BLOCKED_DLP</span>`)
		default:
			return template.HTML(`<span class="badge badge-unknown">UNKNOWN</span>`)
		}
	},
	"calcGaugeOffset": func(score float64) float64 {
		// Semi-circle arc length: pi * 100 = 314.16
		const arcLength = 314.159
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		return arcLength * (1.0 - (score / 100.0))
	},
	"calcNeedleAngle": func(score float64) int {
		// Needle rotation angle: 180 degrees at 0%, 270 degrees at 50%, 360 degrees at 100%
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}
		return int(math.Round(180.0 + (score * 1.8)))
	},
	"truncateHash": func(h string, maxLen int) string {
		if len(h) <= maxLen {
			return h
		}
		return h[:maxLen] + "…"
	},
}

// GenerateHTML renders the assessment report into a standalone interactive HTML string.
func GenerateHTML(report *AssessmentReport) (string, error) {
	var sb strings.Builder
	if err := WriteHTML(&sb, report); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// WriteHTML streams rendered HTML into the provided io.Writer for memory efficiency.
func WriteHTML(w io.Writer, report *AssessmentReport) error {
	tmpl, err := template.New("dashboard").Funcs(HTMLTemplateFuncs).Parse(templates.DashboardHTML)
	if err != nil {
		return fmt.Errorf("failed to parse dashboard HTML template: %w", err)
	}
	return tmpl.Execute(w, report)
}
