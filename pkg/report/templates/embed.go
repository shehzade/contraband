package templates

import _ "embed"

// DashboardHTML embeds the standalone zero-CDN HTML dashboard template.
//
//go:embed dashboard.html
var DashboardHTML string
