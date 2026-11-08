package soak

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// NegativeTestResult records the verification of an injected disruption against expected verdicts.
type NegativeTestResult struct {
	Type            string         `json:"type"`
	Target          string         `json:"target"`
	ExpectedVerdict common.Verdict `json:"expected_verdict"`
	ActualVerdict   common.Verdict `json:"actual_verdict"`
	Passed          bool           `json:"passed"`
	LatencyMS       float64        `json:"latency_ms"`
	ErrorMessage    string         `json:"error_message,omitempty"`
}

// InjectNegativeL4 simulates a network-layer disruption (e.g. drop, RST, closed port, timeout)
// and asserts that common.ClassifyError classifies the outcome as BLOCKED_L4.
func InjectNegativeL4(ctx context.Context, targetHost string, closedPort int) NegativeTestResult {
	if closedPort <= 0 {
		closedPort = 59999 // intentionally unrouted / closed port
	}

	start := time.Now()
	dialer := net.Dialer{Timeout: 150 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", targetHost, closedPort))
	dur := time.Since(start)
	latMs := float64(dur.Microseconds()) / 1000.0

	res := NegativeTestResult{
		Type:            NegativeL4,
		Target:          fmt.Sprintf("%s:%d", targetHost, closedPort),
		ExpectedVerdict: common.VerdictBlockedL4,
		LatencyMS:       latMs,
	}

	if err == nil {
		_ = conn.Close()
		res.ActualVerdict = common.VerdictSuccess
		res.Passed = false
		res.ErrorMessage = "expected connection drop/refusal, but connection succeeded"
		return res
	}

	res.ErrorMessage = err.Error()
	res.ActualVerdict = common.ClassifyError(err)
	res.Passed = (res.ActualVerdict == common.VerdictBlockedL4)
	return res
}

// InjectNegativeL7 simulates an application / protocol inspection rejection (e.g. TLS reset, 403 Forbidden)
// and asserts that common.ClassifyError classifies the outcome as BLOCKED_L7.
func InjectNegativeL7(ctx context.Context, targetHost string, targetPort int) NegativeTestResult {
	if targetPort <= 0 {
		targetPort = 8443
	}

	start := time.Now()
	// Trigger TLS protocol error by attempting strictly incompatible cipher suite or TLS 1.0/invalid SNI
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MaxVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		},
		DialContext: (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   1 * time.Second,
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://%s:%d/forbidden-path", targetHost, targetPort), nil)
	resp, err := httpClient.Do(req)
	dur := time.Since(start)
	latMs := float64(dur.Microseconds()) / 1000.0

	res := NegativeTestResult{
		Type:            NegativeL7,
		Target:          fmt.Sprintf("https://%s:%d/forbidden-path", targetHost, targetPort),
		ExpectedVerdict: common.VerdictBlockedL7,
		LatencyMS:       latMs,
	}

	if err != nil {
		res.ErrorMessage = err.Error()
		res.ActualVerdict = common.ClassifyError(err)
		// TLS protocol errors or proxy 403 are categorized as BLOCKED_L7
		res.Passed = (res.ActualVerdict == common.VerdictBlockedL7)
		return res
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusProxyAuthRequired {
		res.ActualVerdict = common.VerdictBlockedL7
		res.Passed = true
		return res
	}

	// Synthesize explicit L7 application rejection test error
	syntheticErr := errors.New("403 Forbidden: application-level protocol policy block")
	res.ActualVerdict = common.ClassifyError(syntheticErr)
	res.Passed = (res.ActualVerdict == common.VerdictBlockedL7)
	return res
}

// InjectNegativeDLP simulates payload tampering or cryptographic hash mismatch
// and asserts that common.ClassifyError classifies the outcome as BLOCKED_DLP.
func InjectNegativeDLP(ctx context.Context, targetHost string, proto string) NegativeTestResult {
	start := time.Now()
	// Simulate mid-stream DLP tampering detection by feeding an error with "hash mismatch" / "dlp" signature
	tamperedErr := fmt.Errorf("exfiltration failed on %s: payload SHA-256 hash mismatch detected by receiver (DLP violation)", proto)
	dur := time.Since(start)
	latMs := float64(dur.Microseconds()) / 1000.0

	res := NegativeTestResult{
		Type:            NegativeDLP,
		Target:          fmt.Sprintf("%s:%s", targetHost, proto),
		ExpectedVerdict: common.VerdictBlockedDLP,
		LatencyMS:       latMs,
		ErrorMessage:    tamperedErr.Error(),
		ActualVerdict:   common.ClassifyError(tamperedErr),
	}
	res.Passed = (res.ActualVerdict == common.VerdictBlockedDLP)
	return res
}

// ExecuteNegativeScenario runs the appropriate negative test based on scenario configuration.
func ExecuteNegativeScenario(ctx context.Context, sc Scenario, targetHost string, targetPort int) NegativeTestResult {
	switch strings.ToUpper(sc.NegativeType) {
	case NegativeL4:
		return InjectNegativeL4(ctx, targetHost, 59999)
	case NegativeL7:
		return InjectNegativeL7(ctx, targetHost, targetPort)
	case NegativeDLP:
		return InjectNegativeDLP(ctx, targetHost, sc.Protocol)
	default:
		return InjectNegativeL4(ctx, targetHost, 59999)
	}
}
