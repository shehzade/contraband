package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

var (
	dhcpLeasePaths = []string{
		"/var/lib/dhcp/dhclient.leases",
		"/var/lib/NetworkManager/*.lease",
		"/run/systemd/netif/leases/*",
		"/var/db/dhclient.leases",
	}

	reDHCP252 = regexp.MustCompile(`(?i)option\s+(?:wpad-url|site-local-252|252)\s+"([^"]+)";`)
)

// WPADResult contains discovered WPAD PAC script content and source URL.
type WPADResult struct {
	PACURL string
	Script string
}

// DiscoverWPAD performs WPAD discovery via Explicit URL, DHCP Option 252, or DNS hierarchy walk.
func DiscoverWPAD(ctx context.Context, opts Options) (*WPADResult, error) {
	timeout := opts.WPADTimeout
	if timeout <= 0 {
		timeout = common.DefaultWPADTimeout // 3s
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 1. Explicit PAC URL
	if opts.PACURL != "" {
		script, err := fetchPAC(ctx, opts.PACURL, opts.UserAgent)
		if err == nil && len(strings.TrimSpace(script)) > 0 {
			return &WPADResult{PACURL: opts.PACURL, Script: script}, nil
		}
	}

	// 2. DHCP Option 252 (Linux lease scanning)
	if dhcpURL := ScanDHCPLeasesForWPAD(); dhcpURL != "" {
		script, err := fetchPAC(ctx, dhcpURL, opts.UserAgent)
		if err == nil && len(strings.TrimSpace(script)) > 0 {
			return &WPADResult{PACURL: dhcpURL, Script: script}, nil
		}
	}

	// 3. DNS Hierarchy Probing
	domains := getSearchDomains()
	for _, domain := range domains {
		subdomains := generateWPADCandidates(domain)
		for _, candidateURL := range subdomains {
			select {
			case <-ctx.Done():
				return nil, ErrWPADNotFound
			default:
			}

			script, err := fetchPAC(ctx, candidateURL, opts.UserAgent)
			if err == nil && len(strings.TrimSpace(script)) > 0 {
				return &WPADResult{PACURL: candidateURL, Script: script}, nil
			}
		}
	}

	return nil, ErrWPADNotFound
}

// ScanDHCPLeasesForWPAD inspects common Linux DHCP lease files for Option 252.
func ScanDHCPLeasesForWPAD() string {
	for _, pattern := range dhcpLeasePaths {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, file := range matches {
			content, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			m := reDHCP252.FindSubmatch(content)
			if len(m) > 1 {
				cleanURL := strings.Trim(string(m[1]), "\x00\r\n\t ")
				if _, err := url.Parse(cleanURL); err == nil && cleanURL != "" {
					return cleanURL
				}
			}
		}
	}
	return ""
}

// getSearchDomains extracts DNS search domains from /etc/resolv.conf.
func getSearchDomains() []string {
	var domains []string
	f, err := os.Open("/etc/resolv.conf")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "search ") || strings.HasPrefix(line, "domain ") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					domains = append(domains, fields[1:]...)
				}
			}
		}
	}

	if len(domains) == 0 {
		if h, err := os.Hostname(); err == nil {
			idx := strings.Index(h, ".")
			if idx != -1 && idx < len(h)-1 {
				domains = append(domains, h[idx+1:])
			}
		}
	}

	return domains
}

// generateWPADCandidates generates hierarchical WPAD URLs, avoiding single-label TLDs.
func generateWPADCandidates(domain string) []string {
	domain = strings.Trim(domain, ".")
	parts := strings.Split(domain, ".")
	var candidates []string

	for i := 0; i < len(parts)-1; i++ {
		// Stop before single-label TLD or 2-part public suffix
		sub := strings.Join(parts[i:], ".")
		if strings.Count(sub, ".") < 1 {
			break
		}
		candidates = append(candidates, fmt.Sprintf("http://wpad.%s/wpad.dat", sub))
	}
	return candidates
}

func fetchPAC(ctx context.Context, pacURL, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pacURL, nil)
	if err != nil {
		return "", err
	}
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).DialContext,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	// Limit to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}
