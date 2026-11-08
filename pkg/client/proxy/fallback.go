package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ProxyCandidate represents a potential proxy hop in the fallback chain.
type ProxyCandidate struct {
	Name   string
	Dialer ProxyDialer
	Source string
}

// FallbackEngine implements an intelligent 5-tier proxy fallback cascade:
// 1. Explicit Flag -> 2. System Proxy -> 3. WPAD -> 4. Environment Variables -> 5. Direct Egress
type FallbackEngine struct {
	opts             Options
	logger           common.Logger
	mu               sync.RWMutex
	lastHop          string
	lastMode         string
	directDialer     *DirectDialer
	customCandidates []ProxyCandidate
}

// NewFallbackEngine initializes a new FallbackEngine.
func NewFallbackEngine(opts Options) *FallbackEngine {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &FallbackEngine{
		opts:         opts,
		logger:       opts.Logger,
		directDialer: NewDirectDialer(timeout),
		lastMode:     "auto",
	}
}

// SetCustomCandidates overrides candidate discovery with custom candidates (useful for testing).
func (fe *FallbackEngine) SetCustomCandidates(candidates []ProxyCandidate) {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.customCandidates = candidates
}

func (fe *FallbackEngine) ProxyHop() string {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.lastHop
}

func (fe *FallbackEngine) Mode() string {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	return fe.lastMode
}

// DialContext traverses the candidate chain until a successful connection is established.
func (fe *FallbackEngine) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	candidates := fe.buildCandidates(ctx, targetAddr)

	var lastErr error
	var explicitProxyErr error
	for _, c := range candidates {
		fe.logger.Debugf("Attempting egress via %s [%s]", c.Name, c.Source)

		conn, err := c.Dialer.DialContext(ctx, network, targetAddr)
		if err == nil {
			fe.mu.Lock()
			fe.lastHop = c.Dialer.ProxyHop()
			fe.lastMode = c.Dialer.Mode()
			fe.mu.Unlock()

			if lastErr != nil {
				fe.logger.Warnf("Primary proxy candidate failed (%v); fell back to %s (Hop: %s, Mode: %s)", lastErr, c.Name, c.Dialer.ProxyHop(), c.Dialer.Mode())
			} else {
				fe.logger.Infof("Egress established via %s (Hop: %s, Mode: %s)", c.Name, c.Dialer.ProxyHop(), c.Dialer.Mode())
			}
			return conn, nil
		}

		fe.logger.Warnf("Egress candidate %s [%s] failed: %v", c.Name, c.Source, err)
		if c.Name == "ExplicitProxy" {
			explicitProxyErr = err
		}
		lastErr = err
	}

	if explicitProxyErr != nil {
		return nil, fmt.Errorf("explicit proxy traversal failed: %w", explicitProxyErr)
	}
	return nil, fmt.Errorf("all proxy traversal candidates exhausted, last error: %w", lastErr)
}

func (fe *FallbackEngine) buildCandidates(ctx context.Context, targetAddr string) []ProxyCandidate {
	fe.mu.RLock()
	if len(fe.customCandidates) > 0 {
		c := make([]ProxyCandidate, len(fe.customCandidates))
		copy(c, fe.customCandidates)
		fe.mu.RUnlock()
		return c
	}
	fe.mu.RUnlock()

	var candidates []ProxyCandidate

	// 1. Explicit Flag (if specified and not auto/direct)
	mode := strings.ToLower(fe.opts.Mode)
	if mode != "" && mode != "auto" && mode != "direct" {
		d, err := NewDialerFromOptions(fe.opts)
		if err != nil {
			fe.logger.Warnf("Failed to initialize explicit proxy dialer %q: %v", fe.opts.Mode, err)
		} else {
			candidates = append(candidates, ProxyCandidate{
				Name:   "ExplicitProxy",
				Dialer: d,
				Source: "CLI / Configuration Flag",
			})
			// If explicitly given, do not try other proxies before Direct
			candidates = append(candidates, ProxyCandidate{
				Name:   "DirectFallback",
				Dialer: fe.directDialer,
				Source: "Direct Egress (Fallback)",
			})
			return candidates
		}
	}

	// 2. System Proxy (Windows WinHTTP / Registry)
	if winCfg, _ := GetWindowsProxyConfig(); winCfg != nil {
		if winCfg.Proxy != "" && !shouldBypass(targetAddr, winCfg.ProxyBypass) {
			sysOpts := fe.opts
			sysOpts.Mode = winCfg.Proxy
			if d, err := NewDialerFromOptions(sysOpts); err == nil {
				candidates = append(candidates, ProxyCandidate{
					Name:   "WindowsSystemProxy",
					Dialer: d,
					Source: "Windows Registry Internet Settings",
				})
			}
		}
		if winCfg.AutoConfigURL != "" && fe.opts.PACURL == "" {
			fe.opts.PACURL = winCfg.AutoConfigURL
		}
	}

	// 3. WPAD Auto-Discovery
	wpadCtx, cancel := context.WithTimeout(ctx, fe.opts.WPADTimeout)
	wpadRes, err := DiscoverWPAD(wpadCtx, fe.opts)
	cancel()
	if err == nil && wpadRes != nil && wpadRes.Script != "" {
		host, _, _ := net.SplitHostPort(targetAddr)
		if host == "" {
			host = targetAddr
		}
		directives, err := EvaluatePACScript(ctx, wpadRes.Script, "http://"+targetAddr, host)
		if err == nil {
			for i, d := range directives {
				if d.Type == DirectiveDirect {
					continue
				}
				pacOpts := fe.opts
				pacOpts.Mode = d.ToURL()
				if pd, err := NewDialerFromOptions(pacOpts); err == nil {
					candidates = append(candidates, ProxyCandidate{
						Name:   fmt.Sprintf("WPADDirective_%d", i+1),
						Dialer: pd,
						Source: fmt.Sprintf("WPAD PAC (%s)", wpadRes.PACURL),
					})
				}
			}
		}
	}

	// 4. Environment Variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, with NO_PROXY)
	if !isNoProxy(targetAddr) {
		envProxy := getEnvProxy(targetAddr)
		if envProxy != "" {
			envOpts := fe.opts
			envOpts.Mode = envProxy
			if ed, err := NewDialerFromOptions(envOpts); err == nil {
				candidates = append(candidates, ProxyCandidate{
					Name:   "EnvProxy",
					Dialer: ed,
					Source: "Environment Variables",
				})
			}
		}
	}

	// 5. Direct Egress
	candidates = append(candidates, ProxyCandidate{
		Name:   "DirectEgress",
		Dialer: fe.directDialer,
		Source: "Direct TCP Socket",
	})

	return candidates
}

func getEnvProxy(targetAddr string) string {
	if strings.HasSuffix(targetAddr, ":443") {
		if p := os.Getenv("HTTPS_PROXY"); p != "" {
			return p
		}
		if p := os.Getenv("https_proxy"); p != "" {
			return p
		}
	}
	if p := os.Getenv("HTTP_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("http_proxy"); p != "" {
		return p
	}
	if p := os.Getenv("ALL_PROXY"); p != "" {
		return p
	}
	if p := os.Getenv("all_proxy"); p != "" {
		return p
	}
	return ""
}

func isNoProxy(targetAddr string) bool {
	noProxy := os.Getenv("NO_PROXY")
	if noProxy == "" {
		noProxy = os.Getenv("no_proxy")
	}
	if noProxy == "" {
		return false
	}
	return shouldBypass(targetAddr, noProxy)
}

func shouldBypass(targetAddr, bypassRules string) bool {
	if bypassRules == "" {
		return false
	}
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}
	host = strings.ToLower(strings.TrimSpace(host))

	rules := strings.FieldsFunc(bypassRules, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})

	targetIP := net.ParseIP(host)

	for _, rule := range rules {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if rule == "" {
			continue
		}
		if rule == "*" {
			return true
		}
		if rule == "<local>" && !strings.Contains(host, ".") {
			return true
		}
		if rule == host {
			return true
		}
		if strings.HasPrefix(rule, ".") && strings.HasSuffix(host, rule) {
			return true
		}
		if !strings.HasPrefix(rule, ".") && strings.HasSuffix(host, "."+rule) {
			return true
		}
		// CIDR check
		if targetIP != nil {
			if _, cidr, err := net.ParseCIDR(rule); err == nil {
				if cidr.Contains(targetIP) {
					return true
				}
			}
		}
	}
	return false
}
