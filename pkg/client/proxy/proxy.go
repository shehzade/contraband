package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

var (
	ErrProxyForbidden  = errors.New("proxy access forbidden (403)")
	ErrProxyGateway    = errors.New("proxy gateway error (502/504)")
	ErrProxyAuthFailed = errors.New("proxy authentication failed (407)")
	ErrWPADNotFound    = errors.New("wpad pac script not discovered")
	ErrNoProxyMatch    = errors.New("no proxy found matching target")
)

// Dialer provides context-aware connection establishment to target destinations.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ProxyDialer extends Dialer to expose upstream proxy metadata for telemetry and forensic reporting.
type ProxyDialer interface {
	Dialer
	// ProxyHop returns the upstream proxy address (e.g. "10.0.0.1:8080" or "proxy.corp.local:3128"),
	// or an empty string if direct connection was established.
	ProxyHop() string
	// Mode returns the operational mode: "direct", "http_connect", "socks5".
	Mode() string
}

// Resolver resolves the optimal ProxyDialer for a given target address.
type Resolver interface {
	GetDialer(ctx context.Context, targetAddr string) (ProxyDialer, error)
}

type AuthType string

const (
	AuthNone      AuthType = "none"
	AuthBasic     AuthType = "basic"
	AuthDigest    AuthType = "digest"
	AuthNTLM      AuthType = "ntlm"
	AuthNegotiate AuthType = "negotiate"
	AuthAuto      AuthType = "auto" // Interrogate 407 Proxy-Authenticate headers
)

type Options struct {
	// Mode: "auto", "direct", or an explicit proxy URL (e.g. "http://10.0.0.1:8080", "socks5://127.0.0.1:1080")
	Mode               string
	AuthType           AuthType
	Username           string
	Password           string
	Domain             string        // Windows domain for NTLMv2 / Kerberos
	Workstation        string        // Workstation name for NTLMv2
	PACURL             string        // Explicit PAC URL (skips WPAD discovery if provided)
	Timeout            time.Duration // Proxy connection & handshake timeout (default: 10s)
	WPADTimeout        time.Duration // WPAD discovery timeout (default: 3s)
	UserAgent          string        // User-Agent string for HTTP CONNECT / PAC fetch
	InsecureSkipVerify bool          // Skip TLS cert validation for HTTPS proxies
	Logger             common.Logger
}

// DefaultOptions returns production-grade defaults.
func DefaultOptions() Options {
	return Options{
		Mode:        "auto",
		AuthType:    AuthAuto,
		Timeout:     10 * time.Second,
		WPADTimeout: common.DefaultWPADTimeout, // 3s
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		Logger:      common.GetLogger(),
	}
}

// sanitizeProxyURL converts unencoded backslashes in userinfo (e.g. CORP\corpuser) to %5C.
func sanitizeProxyURL(rawURL string) string {
	atIdx := strings.LastIndex(rawURL, "@")
	if atIdx != -1 {
		schemeIdx := strings.Index(rawURL, "://")
		start := 0
		if schemeIdx != -1 {
			start = schemeIdx + 3
		}
		if start < atIdx {
			userinfo := rawURL[start:atIdx]
			if strings.Contains(userinfo, "\\") {
				escapedUserinfo := strings.ReplaceAll(userinfo, "\\", "%5C")
				return rawURL[:start] + escapedUserinfo + rawURL[atIdx:]
			}
		}
	}
	return rawURL
}

// FromCommonConfig maps common.ProxyConfig into proxy.Options.
func FromCommonConfig(cfg common.ProxyConfig) Options {
	opts := DefaultOptions()
	if cfg.Mode != "" {
		opts.Mode = sanitizeProxyURL(cfg.Mode)
	}
	if cfg.AuthType != "" {
		opts.AuthType = AuthType(cfg.AuthType)
	}
	// Parse credentials if embedded in URL: scheme://user:pass@host:port
	if strings.Contains(opts.Mode, "://") {
		if u, err := url.Parse(opts.Mode); err == nil && u.User != nil {
			opts.Username = u.User.Username()
			opts.Password, _ = u.User.Password()
		}
	}
	return opts
}

// DirectDialer dials targets directly without any proxy hop.
type DirectDialer struct {
	dialer *net.Dialer
}

// NewDirectDialer creates a new DirectDialer with the configured timeout.
func NewDirectDialer(timeout time.Duration) *DirectDialer {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DirectDialer{
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

func (d *DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, addr)
}

func (d *DirectDialer) ProxyHop() string { return "" }
func (d *DirectDialer) Mode() string     { return "direct" }

// NewDialer creates a ProxyDialer from common.ProxyConfig, routing through the fallback engine if "auto".
func NewDialer(cfg common.ProxyConfig) (ProxyDialer, error) {
	opts := FromCommonConfig(cfg)
	return NewDialerFromOptions(opts)
}

// NewDialerFromOptions creates a ProxyDialer based on the provided Options.
func NewDialerFromOptions(opts Options) (ProxyDialer, error) {
	opts.Mode = sanitizeProxyURL(opts.Mode)
	mode := strings.ToLower(opts.Mode)
	if mode == "" || mode == "auto" {
		return NewFallbackEngine(opts), nil
	}
	if mode == "direct" {
		return NewDirectDialer(opts.Timeout), nil
	}

	// Explicit proxy URL
	u, err := url.Parse(opts.Mode)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", opts.Mode, err)
	}

	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return NewHTTPConnectDialer(opts)
	case "socks5", "socks5h":
		return NewSOCKS5Dialer(opts)
	default:
		return nil, fmt.Errorf("unsupported proxy protocol scheme %q", u.Scheme)
	}
}
