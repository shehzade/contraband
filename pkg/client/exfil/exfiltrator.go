package exfil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/shehzade/contraband/pkg/client/proxy"
	"github.com/shehzade/contraband/pkg/client/traffic"
	"github.com/shehzade/contraband/pkg/common"
)

var (
	ErrProtocolNotFound   = errors.New("exfiltrator protocol not registered")
	ErrProtocolRegistered = errors.New("exfiltrator protocol already registered")
	ErrInvalidOptions     = errors.New("invalid exfiltration options")
	ErrHashMismatch       = errors.New("exfiltrated payload hash mismatch")
	ErrExfilFailed        = errors.New("exfiltration failed")
)

// Exfiltrator defines the standardized client smuggling interface across all transport channels.
type Exfiltrator interface {
	Protocol() string
	Exfiltrate(ctx context.Context, reader io.Reader, opts ExfilOptions) (*common.ProbeResult, error)
}

// ExfilOptions configures transport parameters, pacing, evasion profiles, and proxy routing.
type ExfilOptions struct {
	TargetHost     string
	TargetPort     int
	UseTLS         bool
	InsecureTLS    bool
	TLSFingerprint string // "chrome", "edge", "safari", "firefox", "curl", "default"
	SessionToken   common.SessionToken
	ChunkSize      int
	TotalBytes     int64 // Total volume in bytes for bounded streaming chunk calculation
	ExpectedHash   string
	Headers        map[string]string
	ProxyDialer    proxy.Dialer
	Shaper         traffic.RateLimiter
	Cadence        *traffic.CadenceEngine
	Timeout        time.Duration
	PayloadType    string
	CarrierType    string
	HTTPMode       string // "binary", "chunked", "multipart"
}

// Validate checks essential options and sets sensible defaults.
func (o *ExfilOptions) Validate() error {
	if o.TargetHost == "" {
		return fmt.Errorf("%w: target host is required", ErrInvalidOptions)
	}
	if o.TargetPort <= 0 || o.TargetPort > 65535 {
		return fmt.Errorf("%w: invalid target port %d", ErrInvalidOptions, o.TargetPort)
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = common.DefaultChunkSize
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.TLSFingerprint == "" {
		o.TLSFingerprint = common.TLSFingerprintChrome
	}
	if o.Headers == nil {
		o.Headers = make(map[string]string)
	}
	return nil
}

// Global thread-safe Exfiltrator registry
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Exfiltrator)
)

// RegisterExfiltrator registers a protocol exfiltrator into the global registry.
func RegisterExfiltrator(proto string, ex Exfiltrator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[proto] = ex
}

// GetExfiltrator retrieves an exfiltrator by protocol identifier.
func GetExfiltrator(proto string) (Exfiltrator, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	ex, ok := registry[proto]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrProtocolNotFound, proto)
	}
	return ex, nil
}

// GetAllExfiltrators returns a snapshot copy of all registered exfiltrators.
func GetAllExfiltrators() map[string]Exfiltrator {
	registryMu.RLock()
	defer registryMu.RUnlock()
	res := make(map[string]Exfiltrator, len(registry))
	for k, v := range registry {
		res[k] = v
	}
	return res
}
