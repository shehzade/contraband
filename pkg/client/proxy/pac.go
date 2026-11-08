package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"
)

// DirectiveType represents the proxy directive type parsed from PAC results.
type DirectiveType int

const (
	DirectiveDirect DirectiveType = iota
	DirectiveHTTP
	DirectiveHTTPS
	DirectiveSOCKS5
	DirectiveSOCKS4
)

// Typed PAC errors for diagnostics and strict evaluation.
var (
	ErrPACEmptyScript      = errors.New("empty or whitespace PAC script")
	ErrPACSyntaxError      = errors.New("PAC JavaScript syntax error")
	ErrPACMissingFindProxy = errors.New("FindProxyForURL function not defined in PAC script")
	ErrPACExecutionTimeout = errors.New("PAC script execution timed out")
	ErrPACRuntimeError     = errors.New("PAC script execution error")
)

// DefaultPACTimout defines the maximum allowable runtime for evaluating a PAC script.
var DefaultPACTimout = 1000 * time.Millisecond

// ProxyDirective represents a parsed proxy instruction from a PAC script.
type ProxyDirective struct {
	Type DirectiveType
	Host string
	Port int
}

func (d ProxyDirective) String() string {
	switch d.Type {
	case DirectiveDirect:
		return "DIRECT"
	case DirectiveHTTP:
		return fmt.Sprintf("PROXY %s:%d", d.Host, d.Port)
	case DirectiveHTTPS:
		return fmt.Sprintf("HTTPS %s:%d", d.Host, d.Port)
	case DirectiveSOCKS5:
		return fmt.Sprintf("SOCKS5 %s:%d", d.Host, d.Port)
	case DirectiveSOCKS4:
		return fmt.Sprintf("SOCKS %s:%d", d.Host, d.Port)
	default:
		return "DIRECT"
	}
}

// ToURL returns the URL representation of the proxy directive.
func (d ProxyDirective) ToURL() string {
	switch d.Type {
	case DirectiveDirect:
		return "direct"
	case DirectiveHTTP:
		return fmt.Sprintf("http://%s:%d", d.Host, d.Port)
	case DirectiveHTTPS:
		return fmt.Sprintf("https://%s:%d", d.Host, d.Port)
	case DirectiveSOCKS5:
		return fmt.Sprintf("socks5://%s:%d", d.Host, d.Port)
	case DirectiveSOCKS4:
		return fmt.Sprintf("socks4://%s:%d", d.Host, d.Port)
	default:
		return "direct"
	}
}

// ParsePACResult parses the semicolon-delimited string returned by FindProxyForURL.
func ParsePACResult(result string) []ProxyDirective {
	var directives []ProxyDirective
	parts := strings.Split(result, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "DIRECT":
			directives = append(directives, ProxyDirective{Type: DirectiveDirect})
		case "PROXY", "HTTP":
			if len(fields) > 1 {
				h, p := parseHostPort(fields[1], 8080)
				directives = append(directives, ProxyDirective{Type: DirectiveHTTP, Host: h, Port: p})
			}
		case "HTTPS":
			if len(fields) > 1 {
				h, p := parseHostPort(fields[1], 8443)
				directives = append(directives, ProxyDirective{Type: DirectiveHTTPS, Host: h, Port: p})
			}
		case "SOCKS5":
			if len(fields) > 1 {
				h, p := parseHostPort(fields[1], 1080)
				directives = append(directives, ProxyDirective{Type: DirectiveSOCKS5, Host: h, Port: p})
			}
		case "SOCKS":
			if len(fields) > 1 {
				h, p := parseHostPort(fields[1], 1080)
				directives = append(directives, ProxyDirective{Type: DirectiveSOCKS4, Host: h, Port: p})
			}
		}
	}

	if len(directives) == 0 {
		directives = append(directives, ProxyDirective{Type: DirectiveDirect})
	}
	return directives
}

func parseHostPort(hp string, defaultPort int) (string, int) {
	hp = strings.TrimSpace(hp)
	host, portStr, err := net.SplitHostPort(hp)
	if err != nil {
		return hp, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return host, defaultPort
	}
	return host, port
}

// --- Standard PAC Helper Functions ---

// IsPlainHostName returns true if host contains no dots.
func IsPlainHostName(host string) bool {
	return !strings.Contains(host, ".")
}

// DNSDomainIs returns true if host ends with domain.
func DNSDomainIs(host, domain string) bool {
	return strings.HasSuffix(strings.ToLower(host), strings.ToLower(domain))
}

// LocalHostOrDomainIs returns true if host matches domain or prefix matches without dot.
func LocalHostOrDomainIs(host, hostdom string) bool {
	host = strings.ToLower(host)
	hostdom = strings.ToLower(hostdom)
	if host == hostdom {
		return true
	}
	idx := strings.Index(hostdom, ".")
	if idx != -1 && host == hostdom[:idx] {
		return true
	}
	return false
}

// LocalHostOrFQDN returns the host or fully qualified domain name.
func LocalHostOrFQDN(host string) string {
	return host
}

// IsResolvable returns true if the host can be resolved by DNS.
func IsResolvable(host string) bool {
	return DNSResolve(host) != ""
}

// IsInNet resolves or takes an IP address and matches against pattern and mask.
func IsInNet(ipStr, pattern, mask string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		resolved := DNSResolve(ipStr)
		if resolved == "" {
			return false
		}
		ip = net.ParseIP(resolved)
		if ip == nil {
			return false
		}
	}

	patIP := net.ParseIP(pattern)
	maskIP := net.ParseIP(mask)
	if patIP == nil || maskIP == nil {
		return false
	}

	ipv4 := ip.To4()
	pat4 := patIP.To4()
	mask4 := maskIP.To4()
	if ipv4 == nil || pat4 == nil || mask4 == nil {
		return false
	}

	for i := 0; i < 4; i++ {
		if (ipv4[i] & mask4[i]) != (pat4[i] & mask4[i]) {
			return false
		}
	}
	return true
}

// DNSResolve resolves a hostname to an IPv4 string.
func DNSResolve(host string) string {
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}
	return ips[0].String()
}

// MyIPAddress returns the client outbound IP.
func MyIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}

// DNSDomainLevels returns the number of dots in the hostname.
func DNSDomainLevels(host string) int {
	return strings.Count(host, ".")
}

var (
	shExpMu    sync.RWMutex
	shExpCache = make(map[string]*regexp.Regexp)
)

// ShExpMatch checks shell wildcard match (* and ?).
func ShExpMatch(str, shexp string) bool {
	matched, err := filepath.Match(strings.ToLower(shexp), strings.ToLower(str))
	if err == nil && matched {
		return true
	}

	pattern := strings.ToLower(shexp)
	shExpMu.RLock()
	re, ok := shExpCache[pattern]
	shExpMu.RUnlock()

	if !ok {
		regPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regPattern = strings.ReplaceAll(regPattern, `\*`, `.*`)
		regPattern = strings.ReplaceAll(regPattern, `\?`, `.`)
		var compErr error
		re, compErr = regexp.Compile("(?i)" + regPattern)
		if compErr != nil {
			return false
		}
		shExpMu.Lock()
		if len(shExpCache) < 1000 {
			shExpCache[pattern] = re
		}
		shExpMu.Unlock()
	}
	return re.MatchString(str)
}

// bindPACHelpers registers all standard PAC functions to the Goja VM global scope.
func bindPACHelpers(vm *goja.Runtime) {
	helpers := map[string]interface{}{
		"isPlainHostName":     IsPlainHostName,
		"isplainhostname":     IsPlainHostName,
		"dnsDomainIs":         DNSDomainIs,
		"dnsdomainis":         DNSDomainIs,
		"localHostOrDomainIs": LocalHostOrDomainIs,
		"localhostordomainis": LocalHostOrDomainIs,
		"localHostOrFQDN":     LocalHostOrFQDN,
		"localhostorfqdn":     LocalHostOrFQDN,
		"isResolvable":        IsResolvable,
		"isresolvable":        IsResolvable,
		"isInNet":             IsInNet,
		"isinnet":             IsInNet,
		"dnsResolve":          DNSResolve,
		"dnsresolve":          DNSResolve,
		"myIpAddress":         MyIPAddress,
		"myipaddress":         MyIPAddress,
		"dnsDomainLevels":     DNSDomainLevels,
		"dnsdomainlevels":     DNSDomainLevels,
		"shExpMatch":          ShExpMatch,
		"shexpmatch":          ShExpMatch,
		"alert": func(call goja.FunctionCall) goja.Value {
			return goja.Undefined()
		},
	}

	for name, fn := range helpers {
		_ = vm.Set(name, fn)
	}
}

// EvaluatePACScriptStrict evaluates a PAC script using Goja ECMAScript 5.1 runtime and returns typed errors.
func EvaluatePACScriptStrict(ctx context.Context, script string, targetURL string, host string) ([]ProxyDirective, error) {
	if strings.TrimSpace(script) == "" {
		return nil, ErrPACEmptyScript
	}

	if ctx == nil {
		ctx = context.Background()
	}

	evalCtx, cancel := context.WithTimeout(ctx, DefaultPACTimout)
	defer cancel()

	vm := goja.New()

	// Setup interrupt channel for timeout protection
	stopInterrupt := context.AfterFunc(evalCtx, func() {
		vm.Interrupt(evalCtx.Err())
	})
	defer stopInterrupt()

	// Bind standard PAC functions
	bindPACHelpers(vm)

	// Execute PAC script definitions
	_, err := vm.RunString(script)
	if err != nil {
		var intErr *goja.InterruptedError
		if errors.As(err, &intErr) {
			return nil, ErrPACExecutionTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrPACSyntaxError, err)
	}

	// Retrieve FindProxyForURL (or lowercase findProxyForURL)
	fnVal := vm.Get("FindProxyForURL")
	if fnVal == nil || goja.IsUndefined(fnVal) || goja.IsNull(fnVal) {
		fnVal = vm.Get("findProxyForURL")
	}

	findProxy, ok := goja.AssertFunction(fnVal)
	if !ok {
		return nil, ErrPACMissingFindProxy
	}

	// Invoke FindProxyForURL(url, host)
	res, err := findProxy(goja.Undefined(), vm.ToValue(targetURL), vm.ToValue(host))
	if err != nil {
		var intErr *goja.InterruptedError
		if errors.As(err, &intErr) {
			return nil, ErrPACExecutionTimeout
		}
		return nil, fmt.Errorf("%w: %v", ErrPACRuntimeError, err)
	}

	if res == nil || goja.IsUndefined(res) || goja.IsNull(res) {
		return []ProxyDirective{{Type: DirectiveDirect}}, nil
	}

	resultStr := res.String()
	return ParsePACResult(resultStr), nil
}

// EvaluatePACScript evaluates a PAC script with standard fail-open semantics:
// On empty scripts, syntax errors, missing FindProxyForURL, or execution timeouts,
// it safely falls back to DIRECT proxy directives without returning an error.
func EvaluatePACScript(ctx context.Context, script string, targetURL string, host string) ([]ProxyDirective, error) {
	dirs, err := EvaluatePACScriptStrict(ctx, script, targetURL, host)
	if err != nil {
		return []ProxyDirective{{Type: DirectiveDirect}}, nil
	}
	return dirs, nil
}

// EvaluatePAC is a convenience wrapper calling EvaluatePACScript with context.Background().
func EvaluatePAC(script string, targetURL string, host string) ([]ProxyDirective, error) {
	return EvaluatePACScript(context.Background(), script, targetURL, host)
}
