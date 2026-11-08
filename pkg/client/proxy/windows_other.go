//go:build !windows

package proxy

// WindowsProxyConfig holds Windows-specific proxy settings.
type WindowsProxyConfig struct {
	AutoDetect    bool
	AutoConfigURL string
	Proxy         string
	ProxyBypass   string
}

// GetWindowsProxyConfig provides a POSIX fallback stub on non-Windows platforms.
func GetWindowsProxyConfig() (*WindowsProxyConfig, error) {
	return nil, nil
}
