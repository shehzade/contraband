//go:build windows

package proxy

import (
	"golang.org/x/sys/windows/registry"
)

// WindowsProxyConfig holds Windows-specific proxy settings.
type WindowsProxyConfig struct {
	AutoDetect    bool
	AutoConfigURL string
	Proxy         string
	ProxyBypass   string
}

// GetWindowsProxyConfig retrieves Windows proxy configuration from HKCU Internet Settings registry.
func GetWindowsProxyConfig() (*WindowsProxyConfig, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	cfg := &WindowsProxyConfig{}
	if enable, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && enable == 1 {
		if server, _, err := k.GetStringValue("ProxyServer"); err == nil {
			cfg.Proxy = server
		}
		if bypass, _, err := k.GetStringValue("ProxyOverride"); err == nil {
			cfg.ProxyBypass = bypass
		}
	}
	if autoConfig, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		cfg.AutoConfigURL = autoConfig
	}

	return cfg, nil
}
