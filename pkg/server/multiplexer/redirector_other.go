//go:build !linux

package multiplexer

import (
	"errors"

	"github.com/shehzade/contraband/pkg/common"
)

var ErrKernelRedirectorUnavailable = errors.New("kernel redirector only supported on linux")

// LinuxKernelRedirector stub for Windows and macOS cross-compilation.
type LinuxKernelRedirector struct {
	logger common.Logger
}

// NewLinuxKernelRedirector constructs a stub redirector on non-Linux platforms.
func NewLinuxKernelRedirector(targetPort int, logger common.Logger) *LinuxKernelRedirector {
	if logger == nil {
		logger = common.GetLogger()
	}
	return &LinuxKernelRedirector{logger: logger}
}

// Enable returns an error indicating kernel redirection is only supported on Linux.
func (k *LinuxKernelRedirector) Enable() error {
	k.logger.Info("Kernel redirector not supported on non-Linux OS; using userspace multiplexer")
	return ErrKernelRedirectorUnavailable
}

// Disable is a no-op on non-Linux platforms.
func (k *LinuxKernelRedirector) Disable() error {
	return nil
}
