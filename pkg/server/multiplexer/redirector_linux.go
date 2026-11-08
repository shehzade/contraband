//go:build linux

package multiplexer

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/shehzade/contraband/pkg/common"
)

var ErrKernelRedirectorUnavailable = errors.New("kernel redirector requires root or cap_net_admin")

// LinuxKernelRedirector configures an isolated nftables PREROUTING
// redirect chain for full-spectrum 1–65535 redirection to a userspace port.
type LinuxKernelRedirector struct {
	logger     common.Logger
	targetPort int
	tableName  string
	chainName  string
	active     bool
}

// NewLinuxKernelRedirector constructs a redirector targeting a userspace port.
func NewLinuxKernelRedirector(targetPort int, logger common.Logger) *LinuxKernelRedirector {
	if logger == nil {
		logger = common.GetLogger()
	}
	return &LinuxKernelRedirector{
		logger:     logger,
		targetPort: targetPort,
		tableName:  "ctrb_nat",
		chainName:  "CTRB_PREROUTING",
	}
}

// Enable creates dedicated, isolated rules and logs status. Degrades gracefully if unprivileged.
func (k *LinuxKernelRedirector) Enable() error {
	// Verify nftables presence and root capabilities
	checkCmd := exec.Command("nft", "list", "tables")
	if out, err := checkCmd.CombinedOutput(); err != nil {
		k.logger.Warnf("Kernel redirector unavailable (%s); falling back to userspace multiplexer", strings.TrimSpace(string(out)))
		return ErrKernelRedirectorUnavailable
	}

	// Create dedicated table and chain without interfering with existing rules
	// Strict Port Safety Policy: exclude protected ports (22, 443, 4444-4449, 50050) from redirection
	setupCmds := [][]string{
		{"nft", "add", "table", "ip", k.tableName},
		{"nft", "add", "chain", "ip", k.tableName, k.chainName, "{ type nat hook prerouting priority dstnat; policy accept; }"},
		{"nft", "add", "rule", "ip", k.tableName, k.chainName, "tcp", "dport", "!=", "{", "22,", "443,", "4444-4449,", "50050", "}", "redirect", "to", ":" + strconv.Itoa(k.targetPort)},
		{"nft", "add", "rule", "ip", k.tableName, k.chainName, "udp", "dport", "!=", "{", "22,", "443,", "4444-4449,", "50050", "}", "redirect", "to", ":" + strconv.Itoa(k.targetPort)},
	}

	for _, args := range setupCmds {
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			k.logger.Warnf("Failed to setup nftables rule (%s); degrading gracefully to userspace", strings.TrimSpace(string(out)))
			_ = k.Disable()
			return ErrKernelRedirectorUnavailable
		}
	}

	k.active = true
	k.logger.Infof("Linux kernel redirector enabled: full-spectrum redirect active to port %d (protected ports 22, 443, 4444-4449, 50050 excluded)", k.targetPort)
	return nil
}

// Disable removes the isolated table without altering any other system chains.
func (k *LinuxKernelRedirector) Disable() error {
	if !k.active {
		return nil
	}
	cmd := exec.Command("nft", "delete", "table", "ip", k.tableName)
	_ = cmd.Run()
	k.active = false
	k.logger.Info("Linux kernel redirector disabled: isolated nftables chain removed")
	return nil
}
