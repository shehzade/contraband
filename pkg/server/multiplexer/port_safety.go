package multiplexer

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ProtectedPorts defines the strict non-interference port safety policy.
// These operational ports are strictly excluded from redirection, interception,
// and multiplexer binding to guarantee non-interference with critical services
// (e.g., Cobalt Strike TeamServer PID 8842, HTTPS/Web, C2 listeners, and SSH management).
var ProtectedPorts = map[int]string{
	22:    "SSH Management",
	443:   "HTTPS / TeamServer Web",
	4444:  "C2 Listener",
	4445:  "C2 Listener",
	4446:  "C2 Listener",
	4447:  "C2 Listener",
	4448:  "C2 Listener",
	4449:  "C2 Listener",
	50050: "Cobalt Strike TeamServer",
}

// IsProtectedPort reports whether a given port is protected from multiplexer binding or redirection.
func IsProtectedPort(port int) bool {
	_, protected := ProtectedPorts[port]
	return protected
}

// IsPortOccupied probes whether another process is actively listening on target port on 127.0.0.1.
// Strictly non-interfering: uses non-blocking dial with 20ms timeout for TCP.
// Protected operational ports (22, 443, 4444-4449, 50050) always report occupied to guarantee non-interference.
func IsPortOccupied(proto string, port int) bool {
	if IsProtectedPort(port) {
		return true
	}
	if strings.EqualFold(proto, "tcp") {
		target := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", target, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	} else if strings.EqualFold(proto, "udp") {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") {
				return true
			}
		} else {
			_ = pc.Close()
			return false
		}
	}
	return false
}

// SafetyChecker evaluates local port availability without service disruption.
type SafetyChecker struct {
	logger common.Logger
}

// NewSafetyChecker constructs a new safety pre-checker.
func NewSafetyChecker(logger common.Logger) *SafetyChecker {
	if logger == nil {
		logger = common.GetLogger()
	}
	return &SafetyChecker{logger: logger}
}

// IsPortOccupied probes whether another process is actively listening on target port.
func (s *SafetyChecker) IsPortOccupied(proto string, port int) bool {
	return IsPortOccupied(proto, port)
}

// IsPortOccupiedOn checks if port is occupied on a specific bind IP.
func (s *SafetyChecker) IsPortOccupiedOn(network, bindIP string, port int) bool {
	if IsProtectedPort(port) {
		return true
	}
	if strings.EqualFold(network, "tcp") {
		targetHost := bindIP
		if targetHost == "" || targetHost == "0.0.0.0" {
			targetHost = "127.0.0.1"
		}
		target := net.JoinHostPort(targetHost, strconv.Itoa(port))
		conn, err := net.DialTimeout("tcp", target, 20*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	} else if strings.EqualFold(network, "udp") {
		targetHost := bindIP
		if targetHost == "" || targetHost == "0.0.0.0" {
			targetHost = "127.0.0.1"
		}
		addr := net.JoinHostPort(targetHost, strconv.Itoa(port))
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") {
				return true
			}
		} else {
			_ = pc.Close()
			return false
		}
	}
	return false
}

// SafeListenTCP attempts to bind a TCP listener. If the port is already bound
// by an existing system service, requires root privileges, or is on the strict
// protected ports list, it gracefully skips without failing or disrupting existing infrastructure.
func (s *SafetyChecker) SafeListenTCP(bindIP string, port int) (net.Listener, PortBindStatus, error) {
	// Strict Port Safety Policy: protect operational ports (22, 443, 4444-4449, 50050)
	if IsProtectedPort(port) {
		s.logger.Warnf("Port %d/TCP is a strictly protected operational port (%s); skipping gracefully without disruption (operational safety rule)", port, ProtectedPorts[port])
		return nil, PortStatusOccupiedSkipped, nil
	}

	addr := net.JoinHostPort(bindIP, strconv.Itoa(port))

	// Pre-check occupancy
	if s.IsPortOccupiedOn("tcp", bindIP, port) {
		s.logger.Warnf("Port %d/TCP is occupied by an existing system service; skipping gracefully without disruption (operational safety rule)", port)
		return nil, PortStatusOccupiedSkipped, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") {
			s.logger.Warnf("Port %d/TCP in use (EADDRINUSE); skipping gracefully without disruption", port)
			return nil, PortStatusOccupiedSkipped, nil
		}
		if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "permission denied") {
			s.logger.Warnf("Port %d/TCP requires elevated privileges (cap_net_bind_service); skipping gracefully", port)
			return nil, PortStatusPermissionDenied, nil
		}
		return nil, PortStatusFailed, fmt.Errorf("failed to bind TCP port %d: %w", port, err)
	}

	return ln, PortStatusBound, nil
}

// SafeListenUDP attempts to bind a UDP packet connection. Handles EADDRINUSE,
// EACCES, and protected ports gracefully.
func (s *SafetyChecker) SafeListenUDP(bindIP string, port int) (net.PacketConn, PortBindStatus, error) {
	// Strict Port Safety Policy: protect operational ports (22, 443, 4444-4449, 50050)
	if IsProtectedPort(port) {
		s.logger.Warnf("Port %d/UDP is a strictly protected operational port (%s); skipping gracefully without disruption (operational safety rule)", port, ProtectedPorts[port])
		return nil, PortStatusOccupiedSkipped, nil
	}

	addr := net.JoinHostPort(bindIP, strconv.Itoa(port))

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use") {
			s.logger.Warnf("Port %d/UDP in use (EADDRINUSE); skipping gracefully without disruption", port)
			return nil, PortStatusOccupiedSkipped, nil
		}
		if errors.Is(err, syscall.EACCES) || strings.Contains(err.Error(), "permission denied") {
			s.logger.Warnf("Port %d/UDP requires elevated privileges (cap_net_bind_service); skipping gracefully", port)
			return nil, PortStatusPermissionDenied, nil
		}
		return nil, PortStatusFailed, fmt.Errorf("failed to bind UDP port %d: %w", port, err)
	}

	return pc, PortStatusBound, nil
}
