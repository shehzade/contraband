package multiplexer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
)

// PortBindStatus categorizes the binding outcome of an individual port.
type PortBindStatus string

const (
	PortStatusBound            PortBindStatus = "BOUND"
	PortStatusOccupiedSkipped  PortBindStatus = "OCCUPIED_SKIPPED"
	PortStatusPermissionDenied PortBindStatus = "PERMISSION_DENIED"
	PortStatusFailed           PortBindStatus = "FAILED"
	PortStatusClosed           PortBindStatus = "CLOSED"
)

// ProbeType indicates the classification of an incoming connection.
type ProbeType string

const (
	ProbeTypeSweep     ProbeType = "SWEEP_PROBE"
	ProbeTypeSmuggling ProbeType = "SMUGGLING_SESSION"
	ProbeTypeUnknown   ProbeType = "UNKNOWN"
)

// MultiplexerConfig defines runtime parameters for the multi-port reflector.
type MultiplexerConfig struct {
	BindIP        string        `json:"bind_ip"`        // e.g. "0.0.0.0" or "127.0.0.1"
	Ports         string        `json:"ports"`          // "quick", "standard", "full", or "80,443,8000-8100"
	EnableTCP     bool          `json:"enable_tcp"`     // Enable TCP listeners (default: true)
	EnableUDP     bool          `json:"enable_udp"`     // Enable UDP listeners (default: true)
	EnableEBPF    bool          `json:"enable_ebpf"`    // Attempt Linux eBPF/nftables full redirection
	PeekTimeout   time.Duration `json:"peek_timeout"`   // TCP initial byte read deadline (default: 100ms)
	SocketTimeout time.Duration `json:"socket_timeout"` // Inactive connection teardown deadline (default: 3s)
}

// PortReport summarizes binding state across the requested port matrix.
type PortReport struct {
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"` // "TCP" or "UDP"
	Status   PortBindStatus `json:"status"`
	Error    string         `json:"error,omitempty"`
}

// MultiplexerMetrics provides live observability counters.
type MultiplexerMetrics struct {
	RequestedPorts int   `json:"requested_ports"`
	BoundTCP       int   `json:"bound_tcp"`
	BoundUDP       int   `json:"bound_udp"`
	SkippedPorts   int   `json:"skipped_ports"`
	ReflectedTCP   int64 `json:"reflected_tcp"`
	ReflectedUDP   int64 `json:"reflected_udp"`
	DemuxSmuggling int64 `json:"demux_smuggling"`
}

// DemuxHandler defines the callback invoked when an incoming connection
// carries a data smuggling payload instead of a sweep probe.
type DemuxHandler = server.DemuxHandler

// PortListener represents an active multiplexer port listener.
type PortListener struct {
	Port     int
	Protocol string
	Status   PortBindStatus
	TCP      net.Listener
	UDP      net.PacketConn
}

// Multiplexer defines the master interface for multi-port reflection.
type Multiplexer interface {
	Start(ctx context.Context) error
	Shutdown(ctx context.Context) error
	GetPortReports() []PortReport
	GetMetrics() MultiplexerMetrics
	RegisterDemuxHandler(magic uint32, handler DemuxHandler)
	GetPortListeners() []PortListener
}

// UserspaceMultiplexer manages concurrent TCP net.Listener and UDP net.PacketConn instances.
type UserspaceMultiplexer struct {
	mu        sync.RWMutex
	config    MultiplexerConfig
	ledger    server.Ledger
	logger    common.Logger
	safety     *SafetyChecker
	reflector  *ReflectionEngine
	demuxer    *HeaderDemuxer
	redirector *LinuxKernelRedirector

	tcpListeners  map[int]net.Listener
	udpConns      map[int]net.PacketConn
	portReports   map[string]PortReport // "port/proto" -> PortReport
	demuxHandlers map[uint32]DemuxHandler

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running atomic.Bool

	// Atomic telemetry counters
	reflectedTCP   atomic.Int64
	reflectedUDP   atomic.Int64
	demuxSmuggling atomic.Int64
}

// NewUserspaceMultiplexer constructs a production-grade multiplexer instance.
func NewUserspaceMultiplexer(cfg MultiplexerConfig, ledger server.Ledger, logger common.Logger) (*UserspaceMultiplexer, error) {
	if cfg.BindIP == "" {
		cfg.BindIP = common.DefaultServerBind
	}
	if cfg.PeekTimeout <= 0 {
		cfg.PeekTimeout = 100 * time.Millisecond
	}
	if cfg.SocketTimeout <= 0 {
		cfg.SocketTimeout = 3 * time.Second
	}
	if logger == nil {
		logger = common.GetLogger()
	}

	safety := NewSafetyChecker(logger)
	reflector := NewReflectionEngine(ledger, logger)
	demuxer := NewHeaderDemuxer(cfg.PeekTimeout)

	return &UserspaceMultiplexer{
		config:        cfg,
		ledger:        ledger,
		logger:        logger,
		safety:        safety,
		reflector:     reflector,
		demuxer:       demuxer,
		tcpListeners:  make(map[int]net.Listener),
		udpConns:      make(map[int]net.PacketConn),
		portReports:   make(map[string]PortReport),
		demuxHandlers: make(map[uint32]DemuxHandler),
	}, nil
}

// Start parses port presets, executes safe binding, and spawns worker loops.
func (u *UserspaceMultiplexer) Start(ctx context.Context) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.running.Load() {
		return fmt.Errorf("multiplexer already running")
	}

	ports, err := common.ParsePortsField(u.config.Ports)
	if err != nil {
		return fmt.Errorf("failed to parse ports %q: %w", u.config.Ports, err)
	}

	u.ctx, u.cancel = context.WithCancel(ctx)
	u.running.Store(true)

	boundTCP := 0
	boundUDP := 0
	skipped := 0

	// 1. Bind TCP Listeners
	if u.config.EnableTCP {
		for _, port := range ports {
			ln, status, err := u.safety.SafeListenTCP(u.config.BindIP, port)
			key := fmt.Sprintf("%d/TCP", port)
			if err != nil {
				u.portReports[key] = PortReport{Port: port, Protocol: "TCP", Status: status, Error: err.Error()}
				continue
			}
			u.portReports[key] = PortReport{Port: port, Protocol: "TCP", Status: status}
			if status == PortStatusBound {
				u.tcpListeners[port] = ln
				boundTCP++
				u.wg.Add(1)
				go u.tcpAcceptLoop(ln, port)
			} else {
				skipped++
			}
		}
	}

	// 2. Bind UDP Packet Connections
	if u.config.EnableUDP {
		for _, port := range ports {
			pc, status, err := u.safety.SafeListenUDP(u.config.BindIP, port)
			key := fmt.Sprintf("%d/UDP", port)
			if err != nil {
				u.portReports[key] = PortReport{Port: port, Protocol: "UDP", Status: status, Error: err.Error()}
				continue
			}
			u.portReports[key] = PortReport{Port: port, Protocol: "UDP", Status: status}
			if status == PortStatusBound {
				u.udpConns[port] = pc
				boundUDP++
				u.wg.Add(1)
				go u.udpReadLoop(pc, port)
			} else {
				skipped++
			}
		}
	}

	// 3. Optional Linux Kernel Redirection (eBPF / nftables)
	if u.config.EnableEBPF {
		targetPort := SelectTargetPort(ports)
		u.redirector = NewLinuxKernelRedirector(targetPort, u.logger)
		if err := u.redirector.Enable(); err != nil {
			u.logger.Warnf("Kernel redirector initialization skipped (%v); operating in pure userspace multiplexer mode", err)
		}
	}

	u.logger.Infof("Multiplexer active: bound %d TCP and %d UDP listeners (%d occupied/privileged ports skipped safely)",
		boundTCP, boundUDP, skipped)

	return nil
}

// SelectTargetPort selects the first non-protected port from candidate ports.
// If all candidate ports are protected or candidate list is empty, it returns default fallback port 8080.
func SelectTargetPort(ports []int) int {
	for _, p := range ports {
		if !IsProtectedPort(p) {
			return p
		}
	}
	return 8080
}

// tcpAcceptLoop handles incoming TCP connections on a designated port.
func (u *UserspaceMultiplexer) tcpAcceptLoop(ln net.Listener, port int) {
	defer u.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-u.ctx.Done():
				return
			default:
				// Listener closed or transient error
				return
			}
		}

		u.wg.Add(1)
		go func(c net.Conn) {
			defer u.wg.Done()
			u.handleTCPConn(c, port)
		}(conn)
	}
}

// handleTCPConn classifies connection via peeking and executes reflection or demux.
func (u *UserspaceMultiplexer) handleTCPConn(conn net.Conn, port int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.config.SocketTimeout))

	probeType, peeked, err := u.demuxer.Demux(conn)
	if err != nil && probeType == ProbeTypeUnknown {
		return
	}

	switch probeType {
	case ProbeTypeSmuggling:
		u.demuxSmuggling.Add(1)
		if len(peeked) >= 4 {
			magic := binary.BigEndian.Uint32(peeked[0:4])
			u.mu.RLock()
			handler, exists := u.demuxHandlers[magic]
			u.mu.RUnlock()
			if exists {
				_ = handler(conn, peeked, port)
				return
			}
		}
		// If no dedicated smuggling handler registered, emit reflection fallback
		_ = u.reflector.ReflectTCP(conn, port)
		u.reflectedTCP.Add(1)

	case ProbeTypeSweep, ProbeTypeUnknown:
		_ = u.reflector.ReflectTCP(conn, port)
		u.reflectedTCP.Add(1)
	}
}

// udpReadLoop reads incoming datagrams on a designated UDP port.
func (u *UserspaceMultiplexer) udpReadLoop(pc net.PacketConn, port int) {
	defer u.wg.Done()
	buf := make([]byte, 4096)

	for {
		n, rAddr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-u.ctx.Done():
				return
			default:
				return
			}
		}

		if n > 0 {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			u.wg.Add(1)
			go func(data []byte, addr net.Addr) {
				defer u.wg.Done()
				_ = u.reflector.ReflectUDP(pc, addr, port, data)
				u.reflectedUDP.Add(1)
			}(pkt, rAddr)
		}
	}
}

// Shutdown gracefully stops all listeners and waits for in-flight workers.
func (u *UserspaceMultiplexer) Shutdown(ctx context.Context) error {
	if !u.running.CompareAndSwap(true, false) {
		return nil
	}

	u.mu.Lock()
	if u.redirector != nil {
		_ = u.redirector.Disable()
	}
	if u.cancel != nil {
		u.cancel()
	}

	for port, ln := range u.tcpListeners {
		_ = ln.Close()
		key := fmt.Sprintf("%d/TCP", port)
		if rep, ok := u.portReports[key]; ok {
			rep.Status = PortStatusClosed
			u.portReports[key] = rep
		}
	}
	for port, pc := range u.udpConns {
		_ = pc.Close()
		key := fmt.Sprintf("%d/UDP", port)
		if rep, ok := u.portReports[key]; ok {
			rep.Status = PortStatusClosed
			u.portReports[key] = rep
		}
	}
	u.mu.Unlock()

	// Wait for goroutines with context timeout
	done := make(chan struct{})
	go func() {
		u.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		u.logger.Info("Multiplexer shutdown complete: all sockets closed cleanly")
		return nil
	case <-ctx.Done():
		return fmt.Errorf("multiplexer shutdown timed out: %w", ctx.Err())
	}
}

// RegisterDemuxHandler binds a magic-prefixed handler for data smuggling sessions.
func (u *UserspaceMultiplexer) RegisterDemuxHandler(magic uint32, handler DemuxHandler) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.demuxHandlers[magic] = handler
}

// GetPortReports returns a snapshot of port binding states.
func (u *UserspaceMultiplexer) GetPortReports() []PortReport {
	u.mu.RLock()
	defer u.mu.RUnlock()
	reports := make([]PortReport, 0, len(u.portReports))
	for _, r := range u.portReports {
		reports = append(reports, r)
	}
	return reports
}

// GetPortListeners returns a list of active port listeners.
func (u *UserspaceMultiplexer) GetPortListeners() []PortListener {
	u.mu.RLock()
	defer u.mu.RUnlock()
	listeners := make([]PortListener, 0)
	for port, ln := range u.tcpListeners {
		listeners = append(listeners, PortListener{
			Port:     port,
			Protocol: "TCP",
			Status:   PortStatusBound,
			TCP:      ln,
		})
	}
	for port, pc := range u.udpConns {
		listeners = append(listeners, PortListener{
			Port:     port,
			Protocol: "UDP",
			Status:   PortStatusBound,
			UDP:      pc,
		})
	}
	return listeners
}

// GetMetrics returns real-time reflection and demux counts.
func (u *UserspaceMultiplexer) GetMetrics() MultiplexerMetrics {
	u.mu.RLock()
	defer u.mu.RUnlock()
	skipped := 0
	for _, rep := range u.portReports {
		if rep.Status == PortStatusOccupiedSkipped || rep.Status == PortStatusPermissionDenied {
			skipped++
		}
	}
	return MultiplexerMetrics{
		RequestedPorts: len(u.portReports),
		BoundTCP:       len(u.tcpListeners),
		BoundUDP:       len(u.udpConns),
		SkippedPorts:   skipped,
		ReflectedTCP:   u.reflectedTCP.Load(),
		ReflectedUDP:   u.reflectedUDP.Load(),
		DemuxSmuggling: u.demuxSmuggling.Load(),
	}
}
