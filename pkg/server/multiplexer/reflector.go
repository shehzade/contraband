package multiplexer

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
)

// ReflectionEngine emits authenticated JSON reflection banners and records ledger probes.
type ReflectionEngine struct {
	ledger server.Ledger
	logger common.Logger
}

// NewReflectionEngine constructs a ReflectionEngine.
func NewReflectionEngine(ledger server.Ledger, logger common.Logger) *ReflectionEngine {
	if logger == nil {
		logger = common.GetLogger()
	}
	return &ReflectionEngine{
		ledger: ledger,
		logger: logger,
	}
}

// ReflectTCP emits common.BannerReflection JSON to a connected TCP client.
func (r *ReflectionEngine) ReflectTCP(conn net.Conn, port int) error {
	remoteAddr := conn.RemoteAddr().String()
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr
	}

	sessionToken, err := common.NewSessionToken()
	if err != nil {
		sessionToken = common.SessionToken{0x01, 0x02, 0x03, 0x04}
	}
	sessionID := sessionToken.String()
	if len(sessionID) > 16 {
		sessionID = sessionID[:16]
	}

	bannerObj := common.BannerReflection{
		Status:   "OK",
		RemoteIP: clientIP,
		Port:     port,
		Proto:    "TCP",
		Session:  sessionID,
	}

	bannerBytes, err := json.Marshal(bannerObj)
	if err != nil {
		return fmt.Errorf("failed to marshal banner JSON: %w", err)
	}
	bannerBytes = append(bannerBytes, '\n')

	_ = conn.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
	n, writeErr := conn.Write(bannerBytes)

	// Record probe in Ledger if available
	if r.ledger != nil {
		now := time.Now().UTC()
		probeID, _ := common.GenerateUUIDv4()
		probe := common.ProbeResult{
			ID:        probeID,
			Timestamp: now,
			Timestamps: common.ForensicTimestamps{
				StartTCP:     now,
				ConnectedTCP: now,
				AckReceived:  now,
				TeardownDone: now,
			},
			Stage:       "sweep",
			Protocol:    "tcp_sweep",
			TargetPort:  port,
			TargetHost:  conn.LocalAddr().String(),
			LocalAddr:   remoteAddr,
			BytesSent:   int64(n),
			BytesRecv:   0,
			Verdict:     common.VerdictSuccess,
			RawEvidence: string(bannerBytes),
		}
		_ = r.ledger.RecordProbe(probe)
	}

	return writeErr
}

// ReflectUDP emits common.BannerReflection JSON to a UDP probe client.
func (r *ReflectionEngine) ReflectUDP(pc net.PacketConn, rAddr net.Addr, port int, data []byte) error {
	remoteAddr := rAddr.String()
	clientIP, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		clientIP = remoteAddr
	}

	sessionToken, err := common.NewSessionToken()
	if err != nil {
		sessionToken = common.SessionToken{0x01, 0x02, 0x03, 0x04}
	}
	sessionID := sessionToken.String()
	if len(sessionID) > 16 {
		sessionID = sessionID[:16]
	}

	bannerObj := common.BannerReflection{
		Status:   "OK",
		RemoteIP: clientIP,
		Port:     port,
		Proto:    "UDP",
		Session:  sessionID,
	}

	bannerBytes, err := json.Marshal(bannerObj)
	if err != nil {
		return fmt.Errorf("failed to marshal banner JSON: %w", err)
	}
	bannerBytes = append(bannerBytes, '\n')

	n, writeErr := pc.WriteTo(bannerBytes, rAddr)

	// Record probe in Ledger if available
	if r.ledger != nil {
		now := time.Now().UTC()
		probeID, _ := common.GenerateUUIDv4()
		probe := common.ProbeResult{
			ID:        probeID,
			Timestamp: now,
			Timestamps: common.ForensicTimestamps{
				StartTCP:     now,
				ConnectedTCP: now,
				AckReceived:  now,
				TeardownDone: now,
			},
			Stage:       "sweep",
			Protocol:    "udp_sweep",
			TargetPort:  port,
			TargetHost:  pc.LocalAddr().String(),
			LocalAddr:   remoteAddr,
			BytesSent:   int64(n),
			BytesRecv:   int64(len(data)),
			Verdict:     common.VerdictSuccess,
			RawEvidence: string(bannerBytes),
		}
		_ = r.ledger.RecordProbe(probe)
	}

	return writeErr
}
