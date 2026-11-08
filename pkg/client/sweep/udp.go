package sweep

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ProbeUDP performs an egress probe against targetHost:port using stateful UDP probes.
func ProbeUDP(ctx context.Context, targetHost string, port int, timeout time.Duration, requireReflection bool) common.ProbeResult {
	res, err := common.NewProbeResult("sweep", "udp", targetHost, port)
	if err != nil {
		return common.ProbeResult{
			Timestamp:    time.Now().UTC(),
			Stage:        "sweep",
			Protocol:     "udp",
			TargetHost:   targetHost,
			TargetPort:   port,
			Verdict:      common.VerdictBlockedL4,
			ErrorMessage: fmt.Sprintf("failed to initialize probe: %v", err),
		}
	}

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	start := time.Now().UTC()
	res.Timestamps.StartTCP = start
	res.Timestamps.ConnectedTCP = start

	// Connected UDP socket enables ICMP Port Unreachable detection
	conn, dialErr := dialer.DialContext(ctx, "udp", targetAddr)
	if dialErr != nil {
		teardown := time.Now().UTC()
		res.Timestamps.TeardownDone = teardown
		res.Timestamps.ComputeDurations()

		if ctx.Err() != nil {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
			return res
		}

		res.Verdict = common.VerdictBlockedL4
		res.ErrorMessage = fmt.Sprintf("L4_DIAL_ERROR: %v", dialErr)
		return res
	}

	res.LocalAddr = conn.LocalAddr().String()

	// Select port-specific probe packet
	probeBytes := BuildProbeForPort(port)
	res.BytesSent = int64(len(probeBytes))

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Ensure context cancellation interrupts any blocking I/O immediately
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	firstByte := time.Now().UTC()
	res.Timestamps.FirstByteSent = firstByte

	_, writeErr := conn.Write(probeBytes)
	if writeErr != nil {
		_ = conn.Close()
		teardown := time.Now().UTC()
		res.Timestamps.TeardownDone = teardown
		res.Timestamps.ComputeDurations()

		if ctx.Err() != nil {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
			return res
		}

		res.Verdict = common.VerdictBlockedL4
		res.ErrorMessage = fmt.Sprintf("L4_WRITE_ERROR: %v", writeErr)
		return res
	}

	buf := make([]byte, 4096)
	n, readErr := conn.Read(buf)
	ack := time.Now().UTC()
	res.Timestamps.AckReceived = ack

	_ = conn.Close()
	teardown := time.Now().UTC()
	res.Timestamps.TeardownDone = teardown
	res.Timestamps.ComputeDurations()

	if readErr != nil {
		if ctx.Err() != nil {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
			return res
		}

		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_TIMEOUT: no response within %v (filtered or dropped)", timeout)
			return res
		}

		errStr := readErr.Error()
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "ECONNREFUSED") {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_CLOSED: ICMP port unreachable (%v)", readErr)
			return res
		}

		res.Verdict = common.VerdictBlockedL4
		res.ErrorMessage = fmt.Sprintf("L4_READ_ERROR: %v", readErr)
		return res
	}

	res.BytesRecv = int64(n)
	rawResp := buf[:n]

	// Try parsing JSON reflection banner
	var banner common.BannerReflection
	if err := json.Unmarshal(rawResp, &banner); err == nil {
		if banner.Status == "OK" && banner.Port == port && strings.EqualFold(banner.Proto, "UDP") {
			res.Verdict = common.VerdictSuccess
			res.RawEvidence = string(rawResp)
			if banner.RemoteIP != "" {
				res.LocalAddr = banner.RemoteIP
			}
			return res
		}
		if requireReflection {
			res.Verdict = common.VerdictBlockedL7
			res.ErrorMessage = fmt.Sprintf("L7_BANNER_INVALID: reflection banner mismatch: status=%s port=%d (expected %d) proto=%s", banner.Status, banner.Port, port, banner.Proto)
			res.RawEvidence = string(rawResp)
			return res
		}
	}

	// Validate protocol response if reflection JSON was not returned
	if isProtocolResponseValid(port, rawResp) {
		res.Verdict = common.VerdictSuccess
		res.RawEvidence = hex.EncodeToString(rawResp)
		return res
	}

	if requireReflection {
		res.Verdict = common.VerdictBlockedL7
		res.ErrorMessage = "L7_BANNER_INVALID: UDP response received but not valid Contraband banner"
		res.RawEvidence = hex.EncodeToString(rawResp)
		return res
	}

	res.Verdict = common.VerdictSuccess
	res.RawEvidence = hex.EncodeToString(rawResp)
	return res
}

func isProtocolResponseValid(port int, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	switch port {
	case 53:
		// DNS response must have at least 12 bytes and QR bit (bit 7 of byte 2) set
		return len(data) >= 12 && (data[2]&0x80) != 0
	case 123:
		// NTP response must be 48 bytes and Mode must be 4 (server) or 5 (broadcast)
		return len(data) >= 48 && ((data[0]&0x07) == 4 || (data[0]&0x07) == 5)
	case 161:
		// SNMP response must start with SEQUENCE (0x30)
		return len(data) >= 10 && data[0] == 0x30
	default:
		// Echo response of generic probe
		return strings.Contains(string(data), "CTRB_UDP_PROBE")
	}
}
