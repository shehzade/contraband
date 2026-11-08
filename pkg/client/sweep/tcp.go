package sweep

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// ProbeTCP performs an egress probe against targetHost:port using TCP.
func ProbeTCP(ctx context.Context, targetHost string, port int, timeout time.Duration, requireReflection bool) common.ProbeResult {
	res, err := common.NewProbeResult("sweep", "tcp", targetHost, port)
	if err != nil {
		return common.ProbeResult{
			Timestamp:    time.Now().UTC(),
			Stage:        "sweep",
			Protocol:     "tcp",
			TargetHost:   targetHost,
			TargetPort:   port,
			Verdict:      common.VerdictBlockedL4,
			ErrorMessage: fmt.Sprintf("failed to initialize probe: %v", err),
		}
	}

	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(port))
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: -1, // Disable keepalive for ephemeral sweep sockets
	}

	start := time.Now().UTC()
	res.Timestamps.StartTCP = start

	conn, dialErr := dialer.DialContext(ctx, "tcp", targetAddr)
	if dialErr != nil {
		teardown := time.Now().UTC()
		res.Timestamps.TeardownDone = teardown
		res.Timestamps.ComputeDurations()

		if ctx.Err() != nil {
			res.Verdict = common.VerdictBlockedL4
			res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
			return res
		}

		classifyTCPDialError(dialErr, &res)
		return res
	}

	connected := time.Now().UTC()
	res.Timestamps.ConnectedTCP = connected
	res.LocalAddr = conn.LocalAddr().String()

	// Fail fast if context was canceled immediately after dialing
	if ctx.Err() != nil {
		_ = conn.Close()
		teardown := time.Now().UTC()
		res.Timestamps.TeardownDone = teardown
		res.Timestamps.ComputeDurations()
		res.Verdict = common.VerdictBlockedL4
		res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
		return res
	}

	// Set deadline for reflection banner read
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

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

	reader := bufio.NewReaderSize(conn, 4096)
	bannerLine, readErr := reader.ReadBytes('\n')
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

		if errors.Is(readErr, io.EOF) || strings.Contains(readErr.Error(), "connection reset") {
			res.Verdict = common.VerdictBlockedL7
			res.ErrorMessage = fmt.Sprintf("L7_RESET: connection established but reset before banner: %v", readErr)
			return res
		}
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			if requireReflection {
				res.Verdict = common.VerdictBlockedL7
				res.ErrorMessage = fmt.Sprintf("L7_TIMEOUT: TCP connected but no reflection banner within %v", timeout)
			} else {
				// Pure TCP connect mode: handshake established
				res.Verdict = common.VerdictSuccess
			}
			return res
		}
		res.Verdict = common.VerdictBlockedL7
		res.ErrorMessage = fmt.Sprintf("L7_READ_ERROR: %v", readErr)
		return res
	}

	if ctx.Err() != nil {
		res.Verdict = common.VerdictBlockedL4
		res.ErrorMessage = fmt.Sprintf("L4_CANCELED: %v", ctx.Err())
		return res
	}

	res.BytesRecv = int64(len(bannerLine))
	rawStr := strings.TrimSpace(string(bannerLine))
	res.RawEvidence = rawStr

	// Parse JSON reflection banner
	var banner common.BannerReflection
	if err := json.Unmarshal([]byte(rawStr), &banner); err != nil {
		if requireReflection {
			res.Verdict = common.VerdictBlockedL7
			res.ErrorMessage = fmt.Sprintf("L7_BANNER_INVALID: non-JSON response received: %v", err)
		} else {
			res.Verdict = common.VerdictSuccess
			res.ErrorMessage = "FOREIGN_SERVICE: valid TCP connection established with non-reflection service"
		}
		return res
	}

	if banner.Status != "OK" || banner.Port != port || !strings.EqualFold(banner.Proto, "TCP") {
		if requireReflection {
			res.Verdict = common.VerdictBlockedL7
			res.ErrorMessage = fmt.Sprintf("L7_BANNER_MISMATCH: status=%s port=%d (expected %d) proto=%s", banner.Status, banner.Port, port, banner.Proto)
		} else {
			res.Verdict = common.VerdictSuccess
			res.ErrorMessage = "FOREIGN_SERVICE: valid TCP connection established with non-reflection service"
		}
		return res
	}

	// Verified Bidirectional Egress
	res.Verdict = common.VerdictSuccess
	if banner.RemoteIP != "" {
		res.LocalAddr = banner.RemoteIP // Record server-observed public IP
	}
	return res
}

func classifyTCPDialError(err error, res *common.ProbeResult) {
	res.Verdict = common.VerdictBlockedL4
	errStr := err.Error()

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		res.ErrorMessage = fmt.Sprintf("L4_FILTERED: connection timed out (%v)", err)
		return
	}
	if strings.Contains(errStr, "connection reset") {
		res.Verdict = common.VerdictBlockedL7
		res.ErrorMessage = fmt.Sprintf("L7_RESET: connection established but reset before banner: %v", err)
		return
	}
	if strings.Contains(errStr, "connection refused") {
		res.ErrorMessage = fmt.Sprintf("L4_CLOSED: connection refused (%v)", err)
		return
	}
	if strings.Contains(errStr, "network is unreachable") || strings.Contains(errStr, "no route to host") {
		res.ErrorMessage = fmt.Sprintf("L4_UNREACHABLE: %v", err)
		return
	}
	res.ErrorMessage = fmt.Sprintf("L4_DIAL_ERROR: %v", err)
}
