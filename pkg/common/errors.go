package common

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// ClassifyError classifies any network, transport, application, or system error
// into the authoritative Verdict taxonomy:
// - BLOCKED_L4: Network-layer drops, timeouts, connection refused, unroutable paths, closed ports, EOF socket drops.
// - BLOCKED_L7: Protocol inspection drops, TLS handshake resets, HTTP 401/403/407, application rejections.
// - BLOCKED_DLP: Payload tampering, mid-stream truncation, or SHA-256 hash mismatch.
// - SUCCESS: nil error.
func ClassifyError(err error) Verdict {
	if err == nil {
		return VerdictSuccess
	}

	errStr := strings.ToLower(err.Error())

	// 1. Layer 4 Network / Port / Packet Filter Blocks, dial failures,
	// timeouts, and premature socket drops (including EOF, connection reset, unroutable paths).
	// Layer 4 transport drops MUST take precedence over higher-level protocol
	// handshake wrappers (e.g. uTLS, WebSocket handshake, SSH handshake, TLS timeouts)
	// which embed strings like "handshake" alongside EOF or timeout errors.
	var netErr net.Error
	if (errors.As(err, &netErr) && netErr.Timeout()) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		strings.Contains(errStr, "eof") ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ETIMEDOUT) ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "timed out") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "i/o timeout") ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		strings.Contains(errStr, "connection refused") ||
		errors.Is(err, syscall.ECONNRESET) ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "reset by peer") ||
		errors.Is(err, syscall.EPIPE) ||
		strings.Contains(errStr, "broken pipe") ||
		errors.Is(err, net.ErrClosed) ||
		strings.Contains(errStr, "closed network connection") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "connection was closed") ||
		strings.Contains(errStr, "server closed") ||
		strings.Contains(errStr, "transport connection broken") ||
		strings.Contains(errStr, "connection broken") ||
		errors.Is(err, syscall.ENETUNREACH) ||
		strings.Contains(errStr, "network is unreachable") ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "no such host") ||
		errors.Is(err, syscall.EPERM) ||
		strings.Contains(errStr, "operation not permitted") {
		return VerdictBlockedL4
	}

	// 2. DLP interception or cryptographic tampering
	if strings.Contains(errStr, "hash mismatch") ||
		strings.Contains(errStr, "dlp") ||
		strings.Contains(errStr, "tampering") ||
		strings.Contains(errStr, "content inspection") ||
		strings.Contains(errStr, "hash corruption") ||
		strings.Contains(errStr, "dpi") ||
		strings.Contains(errStr, "pattern drop") ||
		strings.Contains(errStr, "does not match expected hash") ||
		strings.Contains(errStr, "hash does not match") {
		return VerdictBlockedDLP
	}

	// 3. TLS protocol / certificate errors are Layer 7 protocol blocks
	// (Reached only if not an underlying Layer 4 transport drop/timeout)
	if strings.Contains(errStr, "tls:") ||
		strings.Contains(errStr, "x509:") ||
		strings.Contains(errStr, "handshake") ||
		strings.Contains(errStr, "bad certificate") ||
		strings.Contains(errStr, "certificate signed by unknown authority") {
		return VerdictBlockedL7
	}

	// 4. Explicit Layer 7 Application & Proxy Rejections
	if strings.Contains(errStr, "403 forbidden") ||
		strings.Contains(errStr, "407 proxy") ||
		strings.Contains(errStr, "401 unauthorized") ||
		strings.Contains(errStr, "forbidden") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "proxy auth") {
		return VerdictBlockedL7
	}

	// 5. Default fallback for application/payload level errors
	return VerdictBlockedL7
}
