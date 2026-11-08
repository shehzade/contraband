package traffic

import (
	"context"
	"io"
	"net"
)

// PacedReader wraps an io.Reader and throttles read throughput using RateLimiter.
type PacedReader struct {
	r        io.Reader
	limiter  RateLimiter
	metrics  *TrafficMetrics
	ctx      context.Context
	maxChunk int // Maximum chunk read slice (default 32KB)
}

// NewPacedReader creates a bandwidth-limited io.Reader.
func NewPacedReader(ctx context.Context, r io.Reader, limiter RateLimiter, metrics *TrafficMetrics) *PacedReader {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PacedReader{
		r:        r,
		limiter:  limiter,
		metrics:  metrics,
		ctx:      ctx,
		maxChunk: 32 * 1024, // 32KB chunks prevent huge instantaneous reads
	}
}

// Read implements io.Reader, consuming tokens and pacing stream flow.
func (pr *PacedReader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	sliceSize := len(p)
	if pr.maxChunk > 0 && sliceSize > pr.maxChunk {
		sliceSize = pr.maxChunk
	}

	// 1. Wait for bandwidth rate limiter tokens
	if err := pr.limiter.WaitN(pr.ctx, sliceSize); err != nil {
		return 0, err
	}

	// 2. Read from underlying source
	n, err = pr.r.Read(p[:sliceSize])

	// 3. Record metrics
	if n > 0 && pr.metrics != nil {
		pr.metrics.RecordBytesSent(int64(n))
		pr.metrics.RecordPacket()
	}

	// 4. Refund tokens if read was shorter than requested slice (e.g. EOF)
	if n < sliceSize {
		pr.limiter.Refund(sliceSize - n)
	}

	return n, err
}

// Close closes the underlying reader if it implements io.Closer.
func (pr *PacedReader) Close() error {
	if closer, ok := pr.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// PacedWriter wraps an io.Writer with rate limiting.
type PacedWriter struct {
	w        io.Writer
	limiter  RateLimiter
	metrics  *TrafficMetrics
	ctx      context.Context
	maxChunk int
}

// NewPacedWriter creates a bandwidth-limited io.Writer.
func NewPacedWriter(ctx context.Context, w io.Writer, limiter RateLimiter, metrics *TrafficMetrics) *PacedWriter {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PacedWriter{
		w:        w,
		limiter:  limiter,
		metrics:  metrics,
		ctx:      ctx,
		maxChunk: 32 * 1024,
	}
}

// Write slices large buffers, consumes tokens, and writes to underlying writer.
func (pw *PacedWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(p) {
		remaining := len(p) - total
		chunk := remaining
		if chunk > pw.maxChunk {
			chunk = pw.maxChunk
		}
		if err := pw.limiter.WaitN(pw.ctx, chunk); err != nil {
			return total, err
		}
		n, err := pw.w.Write(p[total : total+chunk])
		if n > 0 {
			total += n
			if pw.metrics != nil {
				pw.metrics.RecordBytesSent(int64(n))
				pw.metrics.RecordPacket()
			}
		}
		if n < chunk {
			pw.limiter.Refund(chunk - n)
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// PacedConn wraps net.Conn to provide transparent bandwidth pacing and packet gap pacing.
// 100% compatible with crypto/tls, uTLS, HTTP/1.1, HTTP/2, WebSocket, gRPC, and raw TCP.
type PacedConn struct {
	net.Conn
	limiter       RateLimiter
	cadence       *CadenceEngine
	metrics       *TrafficMetrics
	ctx           context.Context
	maxWriteChunk int
}

// NewPacedConn wraps an existing net.Conn with bandwidth rate limiting and packet pacing.
func NewPacedConn(ctx context.Context, conn net.Conn, limiter RateLimiter, cadence *CadenceEngine, metrics *TrafficMetrics) *PacedConn {
	if ctx == nil {
		ctx = context.Background()
	}
	return &PacedConn{
		Conn:          conn,
		limiter:       limiter,
		cadence:       cadence,
		metrics:       metrics,
		ctx:           ctx,
		maxWriteChunk: 32 * 1024, // 32KB write chunking
	}
}

// Write slices large buffers, enforces token consumption, and paces packet gaps.
func (pc *PacedConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	totalWritten := 0
	chunkSize := pc.maxWriteChunk
	if chunkSize <= 0 {
		chunkSize = 32 * 1024
	}

	for totalWritten < len(b) {
		remaining := len(b) - totalWritten
		toWrite := remaining
		if toWrite > chunkSize {
			toWrite = chunkSize
		}

		// 1. Enforce token bucket rate limiting
		if err := pc.limiter.WaitN(pc.ctx, toWrite); err != nil {
			return totalWritten, err
		}

		// 2. Perform write to underlying network connection
		n, err := pc.Conn.Write(b[totalWritten : totalWritten+toWrite])
		if n > 0 {
			totalWritten += n
			if pc.metrics != nil {
				pc.metrics.RecordBytesSent(int64(n))
				pc.metrics.RecordPacket()
			}
		}

		// 3. Refund if partial socket write occurred
		if n < toWrite {
			pc.limiter.Refund(toWrite - n)
		}

		if err != nil {
			return totalWritten, err
		}

		// 4. Microsecond packet gap pacing between consecutive writes
		if pc.cadence != nil && totalWritten < len(b) {
			if gap := pc.limiter.PacketGap(); gap > 0 {
				if err := pc.cadence.SleepDuration(pc.ctx, gap); err != nil {
					return totalWritten, err
				}
			}
		}
	}

	return totalWritten, nil
}

// Read delegates to underlying net.Conn and records received byte metrics.
func (pc *PacedConn) Read(b []byte) (int, error) {
	n, err := pc.Conn.Read(b)
	if n > 0 && pc.metrics != nil {
		pc.metrics.RecordBytesRecv(int64(n))
	}
	return n, err
}
