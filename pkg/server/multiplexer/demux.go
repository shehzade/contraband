package multiplexer

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/shehzade/contraband/pkg/common"
)

// HeaderDemuxer inspects incoming connection bytes within a tight deadline.
type HeaderDemuxer struct {
	peekTimeout time.Duration
}

// NewHeaderDemuxer constructs a HeaderDemuxer with configured peek timeout.
func NewHeaderDemuxer(peekTimeout time.Duration) *HeaderDemuxer {
	if peekTimeout <= 0 {
		peekTimeout = 100 * time.Millisecond
	}
	return &HeaderDemuxer{peekTimeout: peekTimeout}
}

// Demux reads initial bytes from conn. If bytes arrive immediately and match
// MagicHeader or HTTP/TLS signatures, it classifies as ProbeTypeSmuggling.
// If read times out with 0 bytes or client sends sweep ping, it classifies as ProbeTypeSweep.
func (d *HeaderDemuxer) Demux(conn net.Conn) (ProbeType, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(d.peekTimeout))
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{}) // Clear read deadline

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout reached with 0 bytes read -> Client is a sweep probe waiting for reflection banner!
			return ProbeTypeSweep, nil, nil
		}
		if err == io.EOF && n == 0 {
			return ProbeTypeSweep, nil, nil
		}
		if n == 0 {
			return ProbeTypeUnknown, nil, err
		}
	}

	peeked := buf[:n]

	// Check 0: Generic UDP probe token or newline -> Sweep
	if bytes.HasPrefix(peeked, []byte("CTRB_UDP_PROBE")) ||
		bytes.Equal(peeked, []byte("\n")) ||
		bytes.Equal(peeked, []byte("\r\n")) {
		return ProbeTypeSweep, peeked, nil
	}

	// Check 1: 4-byte MagicHeader "CTRB" (0x43545242)
	if n >= 4 {
		magic := binary.BigEndian.Uint32(peeked[0:4])
		if magic == common.MagicHeader {
			return ProbeTypeSmuggling, peeked, nil
		}
	}

	// Check 2: TLS ClientHello (0x16 0x03 ...)
	if n >= 3 && peeked[0] == 0x16 && peeked[1] == 0x03 {
		return ProbeTypeSmuggling, peeked, nil
	}

	// Check 3: HTTP Request Method (POST / GET / PUT / HEAD / OPTIONS / CONNECT)
	if bytes.HasPrefix(peeked, []byte("POST ")) ||
		bytes.HasPrefix(peeked, []byte("GET ")) ||
		bytes.HasPrefix(peeked, []byte("PUT ")) ||
		bytes.HasPrefix(peeked, []byte("HEAD ")) ||
		bytes.HasPrefix(peeked, []byte("OPTIONS ")) ||
		bytes.HasPrefix(peeked, []byte("CONNECT ")) {
		return ProbeTypeSmuggling, peeked, nil
	}

	// Check 4: Generic UDP probe token or newline/whitespace -> Sweep
	return ProbeTypeSweep, peeked, nil
}
