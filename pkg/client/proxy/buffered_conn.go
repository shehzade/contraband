package proxy

import (
	"bufio"
	"io"
	"net"
)

// bufferedConn wraps net.Conn with a buffered reader using io.MultiReader
// so that any bytes read ahead by bufio.Reader during HTTP header parsing
// are preserved and returned before reading directly from the underlying connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func newBufferedConn(c net.Conn, br *bufio.Reader) net.Conn {
	if br == nil || br.Buffered() == 0 {
		return c
	}
	return &bufferedConn{
		Conn: c,
		r:    io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c),
	}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
