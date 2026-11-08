package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	socks5Version = 0x05

	// Auth methods
	socks5AuthNone     = 0x00
	socks5AuthUserPass = 0x02
	socks5AuthNoAccept = 0xFF

	// Command
	socks5CmdConnect = 0x01

	// Address types
	socks5AtypIPv4   = 0x01
	socks5AtypDomain = 0x03
	socks5AtypIPv6   = 0x04

	// Reply codes
	socks5RepSuccess = 0x00
)

var socks5Errors = map[byte]string{
	0x01: "general SOCKS server failure",
	0x02: "connection not allowed by ruleset",
	0x03: "network unreachable",
	0x04: "host unreachable",
	0x05: "connection refused",
	0x06: "TTL expired",
	0x07: "command not supported",
	0x08: "address type not supported",
}

// SOCKS5Dialer implements ProxyDialer for RFC 1928 / RFC 1929 SOCKS5 proxies.
type SOCKS5Dialer struct {
	proxyAddr string
	username  string
	password  string
	timeout   time.Duration
}

// NewSOCKS5Dialer creates a new SOCKS5Dialer from Options.
func NewSOCKS5Dialer(opts Options) (*SOCKS5Dialer, error) {
	addr := opts.Mode
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid socks5 proxy URL: %w", err)
		}
		addr = u.Host
		if u.User != nil {
			if opts.Username == "" {
				opts.Username = u.User.Username()
			}
			if opts.Password == "" {
				opts.Password, _ = u.User.Password()
			}
		}
	}

	if !strings.Contains(addr, ":") {
		addr = addr + ":1080"
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &SOCKS5Dialer{
		proxyAddr: addr,
		username:  opts.Username,
		password:  opts.Password,
		timeout:   timeout,
	}, nil
}

func (s *SOCKS5Dialer) ProxyHop() string {
	return s.proxyAddr
}

func (s *SOCKS5Dialer) Mode() string {
	return "socks5"
}

func (s *SOCKS5Dialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: s.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", s.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy %s: %w", s.proxyAddr, err)
	}

	// Apply deadline
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else if s.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.timeout))
	}
	defer func() {
		// Clear deadline after handshake
		_ = conn.SetDeadline(time.Time{})
	}()

	// 1. Method negotiation
	var methods []byte
	if s.username != "" {
		methods = []byte{socks5AuthNone, socks5AuthUserPass}
	} else {
		methods = []byte{socks5AuthNone}
	}

	req := make([]byte, 2+len(methods))
	req[0] = socks5Version
	req[1] = byte(len(methods))
	copy(req[2:], methods)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SOCKS5 method request: %w", err)
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read SOCKS5 method response: %w", err)
	}

	if resp[0] != socks5Version {
		conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS version %d", resp[0])
	}

	chosenMethod := resp[1]
	switch chosenMethod {
	case socks5AuthNone:
		// No authentication required
	case socks5AuthUserPass:
		if err := s.authenticateUserPass(conn); err != nil {
			conn.Close()
			return nil, err
		}
	case socks5AuthNoAccept:
		conn.Close()
		return nil, errors.New("SOCKS5 proxy rejected authentication methods")
	default:
		conn.Close()
		return nil, fmt.Errorf("unknown SOCKS5 auth method %d chosen by server", chosenMethod)
	}

	// 2. CONNECT Request
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("invalid target address %q: %w", targetAddr, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("invalid target port %q: %w", portStr, err)
	}

	var cmd []byte
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			cmd = make([]byte, 4+4+2)
			cmd[0] = socks5Version
			cmd[1] = socks5CmdConnect
			cmd[2] = 0x00 // Reserved
			cmd[3] = socks5AtypIPv4
			copy(cmd[4:8], ipv4)
			binary.BigEndian.PutUint16(cmd[8:10], uint16(port))
		} else {
			ipv6 := ip.To16()
			cmd = make([]byte, 4+16+2)
			cmd[0] = socks5Version
			cmd[1] = socks5CmdConnect
			cmd[2] = 0x00 // Reserved
			cmd[3] = socks5AtypIPv6
			copy(cmd[4:20], ipv6)
			binary.BigEndian.PutUint16(cmd[20:22], uint16(port))
		}
	} else {
		// ATYP 0x03 Domain name
		cmd = make([]byte, 4+1+len(host)+2)
		cmd[0] = socks5Version
		cmd[1] = socks5CmdConnect
		cmd[2] = 0x00 // Reserved
		cmd[3] = socks5AtypDomain
		cmd[4] = byte(len(host))
		copy(cmd[5:5+len(host)], []byte(host))
		binary.BigEndian.PutUint16(cmd[5+len(host):], uint16(port))
	}

	if _, err := conn.Write(cmd); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SOCKS5 CONNECT command: %w", err)
	}

	// 3. Read Server Reply
	replyHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read SOCKS5 reply header: %w", err)
	}

	if replyHdr[0] != socks5Version {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS5 reply version %d", replyHdr[0])
	}

	if replyHdr[1] != socks5RepSuccess {
		conn.Close()
		errMsg, ok := socks5Errors[replyHdr[1]]
		if !ok {
			errMsg = fmt.Sprintf("error code 0x%02x", replyHdr[1])
		}
		return nil, fmt.Errorf("SOCKS5 connection failed: %s", errMsg)
	}

	// Consume bound address and port
	atyp := replyHdr[3]
	switch atyp {
	case socks5AtypIPv4:
		bnd := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, bnd); err != nil {
			conn.Close()
			return nil, err
		}
	case socks5AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		bnd := make([]byte, int(lenBuf[0])+2)
		if _, err := io.ReadFull(conn, bnd); err != nil {
			conn.Close()
			return nil, err
		}
	case socks5AtypIPv6:
		bnd := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, bnd); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS5 bound address type 0x%02x", atyp)
	}

	return conn, nil
}

func (s *SOCKS5Dialer) authenticateUserPass(conn net.Conn) error {
	// RFC 1929 subnegotiation:
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+
	uLen := len(s.username)
	pLen := len(s.password)
	if uLen > 255 || pLen > 255 {
		return errors.New("SOCKS5 username or password exceeds 255 bytes")
	}

	authReq := make([]byte, 3+uLen+pLen)
	authReq[0] = 0x01
	authReq[1] = byte(uLen)
	copy(authReq[2:2+uLen], []byte(s.username))
	authReq[2+uLen] = byte(pLen)
	copy(authReq[3+uLen:], []byte(s.password))

	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("failed to send SOCKS5 auth request: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		return fmt.Errorf("failed to read SOCKS5 auth response: %w", err)
	}

	if authResp[0] != 0x01 {
		return fmt.Errorf("invalid SOCKS5 auth version %d", authResp[0])
	}

	if authResp[1] != 0x00 {
		return errors.New("SOCKS5 username/password authentication failed")
	}

	return nil
}
