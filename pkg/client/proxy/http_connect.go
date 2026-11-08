package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPConnectDialer implements ProxyDialer for HTTP/HTTPS forward proxies using HTTP CONNECT.
type HTTPConnectDialer struct {
	proxyAddr          string
	isTLS              bool
	tlsConfig          *tls.Config
	username           string
	password           string
	domain             string
	workstation        string
	authType           AuthType
	timeout            time.Duration
	userAgent          string
	insecureSkipVerify bool
}

// NewHTTPConnectDialer creates a new HTTPConnectDialer from Options.
func NewHTTPConnectDialer(opts Options) (*HTTPConnectDialer, error) {
	rawURL := opts.Mode
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP proxy URL %q: %w", opts.Mode, err)
	}

	isTLS := strings.EqualFold(u.Scheme, "https")
	host := u.Host
	if !strings.Contains(host, ":") {
		if isTLS {
			host += ":443"
		} else {
			host += ":8080"
		}
	}

	username := opts.Username
	password := opts.Password
	if u.User != nil {
		if username == "" {
			username = u.User.Username()
		}
		if password == "" {
			password, _ = u.User.Password()
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	userAgent := opts.UserAgent
	if userAgent == "" {
		userAgent = DefaultOptions().UserAgent
	}

	var tlsCfg *tls.Config
	if isTLS {
		serverName := host
		if h, _, err := net.SplitHostPort(host); err == nil {
			serverName = h
		}
		tlsCfg = &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: opts.InsecureSkipVerify,
		}
	}

	return &HTTPConnectDialer{
		proxyAddr:          host,
		isTLS:              isTLS,
		tlsConfig:          tlsCfg,
		username:           username,
		password:           password,
		domain:             opts.Domain,
		workstation:        opts.Workstation,
		authType:           opts.AuthType,
		timeout:            timeout,
		userAgent:          userAgent,
		insecureSkipVerify: opts.InsecureSkipVerify,
	}, nil
}

func (h *HTTPConnectDialer) ProxyHop() string {
	return h.proxyAddr
}

func (h *HTTPConnectDialer) Mode() string {
	return "http_connect"
}

func (h *HTTPConnectDialer) dialProxy(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout: h.timeout,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", h.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial proxy %s: %w", h.proxyAddr, err)
	}

	var conn net.Conn = rawConn
	if h.isTLS {
		tlsConn := tls.Client(rawConn, h.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake to proxy %s failed: %w", h.proxyAddr, err)
		}
		conn = tlsConn
	}
	return conn, nil
}

func (h *HTTPConnectDialer) DialContext(ctx context.Context, network, targetAddr string) (net.Conn, error) {
	conn, err := h.dialProxy(ctx)
	if err != nil {
		return nil, err
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else if h.timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(h.timeout))
	}
	defer func() {
		_ = conn.SetDeadline(time.Time{})
	}()

	br := bufio.NewReader(conn)

	// Step 1: Initial CONNECT request
	var initialAuthHeader string
	if h.authType == AuthBasic && h.username != "" {
		initialAuthHeader = BuildBasicAuthHeader(h.username, h.password)
	}

	if err := h.sendConnect(conn, targetAddr, initialAuthHeader); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		return newBufferedConn(conn, br), nil
	}

	if resp.StatusCode == http.StatusForbidden {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		conn.Close()
		return nil, ErrProxyForbidden
	}

	if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		conn.Close()
		return nil, ErrProxyGateway
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		conn.Close()
		return nil, fmt.Errorf("proxy returned status %d: %s", resp.StatusCode, resp.Status)
	}

	// Step 2: Handle 407 Proxy Authentication Required
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	if resp.Close {
		_ = conn.Close()
		var dialErr error
		conn, dialErr = h.dialProxy(ctx)
		if dialErr != nil {
			return nil, fmt.Errorf("failed to reconnect to proxy: %w", dialErr)
		}
		br = bufio.NewReaderSize(conn, 32768)
	}

	authHeaders := resp.Header.Values("Proxy-Authenticate")
	if len(authHeaders) == 0 {
		authHeaders = []string{resp.Header.Get("Proxy-Authenticate")}
	}

	// Check available mechanisms
	hasNTLM := false
	hasNegotiate := false
	hasDigest := false
	hasBasic := false
	var digestChallenge string

	for _, h := range authHeaders {
		for _, part := range strings.Split(h, ",") {
			part = strings.TrimSpace(part)
			lower := strings.ToLower(part)
			if strings.HasPrefix(lower, "ntlm") {
				hasNTLM = true
			} else if strings.HasPrefix(lower, "negotiate") {
				hasNegotiate = true
			} else if strings.HasPrefix(lower, "digest") {
				hasDigest = true
				digestChallenge = part
			} else if strings.HasPrefix(lower, "basic") {
				hasBasic = true
			}
		}
	}

	// Prioritize auth: NTLM -> Negotiate -> Digest -> Basic
	if (h.authType == AuthNTLM || h.authType == AuthAuto) && hasNTLM && h.username != "" {
		return h.handshakeNTLM(conn, br, targetAddr)
	}

	if (h.authType == AuthNegotiate || h.authType == AuthAuto) && hasNegotiate && h.username != "" {
		// Try SPNEGO with NTLMSSP
		spnegoInit, err := BuildSPNEGONTLMInit(h.domain, h.workstation)
		if err == nil {
			if err := h.sendConnect(conn, targetAddr, spnegoInit); err == nil {
				resp2, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
				if err == nil && resp2.StatusCode == http.StatusProxyAuthRequired {
					if resp2.Body != nil {
						_, _ = io.Copy(io.Discard, resp2.Body)
						_ = resp2.Body.Close()
					}
					spnegoRespHeader := resp2.Header.Get("Proxy-Authenticate")
					token, err := ExtractSPNEGOMechToken(spnegoRespHeader)
					if err == nil {
						t2, err := ParseNTLMType2(string(token))
						if err == nil {
							t3, err := BuildNTLMType3(h.username, h.password, h.domain, h.workstation, t2, nil)
							if err == nil {
								if err := h.sendConnect(conn, targetAddr, "NTLM "+t3); err == nil {
									resp3, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
									if err == nil && resp3.StatusCode == http.StatusOK {
										return newBufferedConn(conn, br), nil
									}
									if resp3 != nil && resp3.Body != nil {
										_, _ = io.Copy(io.Discard, resp3.Body)
										_ = resp3.Body.Close()
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (h.authType == AuthDigest || h.authType == AuthAuto) && hasDigest && h.username != "" {
		ch := ParseDigestChallenge(digestChallenge)
		digestHeader := BuildDigestAuthHeader(h.username, h.password, targetAddr, ch, 1)
		if err := h.sendConnect(conn, targetAddr, digestHeader); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send digest auth: %w", err)
		}
		resp2, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read digest auth response: %w", err)
		}
		if resp2.Body != nil {
			_, _ = io.Copy(io.Discard, resp2.Body)
			_ = resp2.Body.Close()
		}
		if resp2.StatusCode == http.StatusOK {
			return newBufferedConn(conn, br), nil
		}
	}

	if (h.authType == AuthBasic || h.authType == AuthAuto) && hasBasic && h.username != "" {
		basicHeader := BuildBasicAuthHeader(h.username, h.password)
		if err := h.sendConnect(conn, targetAddr, basicHeader); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to send basic auth: %w", err)
		}
		resp2, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read basic auth response: %w", err)
		}
		if resp2.Body != nil {
			_, _ = io.Copy(io.Discard, resp2.Body)
			_ = resp2.Body.Close()
		}
		if resp2.StatusCode == http.StatusOK {
			return newBufferedConn(conn, br), nil
		}
		if resp2.StatusCode == http.StatusProxyAuthRequired {
			conn.Close()
			return nil, ErrProxyAuthFailed
		}
		if resp2.StatusCode == http.StatusForbidden {
			conn.Close()
			return nil, ErrProxyForbidden
		}
	}

	conn.Close()
	return nil, ErrProxyAuthFailed
}

func (h *HTTPConnectDialer) sendConnect(conn net.Conn, targetAddr, authHeader string) error {
	var req strings.Builder
	req.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", targetAddr))
	req.WriteString(fmt.Sprintf("Host: %s\r\n", targetAddr))
	req.WriteString(fmt.Sprintf("User-Agent: %s\r\n", h.userAgent))
	req.WriteString("Proxy-Connection: Keep-Alive\r\n")
	if authHeader != "" {
		req.WriteString(fmt.Sprintf("Proxy-Authorization: %s\r\n", authHeader))
	}
	req.WriteString("\r\n")

	_, err := conn.Write([]byte(req.String()))
	return err
}

func (h *HTTPConnectDialer) handshakeNTLM(conn net.Conn, br *bufio.Reader, targetAddr string) (net.Conn, error) {
	// Type 1 Negotiate
	type1 := BuildNTLMType1(h.domain, h.workstation)
	if err := h.sendConnect(conn, targetAddr, "NTLM "+type1); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send NTLM Type 1: %w", err)
	}

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read NTLM Type 2 response: %w", err)
	}

	if resp.StatusCode != http.StatusProxyAuthRequired {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		conn.Close()
		return nil, fmt.Errorf("expected 407 on NTLM Type 1, got %d", resp.StatusCode)
	}
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	type2Header := resp.Header.Get("Proxy-Authenticate")
	t2, err := ParseNTLMType2(type2Header)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to parse NTLM Type 2 challenge: %w", err)
	}

	// Type 3 Authenticate
	type3, err := BuildNTLMType3(h.username, h.password, h.domain, h.workstation, t2, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to build NTLM Type 3 authenticate: %w", err)
	}

	if err := h.sendConnect(conn, targetAddr, "NTLM "+type3); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send NTLM Type 3: %w", err)
	}

	respFinal, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read NTLM final response: %w", err)
	}

	if respFinal.StatusCode == http.StatusOK {
		return newBufferedConn(conn, br), nil
	}

	if respFinal.Body != nil {
		_ = respFinal.Body.Close()
	}
	conn.Close()
	return nil, fmt.Errorf("%w: status %d %s", ErrProxyAuthFailed, respFinal.StatusCode, respFinal.Status)
}
