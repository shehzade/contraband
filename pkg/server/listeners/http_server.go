package listeners

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// HTTPServerListener provides a unified web listener supporting HTTP/1.1, HTTP/2, HTTP/3, WebSockets, and WebDAV.
type HTTPServerListener struct {
	mu            sync.Mutex
	bindAddr      string
	tcpPorts      []int
	udpPort       int
	boundTCPPorts []int
	boundUDPPort  int
	cleartext     bool
	tlsConfig     *tls.Config
	ledger        server.Ledger
	httpServers   []*http.Server
	h3Server      *http3.Server
	tcpLns        []net.Listener
	udpLn         net.PacketConn
	cancel        context.CancelFunc
	closed        bool
}

// NewHTTPServerListener constructs a unified web listener.
func NewHTTPServerListener(bindAddr string, tcpPorts []int, udpPort int, tlsConfig *tls.Config) *HTTPServerListener {
	if len(tcpPorts) == 0 {
		tcpPorts = []int{80, 443}
	}
	return &HTTPServerListener{
		bindAddr:  bindAddr,
		tcpPorts:  tcpPorts,
		udpPort:   udpPort,
		tlsConfig: tlsConfig,
	}
}

// SetCleartext configures the TCP listener(s) to serve plain cleartext HTTP.
func (l *HTTPServerListener) SetCleartext(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleartext = enabled
}

func (l *HTTPServerListener) Name() string {
	return "unified_web"
}

func (l *HTTPServerListener) Protocol() string {
	return common.ProtoHTTP1
}

func (l *HTTPServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.boundTCPPorts) > 0 {
		return l.boundTCPPorts
	}
	return l.tcpPorts
}

// UDPPort returns the bound UDP port for HTTP/3, or 0 if disabled.
func (l *HTTPServerListener) UDPPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundUDPPort
}

// Start spins up HTTP/1.1, HTTP/2 and HTTP/3 listeners.
func (l *HTTPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("http listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	// Ensure TLS configuration
	if l.tlsConfig == nil {
		tlsCfg, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1"}, nil)
		if err != nil {
			return fmt.Errorf("failed to generate server tls config: %w", err)
		}
		l.tlsConfig = tlsCfg
	}

	mux := http.NewServeMux()
	l.registerRoutes(mux)

	// Track actual effective UDP port for Alt-Svc header
	effectiveUDPPort := l.udpPort

	// 1. Start HTTP/3 QUIC server on UDP if configured
	if l.udpPort >= 0 {
		udpAddr := fmt.Sprintf("%s:%d", l.bindAddr, l.udpPort)
		packetConn, err := net.ListenPacket("udp", udpAddr)
		if err == nil {
			l.udpLn = packetConn
			if uAddr, ok := packetConn.LocalAddr().(*net.UDPAddr); ok {
				effectiveUDPPort = uAddr.Port
				l.boundUDPPort = effectiveUDPPort
			}

			h3TLS := l.tlsConfig.Clone()
			h3TLS.NextProtos = []string{"h3"}
			h3Srv := &http3.Server{
				Handler:   mux,
				TLSConfig: h3TLS,
				Port:      effectiveUDPPort,
			}
			l.h3Server = h3Srv

			go func() {
				_ = h3Srv.Serve(packetConn)
			}()
		}
	}

	// Wrapper handler injecting Alt-Svc: h3=":<port>"; ma=2592000
	altSvcValue := fmt.Sprintf("h3=\":%d\"; ma=2592000", effectiveUDPPort)
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", altSvcValue)
		mux.ServeHTTP(w, r)
	})

	// 2. Start TCP listeners (TLS or cleartext)
	for _, port := range l.tcpPorts {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, port)
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			common.Warnf("Listener unified_web skipped occupied/privileged TCP port %d (%v)", port, err)
			continue
		}

		actualPort := rawLn.Addr().(*net.TCPAddr).Port
		l.boundTCPPorts = append(l.boundTCPPorts, actualPort)

		var ln net.Listener = rawLn
		// Use TLS unless explicitly port 80 or cleartext mode
		if port != 80 && !l.cleartext && l.tlsConfig != nil {
			ln = tls.NewListener(rawLn, l.tlsConfig)
		}

		srv := &http.Server{
			Handler:      wrappedHandler,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		l.tcpLns = append(l.tcpLns, ln)
		l.httpServers = append(l.httpServers, srv)

		go func(s *http.Server, l net.Listener) {
			_ = s.Serve(l)
		}(srv, ln)
	}

	if len(l.boundTCPPorts) == 0 {
		l.stopInternal()
		return fmt.Errorf("failed to bind any tcp ports from %v", l.tcpPorts)
	}

	return nil
}

func (l *HTTPServerListener) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/reflect", l.handleReflect)
	mux.HandleFunc("/upload", l.handleUpload)
	mux.HandleFunc("/webdav/", l.handleWebDAV)
	mux.HandleFunc("/ws", l.handleWebSocket)
	mux.HandleFunc("/dns-query", l.handleDNSQuery)
	mux.HandleFunc("/api/telemetry", l.handleTelemetry)
}

func (l *HTTPServerListener) extractClientMeta(r *http.Request, defaultProto string) (clientIP, clientHost, networkZone, proto string, port int) {
	clientIP = r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	}

	if localAddr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && localAddr != nil {
		if _, pStr, err := net.SplitHostPort(localAddr.String()); err == nil {
			port, _ = strconv.Atoi(pStr)
		}
	}
	if port == 0 && r.Host != "" {
		if _, pStr, err := net.SplitHostPort(r.Host); err == nil {
			port, _ = strconv.Atoi(pStr)
		}
	}
	if port == 0 {
		if r.TLS != nil {
			port = 443
		} else {
			port = 80
		}
	}

	if ipHdr := r.Header.Get(common.HeaderClientIP); ipHdr != "" {
		clientIP = ipHdr
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		clientIP = strings.TrimSpace(parts[0])
	}

	clientHost = r.Header.Get(common.HeaderClientHost)
	if clientHost == "" {
		clientHost = clientIP
	}

	networkZone = r.Header.Get(common.HeaderNetworkZone)

	proto = r.Header.Get(common.HeaderProtocol)
	if proto == "" {
		if strings.HasPrefix(r.URL.Path, "/webdav") {
			proto = common.ProtoWebDAV
		} else if defaultProto != "" {
			proto = defaultProto
		} else if r.ProtoMajor == 3 {
			proto = common.ProtoHTTP3
		} else if r.ProtoMajor == 2 {
			proto = common.ProtoHTTP2
		} else {
			proto = common.ProtoHTTP1
		}
	} else {
		proto = common.SanitizeProtocolName(proto)
	}
	return
}

func (l *HTTPServerListener) handleReflect(w http.ResponseWriter, r *http.Request) {
	remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	port := 443
	if len(l.boundTCPPorts) > 0 {
		port = l.boundTCPPorts[0]
	}

	sessionID := r.Header.Get(common.HeaderSessionID)
	if sessionID == "" {
		sessionID = r.URL.Query().Get("session")
	}

	resp := map[string]interface{}{
		"status":    "OK",
		"remote_ip": remoteIP,
		"port":      port,
		"proto":     r.Proto,
		"session":   sessionID,
		"headers":   r.Header,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (l *HTTPServerListener) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Check for multipart form-data
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		l.handleMultipartUpload(w, r)
		return
	}

	// Read binary body bounded by 4MB per chunk to uphold heap invariant
	const MaxChunkBytes = 4 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxChunkBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "failed to read body"})
		return
	}
	if len(body) > MaxChunkBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "payload chunk exceeds 4MB ceiling"})
		return
	}

	var token common.SessionToken
	var seq, total uint32
	var payload []byte
	expectedHash := r.Header.Get(common.HeaderPayloadHash)

	// Attempt to unmarshal 32-byte ChunkHeader
	if len(body) >= common.ChunkHeaderSize {
		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(body[:common.ChunkHeaderSize]); err == nil {
			token = hdr.Token
			seq = hdr.Sequence
			total = hdr.TotalChunks
			payload = body[common.ChunkHeaderSize:]
			if uint32(len(payload)) > hdr.PayloadLen {
				payload = payload[:hdr.PayloadLen]
			}
		}
	}

	// Fallback to headers if ChunkHeader not present
	if seq == 0 {
		sessHeader := r.Header.Get(common.HeaderSessionID)
		if parsedTok, err := common.ParseSessionToken(sessHeader); err == nil {
			token = parsedTok
		} else {
			token, _ = common.NewSessionToken()
		}

		if sVal := r.Header.Get(common.HeaderSequence); sVal != "" {
			if s, err := strconv.ParseUint(sVal, 10, 32); err == nil {
				seq = uint32(s)
			}
		}
		if tVal := r.Header.Get(common.HeaderTotalChunks); tVal != "" {
			if t, err := strconv.ParseUint(tVal, 10, 32); err == nil {
				total = uint32(t)
			}
		}
		if seq == 0 {
			seq = 1
		}
		if total == 0 {
			total = 1
		}
		payload = body
	}

	clientIP, clientHost, networkZone, proto, port := l.extractClientMeta(r, "")
	session, completed, err := l.ledger.AssembleChunkWithMeta(token, seq, total, payload, expectedHash, clientIP, proto, port, clientHost, networkZone)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		verdict := common.VerdictBlockedL7
		if errors.Is(err, server.ErrHashMismatch) || (session != nil && session.Verdict == common.VerdictBlockedDLP) {
			verdict = common.VerdictBlockedDLP
		}
		_ = json.NewEncoder(w).Encode(common.VerificationACK{
			Status:       "ERROR",
			SessionID:    token.String(),
			Verdict:      verdict,
			ErrorMessage: err.Error(),
		})
		return
	}

	if completed {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(common.VerificationACK{
			Status:         "OK",
			SessionID:      token.String(),
			TotalBytes:     session.TotalBytes,
			ReceivedChunks: session.ReceivedChunks,
			TotalChunks:    session.TotalChunks,
			PayloadHash:    session.PayloadHash,
			Verdict:        session.Verdict,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(common.VerificationACK{
		Status:         "OK",
		SessionID:      token.String(),
		ReceivedChunks: session.ReceivedChunks,
		TotalChunks:    session.TotalChunks,
		Sequence:       seq,
		Verdict:        "IN_PROGRESS",
	})
}

func (l *HTTPServerListener) handleMultipartUpload(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "failed to parse multipart form"})
		return
	}

	sessID := r.FormValue("session_id")
	token, err := common.ParseSessionToken(sessID)
	if err != nil {
		token, _ = common.NewSessionToken()
	}

	seqVal, _ := strconv.ParseUint(r.FormValue("sequence"), 10, 32)
	totalVal, _ := strconv.ParseUint(r.FormValue("total_chunks"), 10, 32)
	expectedHash := r.FormValue("payload_hash")

	file, _, err := r.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "missing file part"})
		return
	}
	defer file.Close()

	const MaxMultipartChunkBytes = 4 * 1024 * 1024
	payload, err := io.ReadAll(io.LimitReader(file, MaxMultipartChunkBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "failed to read file part"})
		return
	}
	if len(payload) > MaxMultipartChunkBytes {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ERROR", "error_message": "multipart file chunk exceeds 4MB ceiling"})
		return
	}

	seq := uint32(seqVal)
	total := uint32(totalVal)
	if seq == 0 {
		seq = 1
	}
	if total == 0 {
		total = 1
	}

	clientIP, clientHost, networkZone, proto, port := l.extractClientMeta(r, "")
	session, completed, err := l.ledger.AssembleChunkWithMeta(token, seq, total, payload, expectedHash, clientIP, proto, port, clientHost, networkZone)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		verdict := common.VerdictBlockedL7
		if errors.Is(err, server.ErrHashMismatch) || (session != nil && session.Verdict == common.VerdictBlockedDLP) {
			verdict = common.VerdictBlockedDLP
		}
		_ = json.NewEncoder(w).Encode(common.VerificationACK{
			Status:       "ERROR",
			SessionID:    token.String(),
			Verdict:      verdict,
			ErrorMessage: err.Error(),
		})
		return
	}

	if completed {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(common.VerificationACK{
			Status:         "OK",
			SessionID:      token.String(),
			TotalBytes:     session.TotalBytes,
			ReceivedChunks: session.ReceivedChunks,
			TotalChunks:    session.TotalChunks,
			PayloadHash:    session.PayloadHash,
			Verdict:        session.Verdict,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(common.VerificationACK{
		Status:         "OK",
		SessionID:      token.String(),
		ReceivedChunks: session.ReceivedChunks,
		TotalChunks:    session.TotalChunks,
		Sequence:       seq,
		Verdict:        "IN_PROGRESS",
	})
}

func (l *HTTPServerListener) handleWebDAV(w http.ResponseWriter, r *http.Request) {
	if r.Method == "PROPFIND" {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("DAV", "1, 2")
		w.WriteHeader(207) // Multi-Status
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/webdav/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`))
		return
	}

	if r.Method == http.MethodPut || r.Method == http.MethodPost {
		l.handleUpload(w, r)
		return
	}

	http.Error(w, "WebDAV method not allowed", http.StatusMethodNotAllowed)
}

func (l *HTTPServerListener) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsHandler := NewWebSocketHandler(l.ledger)
	wsHandler.ServeHTTP(w, r)
}

func (l *HTTPServerListener) handleDNSQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	// Echo back or standard response for DoH RFC 8484
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		_, _ = w.Write(body)
	}
}

func (l *HTTPServerListener) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "OK",
		"timestamp": time.Now().UTC(),
		"ports":     l.Ports(),
	})
}

func (l *HTTPServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *HTTPServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cancel != nil {
		l.cancel()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, srv := range l.httpServers {
		_ = srv.Shutdown(ctx)
	}
	for _, ln := range l.tcpLns {
		_ = ln.Close()
	}
	l.httpServers = nil
	l.tcpLns = nil

	if l.h3Server != nil {
		_ = l.h3Server.Close()
		l.h3Server = nil
	}
	if l.udpLn != nil {
		_ = l.udpLn.Close()
		l.udpLn = nil
	}

	return nil
}
