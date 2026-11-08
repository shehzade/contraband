package listeners

import (
	"context"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// DNSServerListener implements an authoritative DNS listener supporting UDP, TCP, DoT, and DoH.
type DNSServerListener struct {
	mu           sync.Mutex
	bindAddr     string
	udpPort      int
	tcpPort      int
	dotPort      int
	dohPort      int
	boundUDPPort int
	boundTCPPort int
	boundDoTPort int
	boundDoHPort int
	tlsConfig    *tls.Config
	ledger       server.Ledger

	udpServer *dns.Server
	tcpServer *dns.Server
	dotServer *dns.Server
	dohServer *http.Server

	udpPacketConn net.PacketConn
	tcpListener   net.Listener
	dotListener   net.Listener
	dohListener   net.Listener

	cancel context.CancelFunc
	closed bool
}

// NewDNSServerListener creates a new multi-transport DNS server listener.
func NewDNSServerListener(bindAddr string, udpPort, tcpPort, dotPort, dohPort int, tlsConfig *tls.Config) *DNSServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	return &DNSServerListener{
		bindAddr:  bindAddr,
		udpPort:   udpPort,
		tcpPort:   tcpPort,
		dotPort:   dotPort,
		dohPort:   dohPort,
		tlsConfig: tlsConfig,
	}
}

func (l *DNSServerListener) Name() string {
	return "authoritative_dns"
}

func (l *DNSServerListener) Protocol() string {
	return common.ProtoDNSA
}

func (l *DNSServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ports []int
	if l.boundUDPPort > 0 {
		ports = append(ports, l.boundUDPPort)
	} else if l.udpPort > 0 {
		ports = append(ports, l.udpPort)
	}
	if l.boundTCPPort > 0 {
		ports = append(ports, l.boundTCPPort)
	} else if l.tcpPort > 0 {
		ports = append(ports, l.tcpPort)
	}
	if l.boundDoTPort > 0 {
		ports = append(ports, l.boundDoTPort)
	} else if l.dotPort > 0 {
		ports = append(ports, l.dotPort)
	}
	if l.boundDoHPort > 0 {
		ports = append(ports, l.boundDoHPort)
	} else if l.dohPort > 0 {
		ports = append(ports, l.dohPort)
	}
	return ports
}

// BoundPorts returns the actual bound ports for each protocol.
func (l *DNSServerListener) BoundPorts() (udp, tcp, dot, doh int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundUDPPort, l.boundTCPPort, l.boundDoTPort, l.boundDoHPort
}

// Start begins serving DNS over all configured transports.
func (l *DNSServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return fmt.Errorf("dns listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	// Ensure TLS config for DoT and DoH
	if (l.dotPort >= 0 || l.dohPort >= 0) && l.tlsConfig == nil {
		tlsCfg, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1", l.bindAddr}, nil)
		if err != nil {
			return fmt.Errorf("failed to generate server tls config for dns: %w", err)
		}
		l.tlsConfig = tlsCfg
	}

	handler := dns.HandlerFunc(l.handleDNS)

	// 1. UDP Listener
	if l.udpPort >= 0 {
		udpAddr := fmt.Sprintf("%s:%d", l.bindAddr, l.udpPort)
		pConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind dns udp %s: %w", udpAddr, err)
		}
		l.udpPacketConn = pConn
		l.boundUDPPort = pConn.LocalAddr().(*net.UDPAddr).Port

		l.udpServer = &dns.Server{
			PacketConn: pConn,
			Handler:    handler,
		}
		go func() {
			_ = l.udpServer.ActivateAndServe()
		}()
	}

	// 2. TCP Listener
	if l.tcpPort >= 0 {
		tcpAddr := fmt.Sprintf("%s:%d", l.bindAddr, l.tcpPort)
		tcpLn, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind dns tcp %s: %w", tcpAddr, err)
		}
		l.tcpListener = tcpLn
		l.boundTCPPort = tcpLn.Addr().(*net.TCPAddr).Port

		l.tcpServer = &dns.Server{
			Listener: tcpLn,
			Handler:  handler,
		}
		go func() {
			_ = l.tcpServer.ActivateAndServe()
		}()
	}

	// 3. DoT Listener (TCP-TLS)
	if l.dotPort >= 0 && l.tlsConfig != nil {
		dotTLS := l.tlsConfig.Clone()
		dotTLS.NextProtos = []string{common.ALPNDoT}
		dotAddr := fmt.Sprintf("%s:%d", l.bindAddr, l.dotPort)
		dotLn, err := tls.Listen("tcp", dotAddr, dotTLS)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind dns dot %s: %w", dotAddr, err)
		}
		l.dotListener = dotLn
		l.boundDoTPort = dotLn.Addr().(*net.TCPAddr).Port

		l.dotServer = &dns.Server{
			Listener: dotLn,
			Handler:  handler,
		}
		go func() {
			_ = l.dotServer.ActivateAndServe()
		}()
	}

	// 4. DoH Listener (HTTPS /dns-query)
	if l.dohPort >= 0 {
		dohMux := http.NewServeMux()
		dohMux.HandleFunc("/dns-query", l.HandleDoH)

		dohAddr := fmt.Sprintf("%s:%d", l.bindAddr, l.dohPort)
		var dohLn net.Listener
		var err error

		if l.tlsConfig != nil {
			dohTLS := l.tlsConfig.Clone()
			dohTLS.NextProtos = []string{"h2", "http/1.1"}
			dohLn, err = tls.Listen("tcp", dohAddr, dohTLS)
		} else {
			dohLn, err = net.Listen("tcp", dohAddr)
		}

		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind dns doh %s: %w", dohAddr, err)
		}
		l.dohListener = dohLn
		l.boundDoHPort = dohLn.Addr().(*net.TCPAddr).Port

		l.dohServer = &http.Server{
			Handler:      dohMux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  15 * time.Second,
		}
		go func() {
			_ = l.dohServer.Serve(dohLn)
		}()
	}

	return nil
}

// Stop terminates all running DNS servers and closes network listeners.
func (l *DNSServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *DNSServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true

	if l.cancel != nil {
		l.cancel()
	}
	if l.udpServer != nil {
		_ = l.udpServer.Shutdown()
	}
	if l.tcpServer != nil {
		_ = l.tcpServer.Shutdown()
	}
	if l.dotServer != nil {
		_ = l.dotServer.Shutdown()
	}
	if l.dohServer != nil {
		_ = l.dohServer.Close()
	}
	if l.udpPacketConn != nil {
		_ = l.udpPacketConn.Close()
	}
	if l.tcpListener != nil {
		_ = l.tcpListener.Close()
	}
	if l.dotListener != nil {
		_ = l.dotListener.Close()
	}
	if l.dohListener != nil {
		_ = l.dohListener.Close()
	}

	return nil
}

// handleDNS handles incoming DNS queries across UDP, TCP, and DoT.
func (l *DNSServerListener) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := ""
	if w != nil && w.RemoteAddr() != nil {
		if host, _, err := net.SplitHostPort(w.RemoteAddr().String()); err == nil {
			clientIP = host
		} else {
			clientIP = w.RemoteAddr().String()
		}
	}
	resp := l.processQuery(r, clientIP)
	_ = w.WriteMsg(resp)
}

// HandleDoH handles DNS over HTTPS requests according to RFC 8484.
func (l *DNSServerListener) HandleDoH(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rawMsg []byte
	var err error

	if r.Method == http.MethodPost {
		rawMsg, err = io.ReadAll(io.LimitReader(r.Body, 65536))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
	} else {
		// GET query parameter "dns" base64url encoded per RFC 8484 §4.1
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		cleanParam := strings.TrimRight(dnsParam, "=")
		rawMsg, err = base64.RawURLEncoding.DecodeString(cleanParam)
		if err != nil {
			rawMsg, err = base64.URLEncoding.DecodeString(dnsParam)
			if err != nil {
				rawMsg, err = base64.StdEncoding.DecodeString(dnsParam)
			}
		}
		if err != nil {
			http.Error(w, "Invalid dns parameter", http.StatusBadRequest)
			return
		}
	}

	reqMsg := new(dns.Msg)
	if err := reqMsg.Unpack(rawMsg); err != nil {
		http.Error(w, "Malformed DNS wire message", http.StatusBadRequest)
		return
	}

	clientIP := ""
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	} else {
		clientIP = r.RemoteAddr
	}

	respMsg := l.processQuery(reqMsg, clientIP)
	packedResp, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to serialize DNS response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(packedResp)
}

// processQuery processes a DNS query, decodes chunk metadata, updates ledger, and crafts response.
func (l *DNSServerListener) processQuery(r *dns.Msg, clientIP string) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	if len(r.Question) == 0 {
		return resp
	}

	q := r.Question[0]
	name := strings.TrimSuffix(q.Name, ".")
	parts := strings.Split(name, ".")

	// Expect schema: [seq].[total].[token_hex].[b32_chunk].[domain...]
	if len(parts) < 4 {
		return resp
	}

	seqVal, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return resp
	}
	totalVal, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return resp
	}

	token, err := common.ParseSessionToken(parts[2])
	if err != nil {
		return resp
	}

	b32Chunk := parts[3]
	payload, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(b32Chunk))
	if err != nil {
		return resp
	}

	seq := uint32(seqVal)
	total := uint32(totalVal)

	var session *common.Session
	if l.ledger != nil {
		protoName := common.ProtoDNSA
		if q.Qtype == dns.TypeTXT {
			protoName = common.ProtoDNSTXT
		}
		sess, _, _ := l.ledger.AssembleChunkWithMeta(token, seq, total, payload, "", clientIP, protoName, 53, clientIP, "")
		session = sess
	}

	switch q.Qtype {
	case dns.TypeA:
		// Encode ACK sequence into loopback IPv4: 127.(seq>>16).(seq>>8).(seq)
		ackIP := net.IPv4(127, byte(seq>>16), byte(seq>>8), byte(seq))
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: ackIP,
		}
		resp.Answer = append(resp.Answer, rr)

	case dns.TypeTXT:
		// Encode ACK into TXT: ACK:[seq]:[received]/[total]:[hash]
		received := seq
		hash := ""
		if session != nil {
			received = uint32(session.ReceivedChunks)
			hash = session.PayloadHash
		}
		txtMsg := fmt.Sprintf("ACK:%d:%d/%d:%s", seq, received, total, hash)
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			Txt: []string{txtMsg},
		}
		resp.Answer = append(resp.Answer, rr)
	}

	return resp
}
