package exfil

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"google.golang.org/grpc/credentials"
)

// TLSConfig configures uTLS client masquerading.
type TLSConfig struct {
	ServerName         string
	InsecureSkipVerify bool
	Fingerprint        string // chrome, edge, safari, firefox, curl, default
	ALPN               []string
	RootCAs            *x509.CertPool
	MinVersion         uint16
	MaxVersion         uint16
}

// MasqueradeConn wraps a uTLS connection and exposes computed JA3/JA4 fingerprints.
type MasqueradeConn struct {
	net.Conn
	uconn   *utls.UConn
	JA3Raw  string
	JA3Hash string
	JA4     string
	Profile string
}

// ConnectionState maps utls.ConnectionState to crypto/tls.ConnectionState for standard library callers.
func (m *MasqueradeConn) ConnectionState() tls.ConnectionState {
	if m.uconn == nil {
		return tls.ConnectionState{}
	}
	return convertUTLSToCryptoTLS(m.uconn.ConnectionState())
}

// NegotiatedProtocol returns the ALPN string negotiated during handshake.
func (m *MasqueradeConn) NegotiatedProtocol() string {
	if m.uconn == nil {
		return ""
	}
	return m.uconn.ConnectionState().NegotiatedProtocol
}

// GetJA3 returns raw JA3 and MD5 hash.
func (m *MasqueradeConn) GetJA3() (string, string) {
	return m.JA3Raw, m.JA3Hash
}

// GetJA4 returns the computed JA4 fingerprint.
func (m *MasqueradeConn) GetJA4() string {
	return m.JA4
}

// GetUConn returns underlying utls.UConn.
func (m *MasqueradeConn) GetUConn() *utls.UConn {
	return m.uconn
}

// ResolveClientHelloID maps string presets to utls.ClientHelloID.
func ResolveClientHelloID(profile string) (utls.ClientHelloID, bool) {
	switch strings.ToLower(profile) {
	case "chrome":
		return utls.HelloChrome_120, true
	case "edge":
		return utls.HelloEdge_Auto, true
	case "safari":
		return utls.HelloSafari_Auto, true
	case "firefox":
		return utls.HelloFirefox_Auto, true
	case "curl":
		return utls.HelloChrome_58, true
	case "default":
		return utls.HelloGolang, true
	default:
		return utls.HelloChrome_120, false
	}
}

// isGREASE checks if a 16-bit value is a TLS GREASE identifier.
func isGREASE(val uint16) bool {
	return (val&0x0f0f) == 0x0a0a && (val>>8) == (val&0xff)
}

func extractExtensionID(ext utls.TLSExtension) (id uint16, ok bool, sigAlgs []uint16) {
	switch e := ext.(type) {
	case *utls.SNIExtension:
		return 0x0000, true, nil
	case *utls.StatusRequestExtension:
		return 0x0005, true, nil
	case *utls.SupportedCurvesExtension:
		return 0x000a, true, nil
	case *utls.SupportedPointsExtension:
		return 0x000b, true, nil
	case *utls.SignatureAlgorithmsExtension:
		var sa []uint16
		for _, s := range e.SupportedSignatureAlgorithms {
			sa = append(sa, uint16(s))
		}
		return 0x000d, true, sa
	case *utls.ALPNExtension:
		return 0x0010, true, nil
	case *utls.SCTExtension:
		return 0x0012, true, nil
	case *utls.ExtendedMasterSecretExtension:
		return 0x0017, true, nil
	case *utls.SessionTicketExtension:
		return 0x0023, true, nil
	case *utls.PSKKeyExchangeModesExtension:
		return 0x002d, true, nil
	case *utls.KeyShareExtension:
		return 0x0033, true, nil
	case *utls.SupportedVersionsExtension:
		return 0x002b, true, nil
	case *utls.RenegotiationInfoExtension:
		return 0xff01, true, nil
	case *utls.UtlsCompressCertExtension:
		return 0x001b, true, nil
	case *utls.ApplicationSettingsExtension:
		return 0x44cd, true, nil
	case *utls.UtlsPaddingExtension:
		return 0x0015, true, nil
	case *utls.GenericExtension:
		return e.Id, true, nil
	case *utls.UtlsGREASEExtension:
		return 0, false, nil
	case *utls.GREASEEncryptedClientHelloExtension:
		return 0, false, nil
	default:
		return 0, false, nil
	}
}

// CalculateJA3 computes raw JA3 and its MD5 hash from a configured uTLS connection.
func CalculateJA3(uconn *utls.UConn) (string, string) {
	if uconn == nil || uconn.HandshakeState.Hello == nil {
		return "", ""
	}
	hello := uconn.HandshakeState.Hello
	ver := hello.Vers

	var ciphers []string
	for _, c := range hello.CipherSuites {
		if !isGREASE(c) {
			ciphers = append(ciphers, fmt.Sprintf("%d", c))
		}
	}

	var exts []string
	for _, ext := range uconn.Extensions {
		id, ok, _ := extractExtensionID(ext)
		if ok && !isGREASE(id) {
			exts = append(exts, fmt.Sprintf("%d", id))
		}
	}

	var curves []string
	for _, cv := range hello.SupportedCurves {
		if !isGREASE(uint16(cv)) {
			curves = append(curves, fmt.Sprintf("%d", cv))
		}
	}

	var points []string
	for _, pt := range hello.SupportedPoints {
		points = append(points, fmt.Sprintf("%d", pt))
	}

	raw := fmt.Sprintf("%d,%s,%s,%s,%s",
		ver,
		strings.Join(ciphers, "-"),
		strings.Join(exts, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)
	h := md5.Sum([]byte(raw))
	return raw, hex.EncodeToString(h[:])
}

// CalculateJA4 computes the FoxIO standard JA4 string (JA4_a_JA4_b_JA4_c).
func CalculateJA4(uconn *utls.UConn) string {
	if uconn == nil || uconn.HandshakeState.Hello == nil {
		return ""
	}
	hello := uconn.HandshakeState.Hello

	proto := "t" // TCP
	ver := "12"
	for _, v := range hello.SupportedVersions {
		if v == 0x0304 {
			ver = "13"
			break
		}
	}

	sni := "i"
	if hello.ServerName != "" && net.ParseIP(hello.ServerName) == nil {
		sni = "d"
	}

	var cipherList []string
	for _, c := range hello.CipherSuites {
		if !isGREASE(c) {
			cipherList = append(cipherList, fmt.Sprintf("%04x", c))
		}
	}

	var ja4ExtList []string
	var allExtList []string
	var sigAlgs []string

	for _, ext := range uconn.Extensions {
		id, ok, sa := extractExtensionID(ext)
		if !ok || isGREASE(id) {
			continue
		}
		allExtList = append(allExtList, fmt.Sprintf("%04x", id))
		if id != 0x0000 && id != 0x0010 { // JA4 excludes SNI (0000) and ALPN (0010)
			ja4ExtList = append(ja4ExtList, fmt.Sprintf("%04x", id))
		}
		for _, s := range sa {
			if !isGREASE(s) {
				sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", s))
			}
		}
	}

	alpn := "00"
	if len(hello.AlpnProtocols) > 0 && len(hello.AlpnProtocols[0]) >= 2 {
		first := hello.AlpnProtocols[0]
		alpn = string(first[0]) + string(first[len(first)-1])
	}

	partA := fmt.Sprintf("%s%s%s%02d%02d%s", proto, ver, sni, len(cipherList), len(allExtList), alpn)

	sort.Strings(cipherList)
	bHash := sha256.Sum256([]byte(strings.Join(cipherList, ",")))
	partB := hex.EncodeToString(bHash[:])[:12]

	sort.Strings(ja4ExtList)
	sort.Strings(sigAlgs)
	cRaw := strings.Join(ja4ExtList, ",")
	if len(sigAlgs) > 0 {
		cRaw += "_" + strings.Join(sigAlgs, ",")
	}
	cHash := sha256.Sum256([]byte(cRaw))
	partC := hex.EncodeToString(cHash[:])[:12]

	return fmt.Sprintf("%s_%s_%s", partA, partB, partC)
}

// DialTLS dials a target address over TCP and completes a uTLS masquerade handshake.
func DialTLS(ctx context.Context, network, addr string, cfg TLSConfig) (*MasqueradeConn, error) {
	var d net.Dialer
	rawConn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	return WrapConn(ctx, rawConn, addr, cfg)
}

// WrapConn wraps an established net.Conn with uTLS masquerader.
func WrapConn(ctx context.Context, rawConn net.Conn, addr string, cfg TLSConfig) (*MasqueradeConn, error) {
	helloID, _ := ResolveClientHelloID(cfg.Fingerprint)

	serverName := cfg.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(addr)
		if err == nil {
			serverName = host
		} else {
			serverName = addr
		}
	}

	utlsCfg := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
		NextProtos:         cfg.ALPN,
	}

	uconn := utls.UClient(rawConn, utlsCfg, helloID)
	_ = uconn.BuildHandshakeState()

	if len(cfg.ALPN) > 0 {
		found := false
		for _, ext := range uconn.Extensions {
			if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
				alpnExt.AlpnProtocols = cfg.ALPN
				found = true
				break
			}
		}
		if !found {
			uconn.Extensions = append(uconn.Extensions, &utls.ALPNExtension{AlpnProtocols: cfg.ALPN})
		}
		_ = uconn.BuildHandshakeState()
	}

	ja3Raw, ja3Hash := CalculateJA3(uconn)
	ja4 := CalculateJA4(uconn)

	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("utls handshake failed: %w", err)
	}

	return &MasqueradeConn{
		Conn:    uconn,
		uconn:   uconn,
		JA3Raw:  ja3Raw,
		JA3Hash: ja3Hash,
		JA4:     ja4,
		Profile: cfg.Fingerprint,
	}, nil
}

// NewHTTPTransport creates an *http.Transport configured with uTLS DialTLSContext.
func NewHTTPTransport(cfg TLSConfig) *http.Transport {
	c1 := cfg
	if len(c1.ALPN) == 0 {
		c1.ALPN = []string{"http/1.1"}
	}
	return &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return DialTLS(ctx, network, addr, c1)
		},
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// NewHTTP2Transport creates an *http2.Transport configured with uTLS DialTLSContext.
func NewHTTP2Transport(cfg TLSConfig) *http2.Transport {
	c2 := cfg
	c2.ALPN = []string{"h2"}
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return DialTLS(ctx, network, addr, c2)
		},
		AllowHTTP: false,
	}
}

// convertUTLSToCryptoTLS converts utls.ConnectionState into standard crypto/tls.ConnectionState.
func convertUTLSToCryptoTLS(s utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
	}
}

// utlsGRPCWrap implements credentials.TransportCredentials for gRPC client dialing over uTLS.
type utlsGRPCWrap struct {
	helloID utls.ClientHelloID
	config  *utls.Config
}

// NewGRPCTransportCredentials creates gRPC transport credentials using uTLS masquerading.
func NewGRPCTransportCredentials(cfg TLSConfig) credentials.TransportCredentials {
	helloID, _ := ResolveClientHelloID(cfg.Fingerprint)
	utlsCfg := &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		RootCAs:            cfg.RootCAs,
		MinVersion:         cfg.MinVersion,
		MaxVersion:         cfg.MaxVersion,
		NextProtos:         []string{"h2"},
	}
	return &utlsGRPCWrap{
		helloID: helloID,
		config:  utlsCfg,
	}
}

func (c *utlsGRPCWrap) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	cfg := c.config.Clone()
	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(authority)
		if err == nil {
			cfg.ServerName = host
		} else {
			cfg.ServerName = authority
		}
	}
	uconn := utls.UClient(rawConn, cfg, c.helloID)
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("utls grpc handshake failed: %w", err)
	}
	return uconn, credentials.TLSInfo{State: convertUTLSToCryptoTLS(uconn.ConnectionState())}, nil
}

func (c *utlsGRPCWrap) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("utlsGRPCWrap is client-only")
}

func (c *utlsGRPCWrap) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", ServerName: c.config.ServerName}
}

func (c *utlsGRPCWrap) Clone() credentials.TransportCredentials {
	return &utlsGRPCWrap{helloID: c.helloID, config: c.config.Clone()}
}

func (c *utlsGRPCWrap) OverrideServerName(serverNameOverride string) error {
	c.config.ServerName = serverNameOverride
	return nil
}
