package listeners

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/shehzade/contraband/pkg/common"
	"github.com/shehzade/contraband/pkg/server"
	"github.com/shehzade/contraband/pkg/server/certgen"
)

// SMTPServerListener provides a multi-port in-memory SMTP / SMTPS server listener.
// Uploaded chunks sent via MIME attachments or headers/body are extracted in memory
// and passed directly to ledger.AssembleChunk with zero disk writes.
type SMTPServerListener struct {
	mu             sync.Mutex
	bindAddr       string
	plainPort      int
	smtpsPort      int
	submissionPort int

	boundPlain      int
	boundSMTPS      int
	boundSubmission int

	tlsConfig *tls.Config
	ledger    server.Ledger

	plainSrv      *gosmtp.Server
	smtpsSrv      *gosmtp.Server
	submissionSrv *gosmtp.Server

	plainLn      net.Listener
	smtpsLn      net.Listener
	submissionLn net.Listener

	cancel context.CancelFunc
	closed bool
}

// NewSMTPServerListener creates a new in-memory SMTP server listener for ports 25, 465, and 587.
func NewSMTPServerListener(bindAddr string, plainPort, smtpsPort, submissionPort int, tlsConfig *tls.Config) *SMTPServerListener {
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	return &SMTPServerListener{
		bindAddr:       bindAddr,
		plainPort:      plainPort,
		smtpsPort:      smtpsPort,
		submissionPort: submissionPort,
		tlsConfig:      tlsConfig,
	}
}

func (l *SMTPServerListener) Name() string {
	return "in_memory_smtp"
}

func (l *SMTPServerListener) Protocol() string {
	return common.ProtoSMTP
}

func (l *SMTPServerListener) Ports() []int {
	l.mu.Lock()
	defer l.mu.Unlock()
	var ports []int
	if l.boundPlain > 0 {
		ports = append(ports, l.boundPlain)
	} else if l.plainPort > 0 {
		ports = append(ports, l.plainPort)
	}
	if l.boundSMTPS > 0 {
		ports = append(ports, l.boundSMTPS)
	} else if l.smtpsPort > 0 {
		ports = append(ports, l.smtpsPort)
	}
	if l.boundSubmission > 0 {
		ports = append(ports, l.boundSubmission)
	} else if l.submissionPort > 0 {
		ports = append(ports, l.submissionPort)
	}
	return ports
}

// BoundPorts returns the actual bound plain, smtps, and submission ports.
func (l *SMTPServerListener) BoundPorts() (plain, smtps, submission int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPlain, l.boundSMTPS, l.boundSubmission
}

// Start initiates the SMTP listeners.
func (l *SMTPServerListener) Start(ctx context.Context, ledger server.Ledger) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return errors.New("smtp server listener already stopped")
	}

	l.ledger = ledger
	ctx, l.cancel = context.WithCancel(ctx)

	// Ensure TLS config
	if l.tlsConfig == nil {
		tlsCfg, err := certgen.NewServerTLSConfig([]string{"localhost", "127.0.0.1", l.bindAddr}, nil)
		if err != nil {
			return fmt.Errorf("failed to generate tls config for smtp: %w", err)
		}
		l.tlsConfig = tlsCfg
	}

	backend := &smtpBackend{
		listener: l,
	}

	// 1. Plain SMTP listener (e.g. port 25) with STARTTLS support
	if l.plainPort >= 0 {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, l.plainPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind plain smtp port %d: %w", l.plainPort, err)
		}
		l.plainLn = ln
		l.boundPlain = ln.Addr().(*net.TCPAddr).Port

		s := gosmtp.NewServer(backend)
		s.Addr = ln.Addr().String()
		s.Domain = "contraband.local"
		s.TLSConfig = l.tlsConfig
		s.AllowInsecureAuth = true
		s.ReadTimeout = 30 * time.Second
		s.WriteTimeout = 30 * time.Second
		l.plainSrv = s

		go func() {
			_ = s.Serve(ln)
		}()
	}

	// 2. Implicit SMTPS listener (e.g. port 465)
	if l.smtpsPort >= 0 && l.tlsConfig != nil {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, l.smtpsPort)
		rawLn, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind smtps port %d: %w", l.smtpsPort, err)
		}
		tlsLn := tls.NewListener(rawLn, l.tlsConfig)
		l.smtpsLn = tlsLn
		l.boundSMTPS = rawLn.Addr().(*net.TCPAddr).Port

		s := gosmtp.NewServer(backend)
		s.Addr = rawLn.Addr().String()
		s.Domain = "contraband.local"
		s.AllowInsecureAuth = true
		s.ReadTimeout = 30 * time.Second
		s.WriteTimeout = 30 * time.Second
		l.smtpsSrv = s

		go func() {
			_ = s.Serve(tlsLn)
		}()
	}

	// 3. Submission listener (e.g. port 587) with STARTTLS
	if l.submissionPort >= 0 {
		addr := fmt.Sprintf("%s:%d", l.bindAddr, l.submissionPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			l.stopInternal()
			return fmt.Errorf("failed to bind submission smtp port %d: %w", l.submissionPort, err)
		}
		l.submissionLn = ln
		l.boundSubmission = ln.Addr().(*net.TCPAddr).Port

		s := gosmtp.NewServer(backend)
		s.Addr = ln.Addr().String()
		s.Domain = "contraband.local"
		s.TLSConfig = l.tlsConfig
		s.AllowInsecureAuth = true
		s.ReadTimeout = 30 * time.Second
		s.WriteTimeout = 30 * time.Second
		l.submissionSrv = s

		go func() {
			_ = s.Serve(ln)
		}()
	}

	return nil
}

func (l *SMTPServerListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stopInternal()
}

func (l *SMTPServerListener) stopInternal() error {
	if l.closed {
		return nil
	}
	l.closed = true

	if l.cancel != nil {
		l.cancel()
	}

	if l.plainSrv != nil {
		_ = l.plainSrv.Close()
	}
	if l.plainLn != nil {
		_ = l.plainLn.Close()
	}

	if l.smtpsSrv != nil {
		_ = l.smtpsSrv.Close()
	}
	if l.smtpsLn != nil {
		_ = l.smtpsLn.Close()
	}

	if l.submissionSrv != nil {
		_ = l.submissionSrv.Close()
	}
	if l.submissionLn != nil {
		_ = l.submissionLn.Close()
	}

	return nil
}

// -----------------------------------------------------------------------------
// go-smtp Backend & Session Implementation
// -----------------------------------------------------------------------------

type smtpBackend struct {
	listener *SMTPServerListener
}

func (b *smtpBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	clientIP := ""
	if c.Conn() != nil && c.Conn().RemoteAddr() != nil {
		clientIP, _, _ = net.SplitHostPort(c.Conn().RemoteAddr().String())
	}
	return &smtpSession{
		listener: b.listener,
		clientIP: clientIP,
	}, nil
}

type smtpSession struct {
	listener *SMTPServerListener
	clientIP string
	from     string
	to       []string
}

func (s *smtpSession) Reset() {
	s.from = ""
	s.to = nil
}

func (s *smtpSession) Logout() error {
	return nil
}

func (s *smtpSession) Mail(from string, opts *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *smtpSession) Rcpt(to string, opts *gosmtp.RcptOptions) error {
	s.to = append(s.to, to)
	return nil
}

func (s *smtpSession) AuthMechanisms() []string {
	return []string{sasl.Plain, sasl.Login}
}

func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if s.listener.ledger != nil {
				_ = s.listener.ledger.RecordCredential(common.CapturedCredential{
					Protocol:  common.ProtoSMTP,
					Timestamp: time.Now().UTC(),
					ClientIP:  s.clientIP,
					Username:  username,
					HashType:  "plaintext",
					Hash:      password,
				})
			}
			if username == "reject" {
				return errors.New("authentication rejected")
			}
			return nil
		}), nil
	case sasl.Login:
		return sasl.NewLoginServer(func(username, password string) error {
			if s.listener.ledger != nil {
				_ = s.listener.ledger.RecordCredential(common.CapturedCredential{
					Protocol:  common.ProtoSMTP,
					Timestamp: time.Now().UTC(),
					ClientIP:  s.clientIP,
					Username:  username,
					HashType:  "plaintext",
					Hash:      password,
				})
			}
			if username == "reject" {
				return errors.New("authentication rejected")
			}
			return nil
		}), nil
	default:
		return nil, gosmtp.ErrAuthUnknownMechanism
	}
}

// Data receives the SMTP email message body, extracts forensic headers and chunks,
// and passes directly to ledger.AssembleChunk with zero disk writes.
func (s *smtpSession) Data(r io.Reader) error {
	rawBytes, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	msg, err := mail.ReadMessage(bytes.NewReader(rawBytes))
	if err != nil {
		return err
	}

	headerTokenHex := msg.Header.Get("X-CTRB-Session-ID")
	headerSeq := msg.Header.Get("X-CTRB-Sequence")
	headerTotal := msg.Header.Get("X-CTRB-Total-Chunks")
	headerHash := msg.Header.Get("X-CTRB-Payload-Hash")

	var chunkBytes []byte

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		// MIME multipart attachment parsing
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, pErr := mr.NextPart()
			if pErr != nil {
				break
			}
			partBytes, _ := io.ReadAll(p)
			if strings.EqualFold(p.Header.Get("Content-Transfer-Encoding"), "base64") {
				cleaned := cleanBase64(string(partBytes))
				if decoded, decErr := base64.StdEncoding.DecodeString(cleaned); decErr == nil {
					partBytes = decoded
				}
			}
			// Look for chunk header in this part
			if len(partBytes) >= common.ChunkHeaderSize {
				var hdr common.ChunkHeader
				if uErr := hdr.UnmarshalBinary(partBytes[:common.ChunkHeaderSize]); uErr == nil {
					chunkBytes = partBytes
					break
				}
			}
			if len(partBytes) > 0 && chunkBytes == nil {
				chunkBytes = partBytes
			}
		}
	} else {
		// Single part / body embedding mode
		bodyBytes, _ := io.ReadAll(msg.Body)
		if strings.EqualFold(msg.Header.Get("Content-Transfer-Encoding"), "base64") {
			cleaned := cleanBase64(string(bodyBytes))
			if decoded, decErr := base64.StdEncoding.DecodeString(cleaned); decErr == nil {
				bodyBytes = decoded
			}
		}
		chunkBytes = bodyBytes
	}

	if len(chunkBytes) == 0 {
		return nil
	}

	if s.listener.ledger == nil {
		return nil
	}

	// 1. Try unpacking 32-byte ChunkHeader directly from chunkBytes
	if len(chunkBytes) >= common.ChunkHeaderSize {
		var hdr common.ChunkHeader
		if err := hdr.UnmarshalBinary(chunkBytes[:common.ChunkHeaderSize]); err == nil {
			payload := chunkBytes[common.ChunkHeaderSize:]
			if int(hdr.PayloadLen) <= len(payload) {
				payload = payload[:hdr.PayloadLen]
			}
			_, _, _ = s.listener.ledger.AssembleChunkWithMeta(hdr.Token, hdr.Sequence, hdr.TotalChunks, payload, headerHash, s.clientIP, common.ProtoSMTP, 25, s.clientIP, "")
			return nil
		}
	}

	// 2. Fall back to parsing forensic headers
	if headerTokenHex != "" && headerSeq != "" && headerTotal != "" {
		token, parseErr := common.ParseSessionToken(headerTokenHex)
		if parseErr == nil {
			seqVal, _ := strconv.ParseUint(headerSeq, 10, 32)
			totVal, _ := strconv.ParseUint(headerTotal, 10, 32)
			_, _, _ = s.listener.ledger.AssembleChunkWithMeta(token, uint32(seqVal), uint32(totVal), chunkBytes, headerHash, s.clientIP, common.ProtoSMTP, 25, s.clientIP, "")
		}
	}

	return nil
}

func cleanBase64(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
}
