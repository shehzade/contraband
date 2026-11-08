package certgen

import (
	"crypto/tls"
	"fmt"
	"time"
)

// GenerateTLSCert generates an ephemeral in-memory TLS certificate. If a CA is provided,
// it signs the certificate using the CA; otherwise, it creates an ephemeral Root CA and signs the leaf.
func GenerateTLSCert(hosts []string, ca *CertificateAuthority) (*tls.Certificate, error) {
	if ca == nil {
		var err error
		ca, err = NewCA("Contraband Ephemeral CA")
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral CA: %w", err)
		}
	}

	certPEM, keyPEM, err := ca.SignServerCert(hosts, 30*24*time.Hour)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 key pair: %w", err)
	}
	return &cert, nil
}

// NewServerTLSConfig creates a hardened TLS server configuration pre-loaded with an ephemeral cert.
func NewServerTLSConfig(hosts []string, ca *CertificateAuthority) (*tls.Config, error) {
	cert, err := GenerateTLSCert(hosts, ca)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}, nil
}

// NewClientTLSConfig creates a TLS client configuration trusting the provided CA CertPool.
func NewClientTLSConfig(ca *CertificateAuthority, serverName string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if ca != nil {
		cfg.RootCAs = ca.CertPool()
	}
	return cfg
}
