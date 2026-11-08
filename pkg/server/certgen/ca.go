package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CertificateAuthority represents an ephemeral dynamic in-memory Root CA.
type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
}

// NewCA generates a self-signed ephemeral root CA with ECDSA P-256.
func NewCA(commonName string) (*CertificateAuthority, error) {
	if commonName == "" {
		commonName = "Contraband Dynamic Root CA"
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA serial number: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Contraband Security Framework"},
		},
		NotBefore:             now.Add(-1 * time.Hour), // Clock skew buffer
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create self-signed CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// LoadCA parses existing PEM-encoded certificate and private key blocks.
func LoadCA(certPEM, keyPEM []byte) (*CertificateAuthority, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode valid CERTIFICATE PEM block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}

	var privKey crypto.Signer
	if keyBlock.Type == "EC PRIVATE KEY" {
		ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		privKey = ecKey
	} else if keyBlock.Type == "PRIVATE KEY" {
		pk, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		signer, ok := pk.(crypto.Signer)
		if !ok {
			return nil, errors.New("parsed private key is not a crypto.Signer")
		}
		privKey = signer
	} else {
		return nil, fmt.Errorf("unsupported private key PEM type: %s", keyBlock.Type)
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  privKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// CertPool returns an x509 CertPool containing this CA cert for client verification.
func (ca *CertificateAuthority) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Certificate)
	return pool
}

// SignServerCert issues and signs a leaf TLS certificate for the specified hosts.
func (ca *CertificateAuthority) SignServerCert(hosts []string, validFor time.Duration) ([]byte, []byte, error) {
	if validFor <= 0 {
		validFor = 30 * 24 * time.Hour
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate server serial: %w", err)
	}

	now := time.Now().UTC()
	cn := "localhost"
	if len(hosts) > 0 && hosts[0] != "" {
		cn = hosts[0]
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Contraband Dynamic Server"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.Add(validFor),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Categorize DNS names vs IP addresses in SANs
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	// Always include loopback SANs
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	template.DNSNames = append(template.DNSNames, "localhost")

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, &privKey.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign server cert with CA: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal server private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM, nil
}
