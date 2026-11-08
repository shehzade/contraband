package certgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// SSHHostKey holds the generated ephemeral SSH host key and credentials.
type SSHHostKey struct {
	Signer    ssh.Signer
	PublicKey ssh.PublicKey
	PrivPEM   []byte
}

// GenerateSSHHostKey creates an ephemeral in-memory Ed25519 SSH host key for SFTP.
func GenerateSSHHostKey() (*SSHHostKey, error) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create ssh signer from ed25519 key: %w", err)
	}

	privBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ssh private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(privBlock)

	return &SSHHostKey{
		Signer:    signer,
		PublicKey: signer.PublicKey(),
		PrivPEM:   privPEM,
	}, nil
}

// AuthorizedKeyString returns the OpenSSH authorized_keys format string.
func (k *SSHHostKey) AuthorizedKeyString(comment string) string {
	if comment == "" {
		comment = "contraband-ephemeral-sftp"
	}
	return fmt.Sprintf("%s %s", string(ssh.MarshalAuthorizedKey(k.PublicKey)), comment)
}

// NewSSHServerConfig configures an SSH server for the SFTP listener with the host key.
func NewSSHServerConfig(hostKey *SSHHostKey, authCallback func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		PasswordCallback: authCallback,
	}
	cfg.AddHostKey(hostKey.Signer)
	return cfg
}
