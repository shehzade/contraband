package evasion

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PBKDF2Iterations = 100000
	SaltSize         = 32
	NonceSize        = 12
	KeySize          = 32 // AES-256
)

func DeriveKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, PBKDF2Iterations, KeySize, sha256.New)
}

func EncryptAESGCM(plaintext []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid AES-256 key size: expected %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}
	// Seal appends ciphertext + 16-byte auth tag to nonce
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func DecryptAESGCM(ciphertextWithNonce []byte, key []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid AES-256 key size: expected %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertextWithNonce) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short (missing nonce)")
	}
	nonce := ciphertextWithNonce[:gcm.NonceSize()]
	ciphertext := ciphertextWithNonce[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func EncryptWithPassphrase(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	key := DeriveKey(passphrase, salt)
	encrypted, err := EncryptAESGCM(plaintext, key)
	if err != nil {
		return nil, err
	}
	// Layout: [Salt (32B)][Nonce (12B)][Ciphertext + Tag]
	out := make([]byte, SaltSize+len(encrypted))
	copy(out[:SaltSize], salt)
	copy(out[SaltSize:], encrypted)
	return out, nil
}

func DecryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	if len(data) < SaltSize+NonceSize+16 {
		return nil, errors.New("data too short for salt + nonce + tag")
	}
	salt := data[:SaltSize]
	ciphertextWithNonce := data[SaltSize:]
	key := DeriveKey(passphrase, salt)
	return DecryptAESGCM(ciphertextWithNonce, key)
}
