// Package keys provides Ed25519 keypair generation and public key serialization.
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
	saltLen       = 16
)

// PrivateKey wraps an Ed25519 private key.
type PrivateKey ed25519.PrivateKey

// PublicKey wraps an Ed25519 public key.
type PublicKey ed25519.PublicKey

// GenerateKeyPair generates a new Ed25519 keypair.
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}
	return PublicKey(pub), PrivateKey(priv), nil
}

// MarshalAuthorizedKey returns the public key in OpenSSH authorized_keys wire format.
func (pub PublicKey) MarshalAuthorizedKey() string {
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return ""
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// MarshalPEM returns the public key as PEM-encoded SubjectPublicKeyInfo.
func (pub PublicKey) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

// EncryptPrivateKey encrypts a private key with a passphrase using AES-256-GCM and Argon2id KDF.
// The result is a PEM block of type "ENCRYPTED PRIVATE KEY" with Argon2id-Salt and Argon2id-Nonce headers.
func EncryptPrivateKey(key PrivateKey, passphrase []byte) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	dk := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range dk {
			dk[i] = 0
		}
	}()

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	keyBytes := []byte(key)
	ciphertext := gcm.Seal(nil, nonce, keyBytes, nil)

	pemBlock := &pem.Block{
		Type: "ENCRYPTED PRIVATE KEY",
		Headers: map[string]string{
			"Argon2id-Salt":  base64.StdEncoding.EncodeToString(salt),
			"Argon2id-Nonce": base64.StdEncoding.EncodeToString(nonce),
		},
		Bytes: ciphertext,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// DecryptPrivateKey decrypts a PEM-encoded encrypted private key using the given passphrase.
func DecryptPrivateKey(pemData []byte, passphrase []byte) (PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("decrypt private key: invalid PEM data")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, errors.New("decrypt private key: unexpected PEM type")
	}

	saltB64, ok := block.Headers["Argon2id-Salt"]
	if !ok {
		return nil, errors.New("decrypt private key: missing salt header")
	}
	nonceB64, ok := block.Headers["Argon2id-Nonce"]
	if !ok {
		return nil, errors.New("decrypt private key: missing nonce header")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, errors.New("decrypt private key: invalid salt encoding")
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, errors.New("decrypt private key: invalid nonce encoding")
	}

	dk := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	defer func() {
		for i := range dk {
			dk[i] = 0
		}
	}()

	aesCipher, err := aes.NewCipher(dk)
	if err != nil {
		return nil, errors.New("decrypt private key: cipher initialisation failed")
	}
	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, errors.New("decrypt private key: GCM initialisation failed")
	}

	plaintext, err := gcm.Open(nil, nonce, block.Bytes, nil)
	if err != nil {
		return nil, errors.New("decrypt private key: decryption failed")
	}

	return PrivateKey(plaintext), nil
}

// Fingerprint returns the SHA-256 fingerprint of the public key as colon-separated hex.
func (pub PublicKey) Fingerprint() string {
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(pub))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(sshPub.Marshal())
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
