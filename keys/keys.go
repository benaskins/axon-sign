// Package keys provides Ed25519 keypair generation and public key serialization.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
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
