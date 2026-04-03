// Package sign provides raw Ed25519 signing and verification with detached signature files.
package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/benaskins/axon-sign/keys"
)

// Sign signs data with the given private key and returns a base64-encoded signature.
func Sign(data []byte, priv keys.PrivateKey) (string, error) {
	sig := ed25519.Sign(ed25519.PrivateKey(priv), data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify decodes a base64-encoded signature and verifies it against data using the public key.
// Returns false (not an error) when the signature is valid but does not match.
func Verify(data []byte, sig string, pub keys.PublicKey) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("verify: decode signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false, errors.New("verify: invalid signature length")
	}
	// ed25519.Verify uses constant-time comparison internally.
	return ed25519.Verify(ed25519.PublicKey(pub), data, sigBytes), nil
}

// SignFile reads the file at path and returns a base64-encoded signature over its contents.
func SignFile(path string, priv keys.PrivateKey) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("sign file: read %q: %w", path, err)
	}
	return Sign(data, priv)
}

// WriteSigFile writes a detached signature file to {path}.sig containing the signature
// and the signer's public key fingerprint.
func WriteSigFile(path string, sig string, pubFingerprint string) error {
	contents := fmt.Sprintf("signature: %s\nfingerprint: %s\n", sig, pubFingerprint)
	if err := os.WriteFile(path+".sig", []byte(contents), 0o644); err != nil {
		return fmt.Errorf("write sig file: %w", err)
	}
	return nil
}
