// Package rotation provides key rotation for named Ed25519 signing keys.
package rotation

import (
	"fmt"

	"github.com/benaskins/axon-sign/keystore"
	"github.com/benaskins/axon-sign/keys"
)

// RotateKey generates a fresh Ed25519 keypair for name, stores it as the
// active key in ks, and marks the previous active key as rotated so it
// remains available for historical signature verification.
// The new private key is encrypted with passphrase before storage.
// Returns the new public key.
func RotateKey(ks keystore.Keystore, name string, passphrase []byte) (keys.PublicKey, error) {
	// Archive the current key before overwriting.
	if err := ks.MarkRotated(name); err != nil {
		return nil, fmt.Errorf("rotate key %q: mark rotated: %w", name, err)
	}

	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("rotate key %q: generate: %w", name, err)
	}

	enc, err := keys.EncryptPrivateKey(priv, passphrase)
	if err != nil {
		return nil, fmt.Errorf("rotate key %q: encrypt: %w", name, err)
	}

	if err := ks.StoreKey(name, pub, enc); err != nil {
		return nil, fmt.Errorf("rotate key %q: store: %w", name, err)
	}

	return pub, nil
}
