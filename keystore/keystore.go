// Package keystore provides storage and retrieval of named Ed25519 signing keys.
package keystore

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/benaskins/axon-sign/keys"
	"golang.org/x/crypto/ssh"
)

// Keystore defines storage operations for named signing keys.
type Keystore interface {
	StoreKey(name string, pub keys.PublicKey, encryptedPriv []byte) error
	LoadKey(name string) (keys.PublicKey, []byte, error)
	ListKeys() ([]string, error)
	DeleteKey(name string) error
	// MarkRotated renames the active key files to rotated variants so they are
	// preserved for multi-key signature verification after a key rotation.
	MarkRotated(name string) error
	// LoadRotatedKeys returns the public keys of all rotated versions of name,
	// in rotation order (oldest first).
	LoadRotatedKeys(name string) ([]keys.PublicKey, error)
}

// FSKeystore is a filesystem-backed Keystore.
// Each key is stored as two files in a directory:
//   - {name}.pub  — public key in OpenSSH authorized_keys format
//   - {name}.key  — AES-256-GCM encrypted private key PEM
//
// Rotated keys are renamed to {name}.pub.rotated.N / {name}.key.rotated.N
// where N is a zero-based rotation index.
type FSKeystore struct {
	dir string
}

// NewFSKeystore returns an FSKeystore rooted at dir, creating the directory if
// it does not exist.
func NewFSKeystore(dir string) (*FSKeystore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create keystore dir: %w", err)
	}
	return &FSKeystore{dir: dir}, nil
}

// StoreKey writes pub (authorized_keys format) and encryptedPriv (PEM) to disk.
func (fs *FSKeystore) StoreKey(name string, pub keys.PublicKey, encryptedPriv []byte) error {
	pubPath := filepath.Join(fs.dir, name+".pub")
	keyPath := filepath.Join(fs.dir, name+".key")

	if err := os.WriteFile(pubPath, []byte(pub.MarshalAuthorizedKey()), 0600); err != nil {
		return fmt.Errorf("store public key: %w", err)
	}
	if err := os.WriteFile(keyPath, encryptedPriv, 0600); err != nil {
		_ = os.Remove(pubPath)
		return fmt.Errorf("store private key: %w", err)
	}
	return nil
}

// LoadKey reads the active key pair for name from disk.
func (fs *FSKeystore) LoadKey(name string) (keys.PublicKey, []byte, error) {
	pubPath := filepath.Join(fs.dir, name+".pub")
	keyPath := filepath.Join(fs.dir, name+".key")

	pub, err := loadPublicKeyFile(pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load key %q: %w", name, err)
	}

	privData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load key %q: %w", name, err)
	}

	return pub, privData, nil
}

// ListKeys returns the names of all active (non-rotated) keys, sorted.
func (fs *FSKeystore) ListKeys() ([]string, error) {
	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		// Active public key files end in exactly ".pub" with no ".rotated" in the name.
		if strings.HasSuffix(n, ".pub") && !strings.Contains(n, ".rotated") {
			names = append(names, strings.TrimSuffix(n, ".pub"))
		}
	}
	sort.Strings(names)
	return names, nil
}

// DeleteKey removes both key files for name.
func (fs *FSKeystore) DeleteKey(name string) error {
	pubPath := filepath.Join(fs.dir, name+".pub")
	keyPath := filepath.Join(fs.dir, name+".key")

	var msgs []string
	for _, p := range []string{pubPath, keyPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			msgs = append(msgs, err.Error())
		}
	}
	if len(msgs) > 0 {
		return fmt.Errorf("delete key %q: %s", name, strings.Join(msgs, "; "))
	}
	return nil
}

// MarkRotated renames the active key files to rotated variants so they are
// preserved for multi-key signature verification after a key rotation.
// Rotated files are named {name}.pub.rotated.N / {name}.key.rotated.N where N
// is the next available zero-based index.
func (fs *FSKeystore) MarkRotated(name string) error {
	n := fs.nextRotationIndex(name)
	suffix := fmt.Sprintf(".rotated.%d", n)

	pubSrc := filepath.Join(fs.dir, name+".pub")
	pubDst := filepath.Join(fs.dir, name+".pub"+suffix)
	keySrc := filepath.Join(fs.dir, name+".key")
	keyDst := filepath.Join(fs.dir, name+".key"+suffix)

	if err := os.Rename(pubSrc, pubDst); err != nil {
		return fmt.Errorf("mark rotated (pub) for %q: %w", name, err)
	}
	if err := os.Rename(keySrc, keyDst); err != nil {
		_ = os.Rename(pubDst, pubSrc) // attempt rollback
		return fmt.Errorf("mark rotated (key) for %q: %w", name, err)
	}
	return nil
}

// LoadRotatedKeys returns the public keys of all rotated versions of name, in
// rotation order (oldest first).
func (fs *FSKeystore) LoadRotatedKeys(name string) ([]keys.PublicKey, error) {
	pattern := filepath.Join(fs.dir, name+".pub.rotated.*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("load rotated keys for %q: %w", name, err)
	}
	sort.Strings(matches)

	result := make([]keys.PublicKey, 0, len(matches))
	for _, path := range matches {
		pub, err := loadPublicKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("load rotated key %q: %w", path, err)
		}
		result = append(result, pub)
	}
	return result, nil
}

// nextRotationIndex returns the next available rotation index for name.
func (fs *FSKeystore) nextRotationIndex(name string) int {
	pattern := filepath.Join(fs.dir, name+".pub.rotated.*")
	matches, _ := filepath.Glob(pattern)
	return len(matches)
}

// loadPublicKeyFile reads an OpenSSH authorized_keys file and returns the
// Ed25519 public key it contains.
func loadPublicKeyFile(path string) (keys.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse authorized key: %w", err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected SSH key type")
	}
	ed25519Pub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return keys.PublicKey(ed25519Pub), nil
}
