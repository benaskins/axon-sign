// Package sign provides raw Ed25519 signing and verification with detached signature files.
package sign

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/benaskins/axon-sign/keystore"
	"github.com/benaskins/axon-sign/keys"
	"golang.org/x/crypto/ssh"
)

// ManifestEntry records the path, content hash, Ed25519 signature, public key, and
// fingerprint for one file. The PublicKey field (OpenSSH authorized_keys format) is
// required so that VerifyManifest can verify signatures without any external key store.
type ManifestEntry struct {
	Path        string `json:"path"`
	SHA256Hex   string `json:"sha256"`
	Signature   string `json:"signature"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// Manifest holds the signed entries produced by BatchSign.
type Manifest struct {
	Entries []ManifestEntry `json:"entries"`
}

// VerifyResult is the per-entry outcome from VerifyManifest.
type VerifyResult struct {
	Path string
	OK   bool
	Err  error
}

// BatchSign signs each file in paths, writes a .sig file alongside each, and returns a Manifest.
func BatchSign(paths []string, priv keys.PrivateKey, pub keys.PublicKey) (Manifest, error) {
	fingerprint := pub.Fingerprint()
	authorizedKey := strings.TrimSpace(pub.MarshalAuthorizedKey())
	entries := make([]ManifestEntry, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return Manifest{}, fmt.Errorf("batch sign: read %q: %w", p, err)
		}
		sum := sha256.Sum256(data)
		sha256Hex := hex.EncodeToString(sum[:])

		sig, err := Sign(data, priv)
		if err != nil {
			return Manifest{}, fmt.Errorf("batch sign: sign %q: %w", p, err)
		}
		if err := WriteSigFile(p, sig, fingerprint); err != nil {
			return Manifest{}, fmt.Errorf("batch sign: write sig %q: %w", p, err)
		}
		entries = append(entries, ManifestEntry{
			Path:        p,
			SHA256Hex:   sha256Hex,
			Signature:   sig,
			PublicKey:   authorizedKey,
			Fingerprint: fingerprint,
		})
	}
	return Manifest{Entries: entries}, nil
}

// WriteManifest serialises m as JSON to dest.
func WriteManifest(m Manifest, dest string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("write manifest: marshal: %w", err)
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return fmt.Errorf("write manifest: write %q: %w", dest, err)
	}
	return nil
}

// ReadManifest deserialises a Manifest from a JSON file at path.
func ReadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("read manifest: unmarshal: %w", err)
	}
	return m, nil
}

// VerifyManifest re-reads each file referenced in m, verifies its SHA-256 hash and
// Ed25519 signature, and returns a per-entry result. A non-nil top-level error is
// returned only for structural problems; per-file failures appear as VerifyResult.OK == false.
func VerifyManifest(m Manifest) ([]VerifyResult, error) {
	results := make([]VerifyResult, 0, len(m.Entries))
	for _, entry := range m.Entries {
		r := VerifyResult{Path: entry.Path}

		pub, err := parseAuthorizedKey(entry.PublicKey)
		if err != nil {
			r.Err = fmt.Errorf("parse public key: %w", err)
			results = append(results, r)
			continue
		}

		data, err := os.ReadFile(entry.Path)
		if err != nil {
			r.Err = fmt.Errorf("read file: %w", err)
			results = append(results, r)
			continue
		}

		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != entry.SHA256Hex {
			r.Err = errors.New("sha256 mismatch")
			results = append(results, r)
			continue
		}

		ok, err := Verify(data, entry.Signature, pub)
		if err != nil {
			r.Err = fmt.Errorf("signature decode: %w", err)
			results = append(results, r)
			continue
		}
		if !ok {
			r.Err = errors.New("signature verification failed")
			results = append(results, r)
			continue
		}

		r.OK = true
		results = append(results, r)
	}
	return results, nil
}

// parseAuthorizedKey parses an OpenSSH authorized_keys line and returns a keys.PublicKey.
func parseAuthorizedKey(authorizedKey string) (keys.PublicKey, error) {
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, fmt.Errorf("parse authorized key: %w", err)
	}
	cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("parse authorized key: not a crypto public key")
	}
	edPub, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("parse authorized key: not an Ed25519 key")
	}
	return keys.PublicKey(edPub), nil
}


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

// VerifyWithRotation verifies sig against data using the named key from ks. It
// tries the current active key first, then each rotated key in rotation order
// (oldest first). Returns true on the first successful match. Returns false
// (without error) when the key is not found or no key matches the signature.
// The passphrase parameter is accepted for API symmetry with signing helpers
// but is not used during verification.
func VerifyWithRotation(data []byte, sig string, ks keystore.Keystore, name string, passphrase []byte) (bool, error) {
	// Try active key first.
	if pub, _, err := ks.LoadKey(name); err == nil {
		ok, verr := Verify(data, sig, pub)
		if verr != nil {
			return false, verr
		}
		if ok {
			return true, nil
		}
	}

	// Fall back to rotated keys (oldest first).
	rotated, err := ks.LoadRotatedKeys(name)
	if err != nil {
		// Key doesn't exist or has no rotated history — no match.
		return false, nil
	}
	for _, rpub := range rotated {
		ok, verr := Verify(data, sig, rpub)
		if verr != nil {
			continue
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
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
