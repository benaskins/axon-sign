// Package sign_test contains end-to-end integration tests for the full axon-sign pipeline.
package sign_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/benaskins/axon-sign/keystore"
	"github.com/benaskins/axon-sign/keys"
	"github.com/benaskins/axon-sign/provenance"
	"github.com/benaskins/axon-sign/rotation"
	"github.com/benaskins/axon-sign/sign"
)

// TestFullPipeline exercises the complete sign → verify → provenance → rotate → verify pipeline.
func TestFullPipeline(t *testing.T) {
	dir := t.TempDir()
	passphrase := []byte("integration-test-passphrase")
	const keyName = "signing-key"

	// ── 1. GenerateKeyPair ────────────────────────────────────────────────────
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	fingerprint := pub.Fingerprint()
	if fingerprint == "" {
		t.Fatal("Fingerprint: empty")
	}

	// ── 2. EncryptPrivateKey ─────────────────────────────────────────────────
	encPriv, err := keys.EncryptPrivateKey(priv, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	// ── 3. FSKeystore.StoreKey ───────────────────────────────────────────────
	ksDir := filepath.Join(dir, "keystore")
	ks, err := keystore.NewFSKeystore(ksDir)
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}
	if err := ks.StoreKey(keyName, pub, encPriv); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Round-trip: verify we can load the key back.
	loadedPub, _, err := ks.LoadKey(keyName)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if loadedPub.Fingerprint() != fingerprint {
		t.Fatalf("LoadKey fingerprint mismatch: got %s, want %s", loadedPub.Fingerprint(), fingerprint)
	}

	// ── 4. BatchSign ─────────────────────────────────────────────────────────
	artifactDir := filepath.Join(dir, "artifacts")
	if err := os.MkdirAll(artifactDir, 0700); err != nil {
		t.Fatalf("mkdir artifacts: %v", err)
	}

	artifact1 := filepath.Join(artifactDir, "file1.txt")
	artifact2 := filepath.Join(artifactDir, "file2.txt")
	if err := os.WriteFile(artifact1, []byte("hello axon-sign"), 0644); err != nil {
		t.Fatalf("write artifact1: %v", err)
	}
	if err := os.WriteFile(artifact2, []byte("second artifact for batch"), 0644); err != nil {
		t.Fatalf("write artifact2: %v", err)
	}

	manifest, err := sign.BatchSign([]string{artifact1, artifact2}, priv, pub)
	if err != nil {
		t.Fatalf("BatchSign: %v", err)
	}
	if len(manifest.Entries) != 2 {
		t.Fatalf("expected 2 manifest entries, got %d", len(manifest.Entries))
	}
	for _, e := range manifest.Entries {
		if e.Fingerprint != fingerprint {
			t.Errorf("manifest entry fingerprint: got %s, want %s", e.Fingerprint, fingerprint)
		}
	}

	// ── Write & read back the manifest ───────────────────────────────────────
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := sign.WriteManifest(manifest, manifestPath); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	loadedManifest, err := sign.ReadManifest(manifestPath)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}

	// ── 5. VerifyManifest ────────────────────────────────────────────────────
	results, err := sign.VerifyManifest(loadedManifest)
	if err != nil {
		t.Fatalf("VerifyManifest: %v", err)
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("VerifyManifest %s: %v", r.Path, r.Err)
		}
	}

	// ── 6. WriteProvenance ───────────────────────────────────────────────────
	entry0 := manifest.Entries[0]
	provPath := filepath.Join(dir, "PROVENANCE.md")
	rec := provenance.ProvenanceRecord{
		Signer:         "integration-test",
		KeyFingerprint: fingerprint,
		SignedAt:       time.Now().UTC(),
		ArtifactHash:   entry0.SHA256Hex,
		ArtifactPath:   entry0.Path,
		Signature:      entry0.Signature,
	}
	if err := provenance.WriteProvenance(rec, provPath); err != nil {
		t.Fatalf("WriteProvenance: %v", err)
	}

	// Assert PROVENANCE.md exists and contains the correct fingerprint.
	provData, err := os.ReadFile(provPath)
	if err != nil {
		t.Fatalf("read PROVENANCE.md: %v", err)
	}
	if !strings.Contains(string(provData), fingerprint) {
		t.Errorf("PROVENANCE.md missing fingerprint %s\ncontent:\n%s", fingerprint, provData)
	}

	// ── 7. RotateKey ─────────────────────────────────────────────────────────
	newPub, err := rotation.RotateKey(ks, keyName, passphrase)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newPub.Fingerprint() == fingerprint {
		t.Error("expected a different fingerprint after key rotation")
	}

	// ── 8. VerifyWithRotation ─────────────────────────────────────────────────
	// Old signatures (made with the now-rotated key) must still verify.
	artifact1Data, err := os.ReadFile(artifact1)
	if err != nil {
		t.Fatalf("read artifact1: %v", err)
	}
	ok, err := sign.VerifyWithRotation(artifact1Data, entry0.Signature, ks, keyName, passphrase)
	if err != nil {
		t.Fatalf("VerifyWithRotation: %v", err)
	}
	if !ok {
		t.Error("old signature should still verify against the rotated key history")
	}

	// New key must NOT verify the old signature.
	okNewKey, err := sign.Verify(artifact1Data, entry0.Signature, newPub)
	if err != nil {
		t.Fatalf("Verify with new key: %v", err)
	}
	if okNewKey {
		t.Error("new key must not verify a signature made by the old key")
	}
}
