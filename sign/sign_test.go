package sign_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/benaskins/axon-sign/keys"
	"github.com/benaskins/axon-sign/sign"
)

func generateTestKeyPair(t *testing.T) (keys.PublicKey, keys.PrivateKey) {
	t.Helper()
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	return pub, priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	data := []byte("hello, axon-sign")
	sig, err := sign.Sign(data, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	ok, err := sign.Verify(data, sig, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestVerifyTamperedData(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	data := []byte("original data")
	sig, err := sign.Sign(data, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := []byte("tampered data")
	ok, err := sign.Verify(tampered, sig, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for tampered data")
	}
}

func TestVerifyInvalidBase64(t *testing.T) {
	pub, _ := generateTestKeyPair(t)

	_, err := sign.Verify([]byte("data"), "not-valid-base64!!!", pub)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv := generateTestKeyPair(t)
	otherPub, _ := generateTestKeyPair(t)

	data := []byte("some data")
	sig, err := sign.Sign(data, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	ok, err := sign.Verify(data, sig, otherPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for wrong key")
	}
}

func TestSignFile(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(path, []byte("file contents"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sig, err := sign.SignFile(path, priv)
	if err != nil {
		t.Fatalf("sign file: %v", err)
	}
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	ok, err := sign.Verify([]byte("file contents"), sig, pub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("expected signature to verify")
	}
}

func TestBatchSign(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	paths := make([]string, 3)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("file%d.txt", i))
		if err := os.WriteFile(paths[i], []byte(fmt.Sprintf("content %d", i)), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	manifest, err := sign.BatchSign(paths, priv, pub)
	if err != nil {
		t.Fatalf("batch sign: %v", err)
	}

	if len(manifest.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(manifest.Entries))
	}

	fingerprint := pub.Fingerprint()
	for i, entry := range manifest.Entries {
		if entry.Path != paths[i] {
			t.Errorf("entry %d: expected path %q, got %q", i, paths[i], entry.Path)
		}
		if entry.SHA256Hex == "" {
			t.Errorf("entry %d: empty SHA256Hex", i)
		}
		if entry.Signature == "" {
			t.Errorf("entry %d: empty Signature", i)
		}
		if entry.Fingerprint != fingerprint {
			t.Errorf("entry %d: expected fingerprint %q, got %q", i, fingerprint, entry.Fingerprint)
		}
		// .sig file should exist alongside the original
		sigPath := paths[i] + ".sig"
		if _, err := os.Stat(sigPath); err != nil {
			t.Errorf("entry %d: .sig file not written: %v", i, err)
		}
	}
}

func TestWriteReadManifest(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	manifest, err := sign.BatchSign([]string{path}, priv, pub)
	if err != nil {
		t.Fatalf("batch sign: %v", err)
	}

	dest := filepath.Join(dir, "manifest.json")
	if err := sign.WriteManifest(manifest, dest); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	got, err := sign.ReadManifest(dest)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	if len(got.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(got.Entries))
	}
	if got.Entries[0].Path != manifest.Entries[0].Path {
		t.Errorf("path mismatch: %q vs %q", got.Entries[0].Path, manifest.Entries[0].Path)
	}
	if got.Entries[0].SHA256Hex != manifest.Entries[0].SHA256Hex {
		t.Errorf("SHA256Hex mismatch")
	}
	if got.Entries[0].Signature != manifest.Entries[0].Signature {
		t.Errorf("Signature mismatch")
	}
	if got.Entries[0].Fingerprint != manifest.Entries[0].Fingerprint {
		t.Errorf("Fingerprint mismatch")
	}
}

func TestVerifyManifestClean(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	}
	for _, p := range paths {
		if err := os.WriteFile(p, []byte("clean content"), 0o644); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	manifest, err := sign.BatchSign(paths, priv, pub)
	if err != nil {
		t.Fatalf("batch sign: %v", err)
	}

	results, err := sign.VerifyManifest(manifest)
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.OK {
			t.Errorf("expected %q to verify OK, err: %v", r.Path, r.Err)
		}
	}
}

func TestVerifyManifestTampered(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	manifest, err := sign.BatchSign([]string{path}, priv, pub)
	if err != nil {
		t.Fatalf("batch sign: %v", err)
	}

	// tamper the file after signing
	if err := os.WriteFile(path, []byte("tampered"), 0o644); err != nil {
		t.Fatalf("overwrite file: %v", err)
	}

	results, err := sign.VerifyManifest(manifest)
	if err != nil {
		t.Fatalf("verify manifest: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].OK {
		t.Fatal("expected tampered file to fail verification")
	}
}

func TestWriteSigFile(t *testing.T) {
	pub, priv := generateTestKeyPair(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.txt")
	if err := os.WriteFile(path, []byte("file contents"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sig, err := sign.SignFile(path, priv)
	if err != nil {
		t.Fatalf("sign file: %v", err)
	}

	fingerprint := pub.Fingerprint()
	if err := sign.WriteSigFile(path, sig, fingerprint); err != nil {
		t.Fatalf("write sig file: %v", err)
	}

	sigPath := path + ".sig"
	data, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig file: %v", err)
	}

	contents := string(data)
	if !strings.Contains(contents, sig) {
		t.Errorf("sig file does not contain signature")
	}
	if !strings.Contains(contents, fingerprint) {
		t.Errorf("sig file does not contain fingerprint")
	}
}
