package sign_test

import (
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
