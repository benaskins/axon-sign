package keys

import (
	"crypto/ed25519"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestMarshalAuthorizedKeyRoundTrip(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	authKey := pub.MarshalAuthorizedKey()
	if authKey == "" {
		t.Fatal("MarshalAuthorizedKey returned empty string")
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}

	roundTripped := string(ssh.MarshalAuthorizedKey(parsed))
	if roundTripped != authKey {
		t.Errorf("round-trip mismatch:\n  got  %q\n  want %q", roundTripped, authKey)
	}
}

func TestMarshalPEM(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pemData, err := pub.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	if !strings.HasPrefix(string(pemData), "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("expected PEM header, got: %q", string(pemData[:min(len(pemData), 40)]))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	passphrase := []byte("correct horse battery staple")

	pemData, err := EncryptPrivateKey(priv, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	recovered, err := DecryptPrivateKey(pemData, passphrase)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}

	if len(recovered) != len(priv) {
		t.Fatalf("recovered key length: got %d, want %d", len(recovered), len(priv))
	}
	for i := range priv {
		if recovered[i] != priv[i] {
			t.Fatalf("recovered key differs at byte %d", i)
		}
	}
}

func TestEncryptedPEMIsValidPEM(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pemData, err := EncryptPrivateKey(priv, []byte("passphrase"))
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("pem.Decode returned nil block")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		t.Errorf("PEM type: got %q, want %q", block.Type, "ENCRYPTED PRIVATE KEY")
	}
	if block.Headers["Argon2id-Salt"] == "" {
		t.Error("PEM header Argon2id-Salt is missing")
	}
	if block.Headers["Argon2id-Nonce"] == "" {
		t.Error("PEM header Argon2id-Nonce is missing")
	}
}

func TestDecryptWrongPassphrase(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	pemData, err := EncryptPrivateKey(priv, []byte("correct"))
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}

	_, err = DecryptPrivateKey(pemData, []byte("wrong"))
	if err == nil {
		t.Fatal("expected error with wrong passphrase, got nil")
	}
	// Error must not contain passphrase or key bytes
	errStr := err.Error()
	if strings.Contains(errStr, "wrong") || strings.Contains(errStr, "correct") {
		t.Errorf("error message leaks passphrase: %q", errStr)
	}
}

func TestFingerprint(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	fp := pub.Fingerprint()
	if fp == "" {
		t.Fatal("Fingerprint returned empty string")
	}

	// SHA-256 is 32 bytes → 32 colon-separated hex pairs
	pattern := regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){31}$`)
	if !pattern.MatchString(fp) {
		t.Errorf("fingerprint %q does not match colon-hex pattern", fp)
	}
}
