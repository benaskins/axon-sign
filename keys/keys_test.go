package keys

import (
	"crypto/ed25519"
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
