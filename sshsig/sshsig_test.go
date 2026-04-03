package sshsig_test

import (
	"bytes"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/benaskins/axon-sign/keys"
	"github.com/benaskins/axon-sign/sshsig"
)

func TestSignAndVerifyCommit(t *testing.T) {
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	commit := []byte("tree abc123\nauthor Alice <alice@example.com> 1234567890 +0000\n\nInitial commit\n")

	sigPEM, err := sshsig.SignCommit(commit, priv)
	if err != nil {
		t.Fatalf("sign commit: %v", err)
	}

	ok, err := sshsig.VerifyCommit(commit, sigPEM, pub)
	if err != nil {
		t.Fatalf("verify commit: %v", err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
}

func TestSignCommitPEMHeader(t *testing.T) {
	_, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	commit := []byte("some commit content")
	sigPEM, err := sshsig.SignCommit(commit, priv)
	if err != nil {
		t.Fatalf("sign commit: %v", err)
	}

	// Check armored PEM header
	if !bytes.HasPrefix(sigPEM, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Errorf("expected PEM to start with '-----BEGIN SSH SIGNATURE-----', got: %s",
			strings.SplitN(string(sigPEM), "\n", 2)[0])
	}

	// Decode and check PEM type
	block, _ := pem.Decode(sigPEM)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != "SSH SIGNATURE" {
		t.Errorf("expected PEM type 'SSH SIGNATURE', got %q", block.Type)
	}
}

func TestVerifyCommitWrongKey(t *testing.T) {
	_, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	wrongPub, _, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate wrong key pair: %v", err)
	}

	commit := []byte("some commit content")
	sigPEM, err := sshsig.SignCommit(commit, priv)
	if err != nil {
		t.Fatalf("sign commit: %v", err)
	}

	ok, err := sshsig.VerifyCommit(commit, sigPEM, wrongPub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

func TestVerifyCommitTamperedContent(t *testing.T) {
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	original := []byte("original commit content")
	sigPEM, err := sshsig.SignCommit(original, priv)
	if err != nil {
		t.Fatalf("sign commit: %v", err)
	}

	tampered := []byte("tampered commit content")
	ok, err := sshsig.VerifyCommit(tampered, sigPEM, pub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected verification to fail for tampered content")
	}
}
