package keystore_test

import (
	"testing"

	"github.com/benaskins/axon-sign/keystore"
	"github.com/benaskins/axon-sign/keys"
)

func mustGenKey(t *testing.T) (keys.PublicKey, []byte) {
	t.Helper()
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	enc, err := keys.EncryptPrivateKey(priv, []byte("passphrase"))
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	return pub, enc
}

func TestFSKeystore_RoundTrip(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}

	pub, enc := mustGenKey(t)

	if err := ks.StoreKey("mykey", pub, enc); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	gotPub, gotEnc, err := ks.LoadKey("mykey")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	if gotPub.Fingerprint() != pub.Fingerprint() {
		t.Errorf("fingerprint mismatch: got %q want %q", gotPub.Fingerprint(), pub.Fingerprint())
	}
	if string(gotEnc) != string(enc) {
		t.Error("encrypted private key bytes mismatch")
	}

	// Encrypted key must still decrypt correctly.
	_, err = keys.DecryptPrivateKey(gotEnc, []byte("passphrase"))
	if err != nil {
		t.Fatalf("DecryptPrivateKey after round-trip: %v", err)
	}
}

func TestFSKeystore_List(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}

	names, err := ks.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys empty: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected empty list, got %v", names)
	}

	for _, name := range []string{"alice", "bob"} {
		pub, enc := mustGenKey(t)
		if err := ks.StoreKey(name, pub, enc); err != nil {
			t.Fatalf("StoreKey %q: %v", name, err)
		}
	}

	names, err = ks.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 keys, got %d: %v", len(names), names)
	}
	if names[0] != "alice" || names[1] != "bob" {
		t.Errorf("unexpected key names: %v", names)
	}
}

func TestFSKeystore_Delete(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}

	pub, enc := mustGenKey(t)
	if err := ks.StoreKey("mykey", pub, enc); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	if err := ks.DeleteKey("mykey"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	names, _ := ks.ListKeys()
	if len(names) != 0 {
		t.Errorf("expected empty list after delete, got %v", names)
	}

	if _, _, err := ks.LoadKey("mykey"); err == nil {
		t.Error("expected error loading deleted key")
	}
}

func TestFSKeystore_MarkRotated(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}

	pub, enc := mustGenKey(t)
	if err := ks.StoreKey("mykey", pub, enc); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	if err := ks.MarkRotated("mykey"); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}

	// Active key must no longer be loadable.
	if _, _, err := ks.LoadKey("mykey"); err == nil {
		t.Error("expected error loading key after rotation")
	}

	// Rotated slice must contain the old public key.
	rotated, err := ks.LoadRotatedKeys("mykey")
	if err != nil {
		t.Fatalf("LoadRotatedKeys: %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("expected 1 rotated key, got %d", len(rotated))
	}
	if rotated[0].Fingerprint() != pub.Fingerprint() {
		t.Error("rotated key fingerprint mismatch")
	}
}

func TestFSKeystore_MultipleRotations(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}

	// Store first key and rotate.
	pub1, enc1 := mustGenKey(t)
	if err := ks.StoreKey("mykey", pub1, enc1); err != nil {
		t.Fatalf("StoreKey 1: %v", err)
	}
	if err := ks.MarkRotated("mykey"); err != nil {
		t.Fatalf("MarkRotated 1: %v", err)
	}

	// Store second key and rotate.
	pub2, enc2 := mustGenKey(t)
	if err := ks.StoreKey("mykey", pub2, enc2); err != nil {
		t.Fatalf("StoreKey 2: %v", err)
	}
	if err := ks.MarkRotated("mykey"); err != nil {
		t.Fatalf("MarkRotated 2: %v", err)
	}

	rotated, err := ks.LoadRotatedKeys("mykey")
	if err != nil {
		t.Fatalf("LoadRotatedKeys: %v", err)
	}
	if len(rotated) != 2 {
		t.Fatalf("expected 2 rotated keys, got %d", len(rotated))
	}

	fps := make(map[string]bool)
	for _, rk := range rotated {
		fps[rk.Fingerprint()] = true
	}
	if !fps[pub1.Fingerprint()] {
		t.Error("first rotated key not found")
	}
	if !fps[pub2.Fingerprint()] {
		t.Error("second rotated key not found")
	}
}

func TestFSKeystore_LoadKey_Missing(t *testing.T) {
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}
	if _, _, err := ks.LoadKey("nonexistent"); err == nil {
		t.Error("expected error for missing key")
	}
}
