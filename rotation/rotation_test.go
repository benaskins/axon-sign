package rotation_test

import (
	"testing"

	"github.com/benaskins/axon-sign/keystore"
	"github.com/benaskins/axon-sign/keys"
	"github.com/benaskins/axon-sign/rotation"
)

func makeKeystore(t *testing.T) *keystore.FSKeystore {
	t.Helper()
	ks, err := keystore.NewFSKeystore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSKeystore: %v", err)
	}
	return ks
}

func storeNewKey(t *testing.T, ks keystore.Keystore, name string, passphrase []byte) (keys.PublicKey, keys.PrivateKey) {
	t.Helper()
	pub, priv, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	enc, err := keys.EncryptPrivateKey(priv, passphrase)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if err := ks.StoreKey(name, pub, enc); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}
	return pub, priv
}

func TestRotateKey_ReturnsNewPublicKey(t *testing.T) {
	ks := makeKeystore(t)
	passphrase := []byte("test-pass")

	origPub, _ := storeNewKey(t, ks, "mykey", passphrase)

	newPub, err := rotation.RotateKey(ks, "mykey", passphrase)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if newPub.Fingerprint() == origPub.Fingerprint() {
		t.Error("expected new public key to differ from original")
	}
}

func TestRotateKey_OldKeyIsRotated(t *testing.T) {
	ks := makeKeystore(t)
	passphrase := []byte("test-pass")

	origPub, _ := storeNewKey(t, ks, "mykey", passphrase)

	if _, err := rotation.RotateKey(ks, "mykey", passphrase); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	rotated, err := ks.LoadRotatedKeys("mykey")
	if err != nil {
		t.Fatalf("LoadRotatedKeys: %v", err)
	}
	if len(rotated) != 1 {
		t.Fatalf("expected 1 rotated key, got %d", len(rotated))
	}
	if rotated[0].Fingerprint() != origPub.Fingerprint() {
		t.Error("rotated key fingerprint mismatch")
	}
}

func TestRotateKey_NewKeyIsActive(t *testing.T) {
	ks := makeKeystore(t)
	passphrase := []byte("test-pass")

	storeNewKey(t, ks, "mykey", passphrase)

	newPub, err := rotation.RotateKey(ks, "mykey", passphrase)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	activePub, _, err := ks.LoadKey("mykey")
	if err != nil {
		t.Fatalf("LoadKey after rotation: %v", err)
	}
	if activePub.Fingerprint() != newPub.Fingerprint() {
		t.Error("active key after rotation does not match returned new key")
	}
}
