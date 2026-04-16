# axon-sign

Pure-Go cryptographic signing library: Ed25519 keypairs, SSHSIG format, key rotation, and provenance.

Import: `github.com/benaskins/axon-sign`

## What it does

axon-sign provides cryptographic signing primitives for the lamina workspace. No shell-outs to ssh-keygen or gpg; everything is pure Go with a single dependency on `golang.org/x/crypto`.

## Packages

| Package | Purpose |
|---------|---------|
| `keys` | Ed25519 keypair generation, PEM/OpenSSH serialization, AES-256-GCM encryption (Argon2id KDF) |
| `keystore` | Key storage interface with filesystem backend, supports rotation history |
| `sign` | Raw signing/verification, batch signing, manifests with embedded public keys |
| `sshsig` | SSHSIG format for Git commit signing (OpenSSH 8.0+ compatible) |
| `rotation` | Key rotation workflow preserving old keys for historical verification |
| `provenance` | PROVENANCE.md generation for release artifacts |

## Usage

### Generate and store a keypair

```go
import (
    "github.com/benaskins/axon-sign/keys"
    "github.com/benaskins/axon-sign/keystore"
)

pub, priv, _ := keys.GenerateKeyPair()
encrypted, _ := keys.EncryptPrivateKey(priv, passphrase)

ks, _ := keystore.NewFSKeystore(dir)
ks.StoreKey("agent-1", pub, encrypted)
```

### Sign and verify

```go
import "github.com/benaskins/axon-sign/sign"

sig, _ := sign.Sign(data, priv)
ok, _ := sign.Verify(data, sig, pub)
```

### Batch sign with manifest

```go
manifest, _ := sign.BatchSign(paths, priv, pub)
sign.WriteManifest(manifest, "MANIFEST.json")
```

### Git commit signing (SSHSIG)

```go
import "github.com/benaskins/axon-sign/sshsig"

sigPEM, _ := sshsig.SignCommit(commitContent, priv)
ok, _ := sshsig.VerifyCommit(commitContent, sigPEM, pub)
```

### Key rotation

```go
import "github.com/benaskins/axon-sign/rotation"

newPub, _ := rotation.RotateKey(ks, "agent-1", passphrase)
// Old key preserved; VerifyWithRotation checks all keys
```

## Dependencies

- `golang.org/x/crypto` (Argon2id, SSH wire format)

## Build & Test

```bash
go test ./...
go vet ./...
```
