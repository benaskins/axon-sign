# axon-sign

Cryptographic signing library: Ed25519 keypairs, SSHSIG-format signatures, key rotation, and provenance generation.

## Module

- Module path: `github.com/benaskins/axon-sign`
- Project type: library (no main package)

## Build & Test

```bash
just test    # go test -race ./...
just vet     # go vet ./...
just build   # go build ./...
```

## Architecture

| Package | Purpose |
|---------|---------|
| `keys` | Ed25519 keypair generation, AES-256-GCM encryption with Argon2id KDF |
| `keystore` | `Keystore` interface + `FSKeystore` (filesystem-backed) |
| `sign` | Raw Ed25519 sign/verify, batch signing, manifest |
| `sshsig` | SSHSIG-format signing compatible with OpenSSH 8.0+ |
| `rotation` | Key rotation with multi-key verification |
| `provenance` | PROVENANCE.md template generation |

Read [AGENTS.md](./AGENTS.md) for boundary map and dependency graph.

## Constraints

- Pure Go crypto only — no shelling out to ssh-keygen, gpg, or any external process
- Only stdlib + golang.org/x/crypto — no other dependencies
- Private key material must never appear in error messages or logs
- AES-256-GCM with Argon2id KDF for key encryption — no alternatives
- SSHSIG format: magic "SSHSIG", namespace "git", hash SHA-512
- No axon-fact — persistence is the caller's responsibility
- No third-party assertion libraries — standard `testing` package only
