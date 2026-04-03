# axon-sign — Initial Build Plan
# 2026-04-03

Each step is commit-sized. Execute via `/iterate`.

## Step 1 — Initialise module and project skeleton

Create go.mod for the library (module path github.com/benaskins/axon-sign), add golang.org/x/crypto as the sole external dependency. Create justfile with build, test, and vet targets. Add AGENTS.md, CLAUDE.md, README.md stubs. No Go source files yet beyond a package declaration in the root package. Test: `just build` and `just test` succeed on an empty package.

Commit: `feat: initialise axon-sign module scaffold with justfile and docs`

## Step 2 — Implement Ed25519 keypair generation and public key serialization

Create package `keys` (keys/keys.go). Define typed values PrivateKey and PublicKey wrapping crypto/ed25519. Implement: GenerateKeyPair() returning (PublicKey, PrivateKey, error); PublicKey.MarshalAuthorizedKey() string (OpenSSH authorized_keys wire format using golang.org/x/crypto/ssh); PublicKey.MarshalPEM() ([]byte, error) (PEM-encoded SubjectPublicKeyInfo); PublicKey.Fingerprint() string (SHA-256 colon-separated hex, matching ssh-keygen -l output). Tests in keys/keys_test.go: verify generated keys are 32/64 bytes, round-trip authorized_keys parsing via golang.org/x/crypto/ssh, verify fingerprint format matches colon-hex pattern.

Commit: `feat: implement Ed25519 keypair generation and public key serialization`

## Step 3 — Implement encrypted private key storage (AES-256-GCM + Argon2id)

Extend the `keys` package with: EncryptPrivateKey(key PrivateKey, passphrase []byte) ([]byte, error) — derives a 32-byte key via Argon2id (golang.org/x/crypto/argon2), encrypts with AES-256-GCM, encodes as PEM block with type "ENCRYPTED PRIVATE KEY" and headers storing the Argon2id salt and nonce (base64). DecryptPrivateKey(pemData []byte, passphrase []byte) (PrivateKey, error) — reverses the process. Ensure private key bytes are zeroed after use using defer. Error messages must not include key bytes or passphrase. Tests: encrypt/decrypt round-trip; wrong passphrase returns error without leaking material; PEM output is valid PEM.

Commit: `feat: implement AES-256-GCM + Argon2id private key encryption and decryption`

## Step 4 — Implement Keystore interface and filesystem-backed implementation

Create package `keystore` (keystore/keystore.go). Define interface Keystore with StoreKey(name string, pub PublicKey, encryptedPriv []byte) error; LoadKey(name string) (PublicKey, []byte, error); ListKeys() ([]string, error); DeleteKey(name string) error. Implement FSKeystore backed by a directory: each key stored as two files — {name}.pub (authorized_keys format) and {name}.key (encrypted PEM). Add MarkRotated(name string) error that renames {name}.key → {name}.key.rotated and {name}.pub → {name}.pub.rotated. LoadRotatedKeys(name string) returns slice of rotated public keys for multi-key verification. Tests in keystore/keystore_test.go: use t.TempDir() for all file I/O; round-trip store/load; list; delete; rotation.

Commit: `feat: implement Keystore interface and filesystem keystore`

## Step 5 — Implement raw Ed25519 sign and verify with detached .sig files

Create package `sign` (sign/sign.go). Implement: Sign(data []byte, priv keys.PrivateKey) (string, error) — returns base64-encoded Ed25519 signature. Verify(data []byte, sig string, pub keys.PublicKey) (bool, error) — decodes base64 signature and verifies using ed25519.Verify (which is constant-time). SignFile(path string, priv keys.PrivateKey) (string, error) — reads file and calls Sign. WriteSigFile(path string, sig string, pubFingerprint string) error — writes {path}.sig containing the signature and fingerprint. Tests: sign/verify round-trip; tampered data returns false; invalid base64 returns error; sig file written and readable.

Commit: `feat: implement raw Ed25519 sign and verify operations`

## Step 6 — Implement SSHSIG-format Git commit signing and verification

Create package `sshsig` (sshsig/sshsig.go). Implement the SSHSIG wire format per OpenSSH spec: magic preamble "SSHSIG", version uint32(1), public key blob, namespace string ("git"), reserved string (""), hash algorithm string ("sha512"), signature blob. SignCommit(commitContent []byte, priv keys.PrivateKey) ([]byte, error) — builds the to-be-signed blob (hash of namespace+null+hash_alg+null+SHA-512(commitContent)), signs with Ed25519, encodes to SSHSIG armoured PEM ("-----BEGIN SSH SIGNATURE-----"). VerifyCommit(commitContent []byte, sigPEM []byte, pub keys.PublicKey) (bool, error). Tests: verify that SignCommit output can be round-tripped through VerifyCommit; test that the PEM header matches "-----BEGIN SSH SIGNATURE-----"; test wrong public key returns false. Note: do not shell out to ssh-keygen.

Commit: `feat: implement SSHSIG-format Git commit signing and verification`

## Step 7 — Implement batch signing and JSON signature manifest

Extend the `sign` package with: BatchSign(paths []string, priv keys.PrivateKey, pub keys.PublicKey) (Manifest, error) — signs each file, writes a .sig alongside each, returns a Manifest struct containing []ManifestEntry{Path, SHA256Hex, Signature, Fingerprint}. WriteManifest(m Manifest, dest string) error — serialises Manifest as JSON to dest. VerifyManifest(m Manifest) ([]VerifyResult, error) — re-reads each file, verifies signature, returns per-entry pass/fail. Tests: batch sign a set of temp files; manifest JSON round-trip; tampered file detected in VerifyManifest.

Commit: `feat: implement batch signing and signature manifest`

## Step 8 — Implement PROVENANCE.md template generation

Create package `provenance` (provenance/provenance.go). Define struct ProvenanceRecord{Signer string; KeyFingerprint string; SignedAt time.Time; ArtifactHash string; ArtifactPath string; Signature string; RotatedKeys []string}. Implement GenerateProvenance(r ProvenanceRecord) ([]byte, error) — renders a Markdown template (text/template) documenting who signed what, when, with which key, hash, and signature. WriteProvenance(r ProvenanceRecord, dest string) error — writes to dest. Tests: rendered markdown contains all fields; missing required fields return descriptive error.

Commit: `feat: implement PROVENANCE.md template generation`

## Step 9 — Implement key rotation and multi-key signature verification

Wire rotation into the keystore and verifier. Add RotateKey(ks keystore.Keystore, name string, passphrase []byte) (keys.PublicKey, error) in a new `rotation` package — generates a new keypair, stores it under name, calls ks.MarkRotated on the old key. Add VerifyWithRotation(data []byte, sig string, ks keystore.Keystore, name string, passphrase []byte) (bool, error) in the `sign` package — tries current key first, then each rotated key, returns true on first match. Tests: rotate once, verify old signature against rotated keystore succeeds; rotate twice, oldest signature still verifiable; signature for unknown key returns false.

Commit: `feat: implement key rotation with multi-key verification`

## Step 10 — Add end-to-end integration tests for the full signing pipeline

Add tests/integration_test.go (package sign_test) covering the end-to-end scenario: GenerateKeyPair → EncryptPrivateKey → FSKeystore.StoreKey → BatchSign → VerifyManifest → WriteProvenance → RotateKey → VerifyWithRotation. All file I/O in t.TempDir(). Assert PROVENANCE.md exists and contains correct fingerprint. Assert old signatures verify after rotation. Run with `just test` and confirm zero failures.

Commit: `test: add integration-style tests exercising full sign→verify→provenance pipeline`

