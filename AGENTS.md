# axon-sign

Create go.mod for the library (module path github.com/benaskins/axon-sign), add golang.org/x/crypto as the sole external dependency. Create justfile with build, test, and vet targets. Add AGENTS.md, CLAUDE.md, README.md stubs. No Go source files yet beyond a package declaration in the root package. Test: `just build` and `just test` succeed on an empty package.

## Build & Test

```bash
go test ./...
go vet ./...
just build     # builds to bin/axon-sign
just install   # copies to ~/.local/bin/axon-sign
```

## Module Selections

- **axon-fact**: Provenance tracking requires an audit trail of signing events (who signed what, when, with which key). axon-fact's Event and EventStore primitives underpin the PROVENANCE.md generation and key rotation history. (deterministic)

## Deterministic / Non-deterministic Boundary

| From | To | Type |
|------|----|------|
| keys package | crypto/ed25519 + golang.org/x/crypto | det |
| keystore package | keys package | det |
| sign package | keys package | det |
| sshsig package | sign package | det |
| provenance package | sign package | det |
| provenance package | keystore package | det |
| keystore package | filesystem (os package) | det |

