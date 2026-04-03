# axon-sign

Create go.mod for the library (module path github.com/benaskins/axon-sign), add golang.org/x/crypto as the sole external dependency. Create justfile with build, test, and vet targets. Add AGENTS.md, CLAUDE.md, README.md stubs. No Go source files yet beyond a package declaration in the root package. Test: `just build` and `just test` succeed on an empty package.

## Prerequisites

- Go 1.24+
- [just](https://github.com/casey/just)

## Build & Run

```bash
just build
just install
axon-sign --help
```

## Development

```bash
just test   # run tests
just vet    # run go vet
```
