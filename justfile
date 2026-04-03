build:
    go build -o bin/axon-sign ./cmd/axon-sign

install: build
    cp bin/axon-sign ~/.local/bin/axon-sign

test:
    go test ./...

vet:
    go vet ./...
