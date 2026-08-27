.PHONY: all build test clean install lint fmt

BINARY=tidebreak
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/tidebreak

test:
	go test -v -race ./...

test-short:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	@which golangci-lint >/dev/null 2>&1 && golangci-lint run ./... || echo "golangci-lint not installed, skipping"

clean:
	rm -rf bin/ dist/

install: build
	cp bin/$(BINARY) ~/.local/bin/$(BINARY)

# Cross-compile for all platforms
dist:
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		OS=$${platform%/*}; \
		ARCH=$${platform#*/}; \
		echo "Building $$OS/$$ARCH..."; \
		GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o dist/$(BINARY)-$$OS-$$ARCH ./cmd/tidebreak; \
	done

# Quick smoke test
smoke: build
	./bin/$(BINARY) version
	./bin/$(BINARY) classify --help