.PHONY: all build darwin linux clean install install-user test lint format

BINARY_NAME = libackagent-pkcs11

# Dev-only ldflags: allow SKIP_VERIFY_ATTESTATION env var in local builds.
# Release/packaging builds do NOT include this flag, so the default "false" applies.
DEV_LDFLAGS = -X github.com/ackagent/cli/internal/shared/transport.AllowSkipAttestation=true

all: darwin

build: all

test:
	go test ./...

darwin:
	@echo "Building PKCS#11 provider for macOS..."
	CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="$(DEV_LDFLAGS)" -o $(BINARY_NAME).dylib .

darwin-universal:
	@echo "Building universal macOS PKCS#11 binary..."
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -buildmode=c-shared -ldflags="$(DEV_LDFLAGS)" -o $(BINARY_NAME)_amd64.dylib .
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -ldflags="$(DEV_LDFLAGS)" -o $(BINARY_NAME)_arm64.dylib .
	lipo -create -output $(BINARY_NAME).dylib $(BINARY_NAME)_amd64.dylib $(BINARY_NAME)_arm64.dylib
	rm -f $(BINARY_NAME)_amd64.dylib $(BINARY_NAME)_arm64.dylib $(BINARY_NAME)_amd64.h $(BINARY_NAME)_arm64.h

linux:
	@echo "Building PKCS#11 provider for Linux..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -ldflags="$(DEV_LDFLAGS)" -o $(BINARY_NAME).so .

clean:
	rm -f $(BINARY_NAME).dylib $(BINARY_NAME).so $(BINARY_NAME).h
	rm -f $(BINARY_NAME)_*.dylib $(BINARY_NAME)_*.h

install: darwin
	cp $(BINARY_NAME).dylib /usr/local/lib/$(BINARY_NAME).dylib

install-user: darwin
	mkdir -p ~/.ackagent/lib && cp $(BINARY_NAME).dylib ~/.ackagent/lib/

lint:
	go vet ./...

format:
	gofmt -w $(shell find . -name '*.go')

test-build:
	go build -v .
