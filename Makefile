.PHONY: build test coverage clean download-bbs-ffi download-test-vectors sk-provider pkcs11-provider pam-module ackagent-pam ackagent-audit lint format release

# ── VERSION resolution ─────────────────────────────────────
# Supports: make release VERSION=1.2.3 | VERSION=patch | VERSION=minor | VERSION=major
ifdef VERSION
  ifneq ($(filter v%,$(VERSION)),)
    $(error VERSION must not start with 'v' — the prefix is added automatically. Usage: make release VERSION=1.2.3)
  endif
  ifneq ($(filter patch minor major,$(VERSION)),)
    _LATEST_TAG := $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)
    _LATEST_VER := $(patsubst v%,%,$(_LATEST_TAG))
    _VER_PARTS  := $(subst ., ,$(_LATEST_VER))
    _CUR_MAJOR  := $(or $(word 1,$(_VER_PARTS)),0)
    _CUR_MINOR  := $(or $(word 2,$(_VER_PARTS)),0)
    _CUR_PATCH  := $(or $(word 3,$(_VER_PARTS)),0)
    ifeq ($(VERSION),patch)
      override VERSION := $(_CUR_MAJOR).$(_CUR_MINOR).$(shell echo $$(($(_CUR_PATCH) + 1)))
    else ifeq ($(VERSION),minor)
      override VERSION := $(_CUR_MAJOR).$(shell echo $$(($(_CUR_MINOR) + 1))).0
    else ifeq ($(VERSION),major)
      override VERSION := $(shell echo $$(($(_CUR_MAJOR) + 1))).0.0
    endif
  endif
  ifeq ($(shell echo '$(VERSION)' | grep -cE '^[0-9]+\.[0-9]+\.[0-9]+$$'),0)
    $(error Invalid VERSION '$(VERSION)'. Must be semver X.Y.Z (e.g. 1.2.3) or bump keyword (patch|minor|major))
  endif
endif
# ────────────────────────────────────────────────────────────

# Dev-only ldflags: allow SKIP_VERIFY_ATTESTATION env var in local builds.
# Release/packaging builds do NOT include this flag, so the default "false" applies.
DEV_LDFLAGS = -X github.com/ackagent/cli/internal/shared/transport.AllowSkipAttestation=true

# Build the CLI binary and all components
build: sk-provider pkcs11-provider ackagent-pam pam-module ackagent-audit
	CGO_ENABLED=1 go build -ldflags="$(DEV_LDFLAGS)" -o ackagent ./cmd/ackagent

# Build the ackagent-pam CLI (pure Go, no platform restrictions)
ackagent-pam: download-bbs-ffi
	CGO_ENABLED=1 go build -ldflags="$(DEV_LDFLAGS)" -o ackagent-pam ./cmd/ackagent-pam

# Build the ackagent-audit CLI
ackagent-audit:
	go build -ldflags="$(DEV_LDFLAGS)" -o ackagent-audit ./cmd/ackagent-audit

# BBS+ FFI version to download
BBS_FFI_VERSION ?= v0.3.0
BBS_FFI_REPO = ackagent/bbs-ffi

# Download BBS+ FFI static library and header from GitHub Release
download-bbs-ffi:
	@if [ ! -f deps/bbs-ffi/lib/libbbs_ffi.a ]; then \
		echo "==> Downloading bbs-ffi $(BBS_FFI_VERSION)..."; \
		mkdir -p deps/bbs-ffi/lib deps/bbs-ffi/include; \
		OS=$$(echo $${GOOS:-$$(uname -s)} | tr '[:upper:]' '[:lower:]'); \
		if [ "$$OS" = "darwin" ]; then OS=macos; fi; \
		ARCH=$${GOARCH:-$$(uname -m)}; \
		if [ "$$ARCH" = "x86_64" ]; then ARCH=amd64; fi; \
		if [ "$$ARCH" = "aarch64" ]; then ARCH=arm64; fi; \
		BASE_URL="https://github.com/$(BBS_FFI_REPO)/releases/download/$(BBS_FFI_VERSION)"; \
		curl -sfL "$$BASE_URL/libbbs_ffi-$${OS}-$${ARCH}.a" -o deps/bbs-ffi/lib/libbbs_ffi.a; \
		curl -sfL "$$BASE_URL/bbs_ffi.h" -o deps/bbs-ffi/include/bbs_ffi.h; \
		echo "==> bbs-ffi downloaded to deps/bbs-ffi/"; \
	else \
		echo "==> bbs-ffi already present"; \
	fi

# Cross-platform test vectors — downloaded from ackagent/api (single source of truth)
TEST_VECTORS_VERSION ?= v0.3.4
TEST_VECTORS_BASE = https://raw.githubusercontent.com/AckAgent/api/$(TEST_VECTORS_VERSION)

download-test-vectors:
	@if [ ! -f data/crypto_test_vectors.json ]; then \
		echo "==> Downloading test vectors $(TEST_VECTORS_VERSION)..."; \
		mkdir -p data; \
		curl -sfL $(TEST_VECTORS_BASE)/data/crypto_test_vectors.json -o data/crypto_test_vectors.json; \
		curl -sfL $(TEST_VECTORS_BASE)/data/protocol_test_vectors.json -o data/protocol_test_vectors.json; \
		echo "==> Test vectors downloaded to data/"; \
	else \
		echo "==> Test vectors already present"; \
	fi

# Build the sk-provider shared library
sk-provider: download-bbs-ffi
	$(MAKE) -C sk-provider

# Build the pkcs11-provider shared library
pkcs11-provider: download-bbs-ffi
	$(MAKE) -C pkcs11-provider

# Run tests
test: download-bbs-ffi download-test-vectors
	CGO_ENABLED=1 go test ./...

# Run tests with coverage
coverage: download-bbs-ffi download-test-vectors
	CGO_ENABLED=1 go test -coverprofile=coverage.out.tmp ./...
	grep -v -E '/gen/|/gen\.go:' coverage.out.tmp > coverage.out
	rm -f coverage.out.tmp
	@echo "Per-package coverage:"
	@go tool cover -func=coverage.out | awk '/^total:/{next} { f=$$1; sub(/:.*/, "", f); n=split(f,a,"/"); f=a[1]; for(i=2;i<n;i++) f=f"/"a[i]; pct=$$NF; sub(/%/,"",pct); s[f]+=pct+0; c[f]++ } END { for(p in s) printf "  %-60s %.1f%%\n", p, s[p]/c[p] }' | sort
	@echo ""
	@go tool cover -func=coverage.out | tail -1

# Lint
lint:
	go vet ./...
	$(MAKE) -C sk-provider lint
	$(MAKE) -C pkcs11-provider lint

# Format (excludes generated code and sub-provider directories)
format:
	gofmt -w $(shell find . -name '*.go' ! -path '*/gen/*' ! -name 'gen.go' ! -name '*_gen.go' ! -name '*.gen.go' ! -path '*/sk-provider/*' ! -path '*/pkcs11-provider/*')
	$(MAKE) -C sk-provider format
	$(MAKE) -C pkcs11-provider format

# Release: tag and push (CI builds binaries and creates GitHub Release)
# Usage: make release VERSION=0.2.0
release:
ifndef VERSION
	$(error VERSION is required. Usage: make release VERSION=1.2.3 (or patch|minor|major))
endif
	@echo "Releasing v$(VERSION)$(if $(_LATEST_VER), (was v$(_LATEST_VER)),)"
	git tag v$(VERSION)
	git push origin v$(VERSION)

# Clean build artifacts
clean:
	rm -f ackagent ackagent-pam ackagent-audit pam_ackagent.so pam_ackagent.h
	$(MAKE) -C sk-provider clean
	$(MAKE) -C pkcs11-provider clean

install: build
	cp ackagent /usr/local/bin/ackagent
	$(MAKE) -C sk-provider install
	$(MAKE) -C pkcs11-provider install

# Build the PAM module (Linux and macOS)
# This creates pam_ackagent.so which can be installed to the platform-specific PAM directory
pam-module: download-bbs-ffi
	CGO_ENABLED=1 go build -buildmode=c-shared -o pam_ackagent.so ./cmd/pam-module

# Install PAM module (requires root)
install-pam: pam-module
ifeq ($(shell uname),Darwin)
	sudo mkdir -p /usr/local/lib/pam
	sudo cp pam_ackagent.so /usr/local/lib/pam/pam_ackagent.so
	sudo chmod 755 /usr/local/lib/pam/pam_ackagent.so
else
	sudo cp pam_ackagent.so /lib/security/pam_ackagent.so
	sudo chmod 755 /lib/security/pam_ackagent.so
endif
