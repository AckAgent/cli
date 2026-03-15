.PHONY: all build-arm64 sign pkg pkg-sign notarize release tarball clean

# Version from git tag (pam/* tags)
VERSION := $(shell git describe --tags --match 'pam/*' --always --dirty 2>/dev/null | sed 's|^pam/||' || echo "0.0.1")
PKG_IDENTIFIER := com.ackagent.pam
PKG_NAME := AckAgent-PAM-$(VERSION)-arm64.pkg

# Directories
BUILD_DIR := build
ARM64_DIR := $(BUILD_DIR)/arm64
PKG_ROOT := $(BUILD_DIR)/pkg-root
CLI_DIR := ../..

# Code signing identities (set via environment variables)
APPLE_DEVELOPER_ID_APP ?=
APPLE_DEVELOPER_ID_INSTALLER ?=
APPLE_ID ?=
APPLE_APP_PASSWORD ?=
APPLE_TEAM_ID ?=

all: build-arm64

# Build ARM64 binaries (CLI + PAM module)
build-arm64: $(ARM64_DIR)/ackagent-pam $(ARM64_DIR)/pam_ackagent.so

$(ARM64_DIR)/ackagent-pam:
	@echo "Building ackagent-pam CLI for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR) && GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" -o packaging/pam/$(ARM64_DIR)/ackagent-pam ./cmd/ackagent-pam

$(ARM64_DIR)/pam_ackagent.so:
	@echo "Building pam_ackagent.so for arm64..."
	@mkdir -p $(ARM64_DIR)
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build \
		-buildmode=c-shared -ldflags="-s -w" \
		-o packaging/pam/$(ARM64_DIR)/pam_ackagent.so ./cmd/pam-module
	@rm -f $(ARM64_DIR)/pam_ackagent.h

# Sign binaries with Developer ID Application certificate
sign: build-arm64
ifndef APPLE_DEVELOPER_ID_APP
	$(error APPLE_DEVELOPER_ID_APP is not set. Set it to your "Developer ID Application: ..." certificate name)
endif
	@echo "Signing binaries..."
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/ackagent-pam
	codesign --sign "$(APPLE_DEVELOPER_ID_APP)" \
		--options runtime \
		--timestamp \
		--force \
		$(ARM64_DIR)/pam_ackagent.so
	@echo "Verifying signatures..."
	codesign --verify --verbose $(ARM64_DIR)/ackagent-pam
	codesign --verify --verbose $(ARM64_DIR)/pam_ackagent.so

# Create package root structure
$(PKG_ROOT): build-arm64
	@echo "Creating package root..."
	@rm -rf $(PKG_ROOT)
	@mkdir -p $(PKG_ROOT)/usr/local/bin
	@mkdir -p $(PKG_ROOT)/usr/local/lib/pam
	cp $(ARM64_DIR)/ackagent-pam $(PKG_ROOT)/usr/local/bin/
	cp $(ARM64_DIR)/pam_ackagent.so $(PKG_ROOT)/usr/local/lib/pam/

# Create unsigned .pkg
pkg: $(PKG_ROOT)
	@echo "Creating component package..."
	@mkdir -p $(BUILD_DIR)
	pkgbuild --root $(PKG_ROOT) \
		--identifier $(PKG_IDENTIFIER) \
		--version $(VERSION) \
		--scripts scripts \
		--install-location / \
		$(BUILD_DIR)/ackagent-pam-component.pkg
	@echo "Creating product archive..."
	productbuild --distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--resources resources \
		$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg
	@echo "Created: $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg"

# Sign .pkg with Developer ID Installer certificate
pkg-sign: pkg
ifndef APPLE_DEVELOPER_ID_INSTALLER
	$(error APPLE_DEVELOPER_ID_INSTALLER is not set. Set it to your "Developer ID Installer: ..." certificate name)
endif
	@echo "Signing package..."
	productsign --sign "$(APPLE_DEVELOPER_ID_INSTALLER)" \
		$(BUILD_DIR)/$(PKG_NAME).unsigned.pkg \
		$(BUILD_DIR)/$(PKG_NAME)
	@rm -f $(BUILD_DIR)/$(PKG_NAME).unsigned.pkg
	@echo "Verifying package signature..."
	pkgutil --check-signature $(BUILD_DIR)/$(PKG_NAME)
	@echo "Created: $(BUILD_DIR)/$(PKG_NAME)"

# Notarize and staple
notarize: pkg-sign
ifndef APPLE_ID
	$(error APPLE_ID is not set)
endif
ifndef APPLE_APP_PASSWORD
	$(error APPLE_APP_PASSWORD is not set. Create an app-specific password at appleid.apple.com)
endif
ifndef APPLE_TEAM_ID
	$(error APPLE_TEAM_ID is not set)
endif
	@echo "Submitting for notarization..."
	xcrun notarytool submit $(BUILD_DIR)/$(PKG_NAME) \
		--apple-id "$(APPLE_ID)" \
		--password "$(APPLE_APP_PASSWORD)" \
		--team-id "$(APPLE_TEAM_ID)" \
		--wait
	@echo "Stapling notarization ticket..."
	xcrun stapler staple $(BUILD_DIR)/$(PKG_NAME)
	@echo "Verifying notarization..."
	spctl --assess --type install --verbose $(BUILD_DIR)/$(PKG_NAME)
	@echo "Notarized package ready: $(BUILD_DIR)/$(PKG_NAME)"

# Create tarball for distribution
tarball: sign
	@echo "Creating darwin-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pam-$(VERSION)-darwin-arm64
	cp $(ARM64_DIR)/ackagent-pam $(BUILD_DIR)/ackagent-pam-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pam-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pam-$(VERSION)-darwin-arm64.tar.gz ackagent-pam-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/ackagent-pam-$(VERSION)-darwin-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-pam-$(VERSION)-darwin-arm64.tar.gz"

# Full release build (build, sign, package, notarize)
release: sign pkg-sign notarize

# Build unsigned package (for testing)
pkg-unsigned: $(PKG_ROOT)
	@echo "Creating unsigned package (for testing)..."
	@mkdir -p $(BUILD_DIR)
	pkgbuild --root $(PKG_ROOT) \
		--identifier $(PKG_IDENTIFIER) \
		--version $(VERSION) \
		--scripts scripts \
		--install-location / \
		$(BUILD_DIR)/ackagent-pam-component.pkg
	productbuild --distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--resources resources \
		$(BUILD_DIR)/$(PKG_NAME)
	@echo "Created unsigned package: $(BUILD_DIR)/$(PKG_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# Show current version
version:
	@echo $(VERSION)

# Help
help:
	@echo "AckAgent PAM Packaging (macOS)"
	@echo ""
	@echo "This package includes both the PAM module and CLI tool for macOS."
	@echo ""
	@echo "Targets:"
	@echo "  build-arm64    Build ARM64 CLI binary and PAM module"
	@echo "  sign           Sign binaries (requires APPLE_DEVELOPER_ID_APP)"
	@echo "  pkg            Create unsigned .pkg"
	@echo "  pkg-unsigned   Create unsigned .pkg for testing"
	@echo "  pkg-sign       Create signed .pkg (requires APPLE_DEVELOPER_ID_INSTALLER)"
	@echo "  notarize       Notarize and staple (requires APPLE_ID, APPLE_APP_PASSWORD, APPLE_TEAM_ID)"
	@echo "  tarball        Create tarball for distribution (requires sign)"
	@echo "  release        Full release: sign + pkg-sign + notarize"
	@echo "  clean          Remove build artifacts"
	@echo ""
	@echo "Environment variables for signing:"
	@echo "  APPLE_DEVELOPER_ID_APP       Developer ID Application certificate name"
	@echo "  APPLE_DEVELOPER_ID_INSTALLER Developer ID Installer certificate name"
	@echo "  APPLE_ID                     Apple ID email"
	@echo "  APPLE_APP_PASSWORD           App-specific password"
	@echo "  APPLE_TEAM_ID                Team ID"
