.PHONY: all clean version help
.PHONY: build-amd64 build-arm64
.PHONY: tarballs-amd64 tarballs-arm64
.PHONY: deb-amd64 deb-arm64 rpm-amd64 rpm-arm64
.PHONY: packages-amd64 packages-arm64

# Version from git tag (consolidated cli/* tags for all platforms)
VERSION := $(shell git describe --tags --match 'cli/*' --always --dirty 2>/dev/null | sed 's|^cli/||' || echo "0.0.1")

# RPM-safe version: fpm converts dashes to underscores in --version,
# but NOT in --depends, so we must do it ourselves for consistency.
RPM_VERSION := $(subst -,_,$(VERSION))

# Directories
BUILD_DIR := build
CLI_DIR := ../..

all: build-amd64 build-arm64

# =============================================================================
# Build Targets
# =============================================================================

build-amd64:
	@echo "Building all components for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/amd64
	# ackagent CLI
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/amd64/ackagent ./cmd/ackagent
	# age-plugin-ackagent
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/amd64/age-plugin-ackagent ./cmd/age-plugin-ackagent
	# sk-provider
	cd $(CLI_DIR)/sk-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/amd64/libackagent-sk.so .
	@rm -f $(BUILD_DIR)/amd64/libackagent-sk.h
	# pkcs11-provider
	cd $(CLI_DIR)/pkcs11-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/amd64/libackagent-pkcs11.so .
	@rm -f $(BUILD_DIR)/amd64/libackagent-pkcs11.h

build-arm64:
	@echo "Building all components for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/arm64
	# ackagent CLI (requires cross-compiler for CGo/BBS+ FFI)
	cd $(CLI_DIR) && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/arm64/ackagent ./cmd/ackagent
	# age-plugin-ackagent (requires cross-compiler for CGo/BBS+ FFI)
	cd $(CLI_DIR) && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/linux/$(BUILD_DIR)/arm64/age-plugin-ackagent ./cmd/age-plugin-ackagent
	# sk-provider (requires cross-compiler)
	cd $(CLI_DIR)/sk-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/arm64/libackagent-sk.so .
	@rm -f $(BUILD_DIR)/arm64/libackagent-sk.h
	# pkcs11-provider (requires cross-compiler)
	cd $(CLI_DIR)/pkcs11-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/linux/$(BUILD_DIR)/arm64/libackagent-pkcs11.so .
	@rm -f $(BUILD_DIR)/arm64/libackagent-pkcs11.h

# =============================================================================
# Component Tarballs (for Homebrew Formula)
# =============================================================================

tarballs-amd64: build-amd64
	@echo "Creating amd64 component tarballs..."
	@mkdir -p $(BUILD_DIR)/tarballs
	# ackagent tarball
	@mkdir -p $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/ackagent $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-$(VERSION)-linux-amd64.tar.gz ackagent-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64
	# ackagent-sk-provider tarball
	@mkdir -p $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/libackagent-sk.so $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-sk-provider-$(VERSION)-linux-amd64.tar.gz ackagent-sk-provider-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-amd64
	# ackagent-pkcs11 tarball
	@mkdir -p $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/libackagent-pkcs11.so $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-pkcs11-$(VERSION)-linux-amd64.tar.gz ackagent-pkcs11-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64
	# ackagent-age-plugin tarball
	@mkdir -p $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/age-plugin-ackagent $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-age-plugin-$(VERSION)-linux-amd64.tar.gz ackagent-age-plugin-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-amd64
	@echo "Created component tarballs in $(BUILD_DIR)/tarballs/"

tarballs-arm64: build-arm64
	@echo "Creating arm64 component tarballs..."
	@mkdir -p $(BUILD_DIR)/tarballs
	# ackagent tarball
	@mkdir -p $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/ackagent $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-$(VERSION)-linux-arm64.tar.gz ackagent-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64
	# ackagent-sk-provider tarball
	@mkdir -p $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/libackagent-sk.so $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-sk-provider-$(VERSION)-linux-arm64.tar.gz ackagent-sk-provider-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-sk-provider-$(VERSION)-linux-arm64
	# ackagent-pkcs11 tarball
	@mkdir -p $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/libackagent-pkcs11.so $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-pkcs11-$(VERSION)-linux-arm64.tar.gz ackagent-pkcs11-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64
	# ackagent-age-plugin tarball
	@mkdir -p $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/age-plugin-ackagent $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf tarballs/ackagent-age-plugin-$(VERSION)-linux-arm64.tar.gz ackagent-age-plugin-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-age-plugin-$(VERSION)-linux-arm64
	@echo "Created component tarballs in $(BUILD_DIR)/tarballs/"

# =============================================================================
# Component deb/rpm Packages (with dependencies)
# =============================================================================

deb-amd64: build-amd64
	@echo "Creating amd64 deb packages..."
	# ackagent-cli (CLI binary)
	fpm -s dir -t deb --architecture amd64 \
		--name ackagent-cli \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Out-of-band approval CLI tool" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends libc6 \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/ackagent=/usr/local/bin/ackagent
	# ackagent-sk-provider
	fpm -s dir -t deb --architecture amd64 \
		--name ackagent-sk-provider \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "SSH SecurityKey provider for AckAgent (software keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libackagent-sk.so=/usr/local/lib/libackagent-sk.so
	# ackagent-pkcs11
	fpm -s dir -t deb --architecture amd64 \
		--name ackagent-pkcs11 \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "PKCS#11 provider for AckAgent (hardware keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libackagent-pkcs11.so=/usr/local/lib/libackagent-pkcs11.so
	# ackagent-age-plugin
	fpm -s dir -t deb --architecture amd64 \
		--name ackagent-age-plugin \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Age encryption plugin for AckAgent" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/age-plugin-ackagent=/usr/local/bin/age-plugin-ackagent
	# ackagent (meta-package)
	fpm -s empty -t deb --architecture amd64 \
		--name ackagent \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Complete AckAgent CLI suite (meta-package)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends "ackagent-sk-provider = $(VERSION)" \
		--depends "ackagent-pkcs11 = $(VERSION)" \
		--depends "ackagent-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created deb packages in $(BUILD_DIR)/"

deb-arm64: build-arm64
	@echo "Creating arm64 deb packages..."
	# ackagent-cli (CLI binary)
	fpm -s dir -t deb --architecture arm64 \
		--name ackagent-cli \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Out-of-band approval CLI tool" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends libc6 \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/ackagent=/usr/local/bin/ackagent
	# ackagent-sk-provider
	fpm -s dir -t deb --architecture arm64 \
		--name ackagent-sk-provider \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "SSH SecurityKey provider for AckAgent (software keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libackagent-sk.so=/usr/local/lib/libackagent-sk.so
	# ackagent-pkcs11
	fpm -s dir -t deb --architecture arm64 \
		--name ackagent-pkcs11 \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "PKCS#11 provider for AckAgent (hardware keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends libc6 \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libackagent-pkcs11.so=/usr/local/lib/libackagent-pkcs11.so
	# ackagent-age-plugin
	fpm -s dir -t deb --architecture arm64 \
		--name ackagent-age-plugin \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Age encryption plugin for AckAgent" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/age-plugin-ackagent=/usr/local/bin/age-plugin-ackagent
	# ackagent (meta-package)
	fpm -s empty -t deb --architecture arm64 \
		--name ackagent \
		--version $(VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Complete AckAgent CLI suite (meta-package)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(VERSION)" \
		--depends "ackagent-sk-provider = $(VERSION)" \
		--depends "ackagent-pkcs11 = $(VERSION)" \
		--depends "ackagent-age-plugin = $(VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created deb packages in $(BUILD_DIR)/"

rpm-amd64: build-amd64
	@echo "Creating x86_64 rpm packages..."
	# ackagent-cli (CLI binary)
	fpm -s dir -t rpm --architecture x86_64 \
		--name ackagent-cli \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Out-of-band approval CLI tool" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends glibc \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/ackagent=/usr/local/bin/ackagent
	# ackagent-sk-provider
	fpm -s dir -t rpm --architecture x86_64 \
		--name ackagent-sk-provider \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "SSH SecurityKey provider for AckAgent (software keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libackagent-sk.so=/usr/local/lib/libackagent-sk.so
	# ackagent-pkcs11
	fpm -s dir -t rpm --architecture x86_64 \
		--name ackagent-pkcs11 \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "PKCS#11 provider for AckAgent (hardware keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/libackagent-pkcs11.so=/usr/local/lib/libackagent-pkcs11.so
	# ackagent-age-plugin
	fpm -s dir -t rpm --architecture x86_64 \
		--name ackagent-age-plugin \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Age encryption plugin for AckAgent" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/amd64/age-plugin-ackagent=/usr/local/bin/age-plugin-ackagent
	# ackagent (meta-package)
	fpm -s empty -t rpm --architecture x86_64 \
		--name ackagent \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Complete AckAgent CLI suite (meta-package)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends "ackagent-sk-provider = $(RPM_VERSION)" \
		--depends "ackagent-pkcs11 = $(RPM_VERSION)" \
		--depends "ackagent-age-plugin = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created rpm packages in $(BUILD_DIR)/"

rpm-arm64: build-arm64
	@echo "Creating aarch64 rpm packages..."
	# ackagent-cli (CLI binary)
	fpm -s dir -t rpm --architecture aarch64 \
		--name ackagent-cli \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Out-of-band approval CLI tool" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends glibc \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/ackagent=/usr/local/bin/ackagent
	# ackagent-sk-provider
	fpm -s dir -t rpm --architecture aarch64 \
		--name ackagent-sk-provider \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "SSH SecurityKey provider for AckAgent (software keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libackagent-sk.so=/usr/local/lib/libackagent-sk.so
	# ackagent-pkcs11
	fpm -s dir -t rpm --architecture aarch64 \
		--name ackagent-pkcs11 \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "PKCS#11 provider for AckAgent (hardware keys)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends glibc \
		--after-install postinstall.sh \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/libackagent-pkcs11.so=/usr/local/lib/libackagent-pkcs11.so
	# ackagent-age-plugin
	fpm -s dir -t rpm --architecture aarch64 \
		--name ackagent-age-plugin \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Age encryption plugin for AckAgent" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/ \
		$(BUILD_DIR)/arm64/age-plugin-ackagent=/usr/local/bin/age-plugin-ackagent
	# ackagent (meta-package)
	fpm -s empty -t rpm --architecture aarch64 \
		--name ackagent \
		--version $(RPM_VERSION) \
		--maintainer "AckAgent <hello@ackagent.com>" \
		--description "Complete AckAgent CLI suite (meta-package)" \
		--url "https://github.com/ackagent/ackagent" \
		--license "MIT" \
		--depends "ackagent-cli = $(RPM_VERSION)" \
		--depends "ackagent-sk-provider = $(RPM_VERSION)" \
		--depends "ackagent-pkcs11 = $(RPM_VERSION)" \
		--depends "ackagent-age-plugin = $(RPM_VERSION)" \
		--package $(BUILD_DIR)/
	@echo "Created rpm packages in $(BUILD_DIR)/"

# =============================================================================
# Combined Targets
# =============================================================================

packages-amd64: tarballs-amd64 deb-amd64 rpm-amd64
packages-arm64: tarballs-arm64 deb-arm64 rpm-arm64

# =============================================================================
# Utility Targets
# =============================================================================

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)

help:
	@echo "AckAgent CLI Linux Packaging"
	@echo ""
	@echo "Build Targets:"
	@echo "  build-amd64        Build all components for x86_64"
	@echo "  build-arm64        Build all components for arm64"
	@echo ""
	@echo "Package Targets:"
	@echo "  tarballs-amd64     Create amd64 component tarballs"
	@echo "  tarballs-arm64     Create arm64 component tarballs"
	@echo "  deb-amd64          Create amd64 component debs"
	@echo "  deb-arm64          Create arm64 component debs"
	@echo "  rpm-amd64          Create x86_64 component rpms"
	@echo "  rpm-arm64          Create aarch64 component rpms"
	@echo "  packages-amd64     Create all amd64 packages"
	@echo "  packages-arm64     Create all arm64 packages"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean              Remove build artifacts"
	@echo "  version            Show current version"
	@echo ""
	@echo "Dependencies:"
	@echo "  sudo apt install gcc-aarch64-linux-gnu  # For arm64 cross-compilation"
	@echo "  sudo gem install fpm                    # For deb/rpm packages"
