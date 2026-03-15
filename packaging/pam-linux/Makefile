.PHONY: all build-amd64 build-arm64 tarball-amd64 tarball-arm64 deb-amd64 deb-arm64 rpm-amd64 rpm-arm64 packages-amd64 packages-arm64 clean version help

# Version from git tag (pam/* tags)
VERSION := $(shell git describe --tags --match 'pam/*' --always --dirty 2>/dev/null | sed 's|^pam/||' || echo "0.0.1")

# Directories
BUILD_DIR := build
CLI_DIR := ../..

all: build-amd64 build-arm64

# Build amd64 binaries (CLI + PAM module)
build-amd64:
	@echo "Building ackagent-pam CLI for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/amd64
	cd $(CLI_DIR) && GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" -o packaging/pam-linux/$(BUILD_DIR)/amd64/ackagent-pam ./cmd/ackagent-pam
	@echo "Building pam_ackagent.so for linux/amd64..."
	cd $(CLI_DIR) && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -ldflags="-s -w" -o packaging/pam-linux/$(BUILD_DIR)/amd64/pam_ackagent.so ./cmd/pam-module
	@rm -f $(BUILD_DIR)/amd64/pam_ackagent.h

# Build arm64 binaries (requires cross-compiler: apt install gcc-aarch64-linux-gnu)
build-arm64:
	@echo "Building ackagent-pam CLI for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/arm64
	cd $(CLI_DIR) && GOOS=linux GOARCH=arm64 go build -ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" -o packaging/pam-linux/$(BUILD_DIR)/arm64/ackagent-pam ./cmd/ackagent-pam
	@echo "Building pam_ackagent.so for linux/arm64..."
	cd $(CLI_DIR) && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=c-shared -ldflags="-s -w" -o packaging/pam-linux/$(BUILD_DIR)/arm64/pam_ackagent.so ./cmd/pam-module
	@rm -f $(BUILD_DIR)/arm64/pam_ackagent.h

# Create tarball for amd64
tarball-amd64: build-amd64
	@echo "Creating amd64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/amd64/ackagent-pam $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp $(BUILD_DIR)/amd64/pam_ackagent.so $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp install.sh $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp README.txt $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp etc/ackagent/pam.conf.example $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp etc/pam.d/ackagent.example $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pam-$(VERSION)-linux-amd64.tar.gz ackagent-pam-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64
	@echo "Created: $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-amd64.tar.gz"

# Create tarball for arm64
tarball-arm64: build-arm64
	@echo "Creating arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/arm64/ackagent-pam $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp $(BUILD_DIR)/arm64/pam_ackagent.so $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp install.sh $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp README.txt $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp etc/ackagent/pam.conf.example $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp etc/pam.d/ackagent.example $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pam-$(VERSION)-linux-arm64.tar.gz ackagent-pam-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-pam-$(VERSION)-linux-arm64.tar.gz"

# Create both tarballs
tarball: tarball-amd64 tarball-arm64

# Common fpm options
FPM_BASE = --name ackagent-pam \
    --version $(VERSION) \
    --maintainer "AckAgent <hello@ackagent.com>" \
    --description "PAM module for AckAgent push-based authentication" \
    --url "https://github.com/ackagent/ackagent" \
    --license "MIT" \
    --after-install postinstall.sh

# Create .deb package for amd64
deb-amd64: build-amd64
	@echo "Creating amd64 deb package..."
	fpm -s dir -t deb --architecture amd64 $(FPM_BASE) --depends libpam0g \
	    --package $(BUILD_DIR)/ \
	    $(BUILD_DIR)/amd64/ackagent-pam=/usr/local/bin/ackagent-pam \
	    $(BUILD_DIR)/amd64/pam_ackagent.so=/lib/x86_64-linux-gnu/security/pam_ackagent.so \
	    etc/ackagent/pam.conf.example=/etc/ackagent/pam.conf.example \
	    etc/pam.d/ackagent.example=/etc/pam.d/ackagent.example
	@echo "Created: $(BUILD_DIR)/ackagent-pam_$(VERSION)_amd64.deb"

# Create .deb package for arm64
deb-arm64: build-arm64
	@echo "Creating arm64 deb package..."
	fpm -s dir -t deb --architecture arm64 $(FPM_BASE) --depends libpam0g \
	    --package $(BUILD_DIR)/ \
	    $(BUILD_DIR)/arm64/ackagent-pam=/usr/local/bin/ackagent-pam \
	    $(BUILD_DIR)/arm64/pam_ackagent.so=/lib/aarch64-linux-gnu/security/pam_ackagent.so \
	    etc/ackagent/pam.conf.example=/etc/ackagent/pam.conf.example \
	    etc/pam.d/ackagent.example=/etc/pam.d/ackagent.example
	@echo "Created: $(BUILD_DIR)/ackagent-pam_$(VERSION)_arm64.deb"

# Create .rpm package for amd64 (x86_64)
rpm-amd64: build-amd64
	@echo "Creating x86_64 rpm package..."
	fpm -s dir -t rpm --architecture x86_64 $(FPM_BASE) --depends pam \
	    --package $(BUILD_DIR)/ \
	    $(BUILD_DIR)/amd64/ackagent-pam=/usr/local/bin/ackagent-pam \
	    $(BUILD_DIR)/amd64/pam_ackagent.so=/lib64/security/pam_ackagent.so \
	    etc/ackagent/pam.conf.example=/etc/ackagent/pam.conf.example \
	    etc/pam.d/ackagent.example=/etc/pam.d/ackagent.example
	@echo "Created: $(BUILD_DIR)/ackagent-pam-$(VERSION)-1.x86_64.rpm"

# Create .rpm package for arm64 (aarch64)
rpm-arm64: build-arm64
	@echo "Creating aarch64 rpm package..."
	fpm -s dir -t rpm --architecture aarch64 $(FPM_BASE) --depends pam \
	    --package $(BUILD_DIR)/ \
	    $(BUILD_DIR)/arm64/ackagent-pam=/usr/local/bin/ackagent-pam \
	    $(BUILD_DIR)/arm64/pam_ackagent.so=/lib64/security/pam_ackagent.so \
	    etc/ackagent/pam.conf.example=/etc/ackagent/pam.conf.example \
	    etc/pam.d/ackagent.example=/etc/pam.d/ackagent.example
	@echo "Created: $(BUILD_DIR)/ackagent-pam-$(VERSION)-1.aarch64.rpm"

# Build all packages for an architecture
packages-amd64: tarball-amd64 deb-amd64 rpm-amd64
packages-arm64: tarball-arm64 deb-arm64 rpm-arm64

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)

# Show current version
version:
	@echo $(VERSION)

help:
	@echo "AckAgent PAM Linux Packaging"
	@echo ""
	@echo "Targets:"
	@echo "  build-amd64     Build x86_64 binaries (CLI + PAM module)"
	@echo "  build-arm64     Build arm64 binaries (requires gcc-aarch64-linux-gnu)"
	@echo "  tarball-amd64   Create amd64 tarball"
	@echo "  tarball-arm64   Create arm64 tarball"
	@echo "  tarball         Create both tarballs"
	@echo "  deb-amd64       Create amd64 deb package (requires fpm)"
	@echo "  deb-arm64       Create arm64 deb package (requires fpm)"
	@echo "  rpm-amd64       Create x86_64 rpm package (requires fpm)"
	@echo "  rpm-arm64       Create aarch64 rpm package (requires fpm)"
	@echo "  packages-amd64  Create all amd64 packages"
	@echo "  packages-arm64  Create all arm64 packages"
	@echo "  clean           Remove build artifacts"
	@echo "  version         Show current version"
	@echo ""
	@echo "Dependencies:"
	@echo "  sudo apt install gcc-aarch64-linux-gnu libpam0g-dev  # For arm64 cross-compilation"
	@echo "  sudo gem install fpm                                  # For deb/rpm packages"
