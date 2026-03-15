.PHONY: all build-darwin-arm64 build-linux-amd64 build-linux-arm64 tarball-darwin-arm64 tarball-linux-amd64 tarball-linux-arm64 clean

# Version from git tag
VERSION := $(shell git describe --tags --match 'cli/*' --always --dirty 2>/dev/null | sed 's|^cli/||' || echo "0.0.1")

# Directories
BUILD_DIR := build
CLI_DIR := ../../..

all: build-darwin-arm64

# === Build targets ===

build-darwin-arm64:
	@echo "Building pkcs11-provider for darwin/arm64..."
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	cd $(CLI_DIR)/pkcs11-provider && CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/pkcs11/$(BUILD_DIR)/darwin-arm64/libackagent-pkcs11.dylib .
	@rm -f $(BUILD_DIR)/darwin-arm64/libackagent-pkcs11.h

build-linux-amd64:
	@echo "Building pkcs11-provider for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	cd $(CLI_DIR)/pkcs11-provider && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/pkcs11/$(BUILD_DIR)/linux-amd64/libackagent-pkcs11.so .
	@rm -f $(BUILD_DIR)/linux-amd64/libackagent-pkcs11.h

build-linux-arm64:
	@echo "Building pkcs11-provider for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/linux-arm64
	cd $(CLI_DIR)/pkcs11-provider && CC=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build \
		-buildmode=c-shared \
		-ldflags="-s -w -X main.version=$(VERSION)" \
		-o ../packaging/components/pkcs11/$(BUILD_DIR)/linux-arm64/libackagent-pkcs11.so .
	@rm -f $(BUILD_DIR)/linux-arm64/libackagent-pkcs11.h

# === Tarball targets ===

tarball-darwin-arm64: build-darwin-arm64
	@echo "Creating ackagent-pkcs11 darwin-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-darwin-arm64
	cp $(BUILD_DIR)/darwin-arm64/libackagent-pkcs11.dylib $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pkcs11-$(VERSION)-darwin-arm64.tar.gz ackagent-pkcs11-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-darwin-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-darwin-arm64.tar.gz"

tarball-linux-amd64: build-linux-amd64
	@echo "Creating ackagent-pkcs11 linux-amd64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/linux-amd64/libackagent-pkcs11.so $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pkcs11-$(VERSION)-linux-amd64.tar.gz ackagent-pkcs11-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64
	@echo "Created: $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-amd64.tar.gz"

tarball-linux-arm64: build-linux-arm64
	@echo "Creating ackagent-pkcs11 linux-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/linux-arm64/libackagent-pkcs11.so $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-pkcs11-$(VERSION)-linux-arm64.tar.gz ackagent-pkcs11-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-pkcs11-$(VERSION)-linux-arm64.tar.gz"

clean:
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)
