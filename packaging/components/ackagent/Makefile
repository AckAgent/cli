.PHONY: all build-darwin-arm64 build-linux-amd64 build-linux-arm64 tarball-darwin-arm64 tarball-linux-amd64 tarball-linux-arm64 clean

# Version from git tag
VERSION := $(shell git describe --tags --match 'cli/*' --always --dirty 2>/dev/null | sed 's|^cli/||' || echo "0.0.1")

# Directories
BUILD_DIR := build
CLI_DIR := ../../..

all: build-darwin-arm64

# === Build targets ===

build-darwin-arm64:
	@echo "Building ackagent CLI for darwin/arm64..."
	@mkdir -p $(BUILD_DIR)/darwin-arm64
	cd $(CLI_DIR) && GOOS=darwin GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/components/ackagent/$(BUILD_DIR)/darwin-arm64/ackagent ./cmd/ackagent

build-linux-amd64:
	@echo "Building ackagent CLI for linux/amd64..."
	@mkdir -p $(BUILD_DIR)/linux-amd64
	cd $(CLI_DIR) && GOOS=linux GOARCH=amd64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/components/ackagent/$(BUILD_DIR)/linux-amd64/ackagent ./cmd/ackagent

build-linux-arm64:
	@echo "Building ackagent CLI for linux/arm64..."
	@mkdir -p $(BUILD_DIR)/linux-arm64
	cd $(CLI_DIR) && GOOS=linux GOARCH=arm64 go build \
		-ldflags="-s -w -X github.com/ackagent/cli/internal/shared/version.Version=$(VERSION)" \
		-o packaging/components/ackagent/$(BUILD_DIR)/linux-arm64/ackagent ./cmd/ackagent

# === Tarball targets ===

tarball-darwin-arm64: build-darwin-arm64
	@echo "Creating ackagent darwin-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-$(VERSION)-darwin-arm64
	cp $(BUILD_DIR)/darwin-arm64/ackagent $(BUILD_DIR)/ackagent-$(VERSION)-darwin-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-$(VERSION)-darwin-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-$(VERSION)-darwin-arm64.tar.gz ackagent-$(VERSION)-darwin-arm64
	@rm -rf $(BUILD_DIR)/ackagent-$(VERSION)-darwin-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-$(VERSION)-darwin-arm64.tar.gz"

tarball-linux-amd64: build-linux-amd64
	@echo "Creating ackagent linux-amd64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64
	cp $(BUILD_DIR)/linux-amd64/ackagent $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64/
	cd $(BUILD_DIR) && tar -czvf ackagent-$(VERSION)-linux-amd64.tar.gz ackagent-$(VERSION)-linux-amd64
	@rm -rf $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64
	@echo "Created: $(BUILD_DIR)/ackagent-$(VERSION)-linux-amd64.tar.gz"

tarball-linux-arm64: build-linux-arm64
	@echo "Creating ackagent linux-arm64 tarball..."
	@mkdir -p $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64
	cp $(BUILD_DIR)/linux-arm64/ackagent $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64/
	cp $(CLI_DIR)/NOTICES $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64/
	cd $(BUILD_DIR) && tar -czvf ackagent-$(VERSION)-linux-arm64.tar.gz ackagent-$(VERSION)-linux-arm64
	@rm -rf $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64
	@echo "Created: $(BUILD_DIR)/ackagent-$(VERSION)-linux-arm64.tar.gz"

clean:
	rm -rf $(BUILD_DIR)

version:
	@echo $(VERSION)
