# Makefile for Tracium Agent
# Cross-platform compilation using Go

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary name
BINARY_NAME=tracium
BINARY_UNIX=$(BINARY_NAME)_unix

# Build directory
BUILD_DIR=build

# Version
VERSION=1.0.0

# Supported platforms
PLATFORMS := linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 openbsd/amd64

.PHONY: all build clean test deps help

# Default target
all: deps test build-all

# Get dependencies
deps:
	$(GOMOD) tidy
	$(GOMOD) download

# Run tests
test:
	$(GOTEST) -v ./...

# Build for current platform
build:
	$(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME) -v ./cmd/tracium

# Build for Linux (default)
build-linux: build-linux-amd64 build-linux-arm64

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 -v ./cmd/tracium

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 -v ./cmd/tracium

build-linux-arm:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm -v ./cmd/tracium

# Build for macOS (Darwin)
build-darwin: build-darwin-amd64 build-darwin-arm64

build-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 -v ./cmd/tracium

build-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 -v ./cmd/tracium

# Build for Windows
build-windows: build-windows-amd64 build-windows-arm64

build-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe -v ./cmd/tracium

build-windows-arm64:
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe -v ./cmd/tracium

# Build for FreeBSD
build-freebsd-amd64:
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-freebsd-amd64 -v ./cmd/tracium

# Build for OpenBSD
build-openbsd-amd64:
	CGO_ENABLED=0 GOOS=openbsd GOARCH=amd64 $(GOBUILD) -mod=vendor -o $(BUILD_DIR)/$(BINARY_NAME)-openbsd-amd64 -v ./cmd/tracium

# Build for all supported platforms
build-all: build-linux build-darwin build-windows build-freebsd-amd64 build-openbsd-amd64
	@echo "Build completed for all platforms"

# Create release archives
release: build-all
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		if [ "$$os" = "windows" ]; then \
			zip -j $(BUILD_DIR)/release/$(BINARY_NAME)-$$os-$$arch-$(VERSION).zip $(BUILD_DIR)/$(BINARY_NAME)-$$os-$$arch.exe; \
		else \
			tar -czf $(BUILD_DIR)/release/$(BINARY_NAME)-$$os-$$arch-$(VERSION).tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-$$os-$$arch; \
		fi; \
	done
	@echo "Release archives created in $(BUILD_DIR)/release/"

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run the binary
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

# Update vendor directory
vendor:
	$(GOMOD) vendor

# Format code
fmt:
	$(GOCMD) fmt ./...

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Run deps, test, and build-all"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  test             - Run tests"
	@echo "  build            - Build for current platform"
	@echo "  build-linux      - Build for Linux (amd64, arm64)"
	@echo "  build-darwin     - Build for macOS (amd64, arm64)"
	@echo "  build-windows    - Build for Windows (amd64, arm64)"
	@echo "  build-freebsd    - Build for FreeBSD (amd64)"
	@echo "  build-openbsd    - Build for OpenBSD (amd64)"
	@echo "  build-all        - Build for all supported platforms"
	@echo "  release          - Create release archives for all platforms"
	@echo "  clean            - Clean build artifacts"
	@echo "  run              - Build and run the binary"
	@echo "  vendor           - Update vendor directory"
	@echo "  fmt              - Format Go code"
	@echo "  lint             - Lint Go code (requires golangci-lint)"
	@echo "  help             - Show this help message"