# Contraband Egress Assessment Framework Makefile
# Pure-Go static compilation under CGO_ENABLED=0

MODULE      := github.com/shehzade/contraband
BINARY_NAME := contraband
BIN_DIR     := bin

# Build Metadata
VERSION     ?= 1.0.0
COMMIT      ?= standalone
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILT_BY    ?= shehzade

# Static linker flags
LDFLAGS := -s -w \
	-X '$(MODULE)/pkg/common.Version=$(VERSION)' \
	-X '$(MODULE)/pkg/common.Commit=$(COMMIT)' \
	-X '$(MODULE)/pkg/common.BuildDate=$(BUILD_DATE)' \
	-X '$(MODULE)/pkg/common.BuiltBy=$(BUILT_BY)'

# Build command template
BUILD_CMD = CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)"

PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64
COMMANDS  := contraband contraband-client contraband-server

.PHONY: all build build-all clean vet lint tidy help wiki-push

all: build

help:
	@echo "Contraband Build System"
	@echo "  make build             - Compile native static binaries for current platform (contraband, client, server)"
	@echo "  make build-all         - Cross-compile all 18 static binaries for Linux, Windows, macOS (amd64/arm64)"
	@echo "  make vet               - Run go vet static analysis"
	@echo "  make tidy              - Run go mod tidy"
	@echo "  make clean             - Remove compiled binaries and artifacts"

build:
	@mkdir -p $(BIN_DIR)
	$(BUILD_CMD) -o $(BIN_DIR)/contraband ./cmd/contraband
	$(BUILD_CMD) -o $(BIN_DIR)/contraband-client ./cmd/contraband-client
	$(BUILD_CMD) -o $(BIN_DIR)/contraband-server ./cmd/contraband-server
	@echo "[+] Successfully built native binaries in $(BIN_DIR)/"

build-all:
	@mkdir -p $(BIN_DIR)
	@echo "[*] Cross-compiling 18 static pure-Go binaries across 6 OS/ARCH targets..."
	@for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64; do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "    -> Building contraband ($$os/$$arch)..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(BUILD_CMD) -o $(BIN_DIR)/contraband-$$os-$$arch$$ext ./cmd/contraband || exit 1; \
		echo "    -> Building contraband-client ($$os/$$arch)..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(BUILD_CMD) -o $(BIN_DIR)/contraband-client-$$os-$$arch$$ext ./cmd/contraband-client || exit 1; \
		echo "    -> Building contraband-server ($$os/$$arch)..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(BUILD_CMD) -o $(BIN_DIR)/contraband-server-$$os-$$arch$$ext ./cmd/contraband-server || exit 1; \
	done
	@cp $(BIN_DIR)/contraband-linux-amd64 $(BIN_DIR)/contraband
	@cp $(BIN_DIR)/contraband-client-linux-amd64 $(BIN_DIR)/contraband-client
	@cp $(BIN_DIR)/contraband-server-linux-amd64 $(BIN_DIR)/contraband-server
	@echo "[+] All 18 platform binaries compiled successfully in $(BIN_DIR)/"

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BIN_DIR)
	@echo "[+] Cleaned $(BIN_DIR)"

wiki-push:
	@echo "[*] Syncing docs/wiki to GitHub Wiki..."
	@bash -c 'if [ -d docs/wiki ]; then \
		echo "[+] docs/wiki is ready. To push to GitHub Wiki: git subtree push --prefix docs/wiki origin wiki"; \
	fi'
