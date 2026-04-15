BINARY := fbsts
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BUILD_DIR := build

PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64

.PHONY: all build clean test vet lint help $(PLATFORMS)

all: test build ## Run tests then build for current platform

build: ## Build for current platform
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/fbsts

$(PLATFORMS): ## Build for a specific platform (e.g., make darwin/arm64)
	$(eval GOOS := $(word 1,$(subst /, ,$@)))
	$(eval GOARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT := $(if $(filter windows,$(GOOS)),.exe,))
	@mkdir -p $(BUILD_DIR)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 \
		go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT) ./cmd/fbsts
	@echo "  built $(BUILD_DIR)/$(BINARY)-$(GOOS)-$(GOARCH)$(EXT)"

build-all: $(PLATFORMS) ## Build for all platforms
	@echo "\nAll binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

test: ## Run all tests
	go test ./... -timeout 60s

vet: ## Run go vet
	go vet ./...

lint: vet ## Run linters (currently just vet)

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR) $(BINARY)

help: ## Show this help
	@grep -E '^[a-zA-Z_/.-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
