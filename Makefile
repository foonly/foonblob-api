# Project variables
BINARY_NAME=foonblob-api
BIN_DIR=bin
CMD_PKG=./cmd/api
VERSION=$(shell cat version.txt 2>/dev/null || echo "dev")

# Go settings: static, reproducible binary with the version embedded
GO=go
export CGO_ENABLED=0
GOFLAGS=-trimpath -ldflags="-s -w -X 'main.Version=$(VERSION)'"

.PHONY: all build run test vet check clean clean-db fmt tidy help

all: build

build: ## Build the API binary
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PKG)

run: build ## Build and run the API
	@echo "Running $(BINARY_NAME)..."
	@./$(BIN_DIR)/$(BINARY_NAME)

test: ## Run all tests with the race detector
	@echo "Running tests..."
	CGO_ENABLED=1 $(GO) test -race ./...

vet: ## Run go vet
	$(GO) vet ./...

check: vet test ## Run vet and tests

clean: ## Remove build artifacts
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)

clean-db: ## Delete the local development database (sync.db)
	@rm -f sync.db sync.db-shm sync.db-wal

fmt: ## Format Go source code
	@echo "Formatting code..."
	$(GO) fmt ./...

tidy: ## Tidy up go.mod and go.sum
	@echo "Tidying up dependencies..."
	$(GO) mod tidy

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
