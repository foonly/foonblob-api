# Project variables
BINARY_NAME=foonblob-api
BIN_DIR=bin
CMD_DIR=cmd/api
VERSION=$(shell cat version.txt 2>/dev/null || echo "dev")

# Go settings
GO=go
GOFLAGS=-ldflags="-X 'main.Version=$(VERSION)'"

.PHONY: all build run test clean fmt tidy help

all: build

build: ## Build the API binary
	@echo "Building $(BINARY_NAME) $(VERSION)..."
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)/main.go

run: build ## Build and run the API
	@echo "Running $(BINARY_NAME)..."
	@./$(BIN_DIR)/$(BINARY_NAME)

test: ## Run all tests
	@echo "Running tests..."
	$(GO) test -v ./...

clean: ## Remove build artifacts and temporary database files
	@echo "Cleaning up..."
	@rm -rf $(BIN_DIR)
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
