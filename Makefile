# Go version is taken from go.mod; GOTOOLCHAIN=auto downloads it if needed.
GO            ?= go
BIN           := bin/tfplan-risk
PKG           := ./cmd/tfplan-risk
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS       := -s -w -X main.version=$(VERSION)
GOLANGCI_VER  := v2.15.0
# Uses a local golangci-lint if installed, otherwise the official image.
GOLANGCI      := $(shell command -v golangci-lint 2>/dev/null || echo docker run --rm -v $(CURDIR):/src -w /src golangci/golangci-lint:$(GOLANGCI_VER) golangci-lint)
COVER_PKGS    := ./plan/...,./rules/...,./engine/...
FUZZTIME      ?= 30s

.PHONY: all build test race lint cover golden fuzz vet tidy clean help

all: lint race build ## Lint, test with -race and build

build: ## Build the binary into bin/
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

test: ## Run unit tests
	$(GO) test ./...

race: ## Run tests with the race detector
	$(GO) test -race ./...

vet: ## Run go vet
	$(GO) vet ./...

lint: ## Run golangci-lint
	$(GOLANGCI) run ./...

cover: ## Coverage report for core packages (plan, rules, engine)
	$(GO) test -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out ./plan/... ./rules/... ./engine/...
	$(GO) tool cover -func=coverage.out | tail -1

golden: ## Regenerate renderer golden files
	$(GO) test ./report/ -update

fuzz: ## Fuzz the plan parser (FUZZTIME=30s)
	$(GO) test ./plan/ -run='^$$' -fuzz=FuzzParse -fuzztime=$(FUZZTIME)

tidy: ## go mod tidy
	$(GO) mod tidy

clean: ## Remove build artifacts
	rm -rf bin dist coverage.out

help: ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
