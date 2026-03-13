BINARY      := femto
CMD         := ./cmd/femto
GO          := go
GOFLAGS     :=
LDFLAGS     := -s -w
BUILDFLAGS  := $(GOFLAGS) -ldflags="$(LDFLAGS)"

# Detect version from git, fall back to "dev"
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS_FULL := -s -w \
	-X main.version=$(VERSION) \
	-X main.buildTime=$(BUILD_TIME)

# Default target
.PHONY: all
all: build

# ── Build ────────────────────────────────────────────────────────────────────

## build: compile a dynamically linked binary (fast, for development)
.PHONY: build
build:
	$(GO) build $(GOFLAGS) -o $(BINARY) $(CMD)

## static: compile a fully static, stripped binary (for production / embedded)
.PHONY: static
static:
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS_FULL)" -o $(BINARY) $(CMD)

## release: like static but names the output with version and arch
.PHONY: release
release:
	CGO_ENABLED=0 $(GO) build \
		-ldflags="$(LDFLAGS_FULL)" \
		-o $(BINARY)-$(VERSION)-$(shell go env GOOS)-$(shell go env GOARCH) \
		$(CMD)

# ── Quality ──────────────────────────────────────────────────────────────────

## test: run the full test suite
.PHONY: test
test:
	$(GO) test ./...

## test-v: run the full test suite with verbose output
.PHONY: test-v
test-v:
	$(GO) test -v ./...

## cover: generate an HTML coverage report (opens in $BROWSER if set)
.PHONY: cover
cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report written to coverage.html"

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet ./...

## fmt: format all source files
.PHONY: fmt
fmt:
	$(GO) fmt ./...

## lint: run vet + check formatting
.PHONY: lint
lint: vet
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

## check: lint + test (CI gate)
.PHONY: check
check: lint test

# ── Maintenance ──────────────────────────────────────────────────────────────

## tidy: tidy and verify the module graph
.PHONY: tidy
tidy:
	$(GO) mod tidy
	$(GO) mod verify

## clean: remove build artifacts
.PHONY: clean
clean:
	$(GO) clean
	rm -f $(BINARY) $(BINARY)-* coverage.out coverage.html

## setcap: grant the binary permission to bind ports < 1024 without root
.PHONY: setcap
setcap:
	sudo setcap cap_net_bind_service=+ep $(BINARY)

# ── Help ─────────────────────────────────────────────────────────────────────

## help: list available targets
.PHONY: help
help:
	@echo "Usage: make <target>"
	@echo ""
	@grep -E '^## [a-z]' Makefile | sed 's/## /  /'
