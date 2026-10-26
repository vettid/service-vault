GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: all build test race lint vet staticcheck fmt scan tidy clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/service-vault ./cmd/service-vault

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

fmt:
	test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

scan:
	gitleaks git --redact .

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN)
