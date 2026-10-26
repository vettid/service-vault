GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: all build test race lint vet staticcheck fmt scan tidy clean integration image cdk-test

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

# ---- Integration tests (LocalStack: KMS, DynamoDB) ---------------------
COMPOSE ?= $(shell command -v podman >/dev/null && echo podman compose || echo docker compose)

integration:
	$(COMPOSE) -f integration/docker-compose.yml up -d
	@for i in $$(seq 1 90); do curl -sf http://127.0.0.1:4566/_localstack/health >/dev/null && break; sleep 1; done
	SV_IT_LOCALSTACK=http://127.0.0.1:4566 $(GO) test -count=1 -tags integration ./integration/; \
	  status=$$?; $(COMPOSE) -f integration/docker-compose.yml down; exit $$status

# ---- Container image and CDK (README "Deployment") ---------------------
CONTAINER ?= $(shell command -v podman >/dev/null && echo podman || echo docker)

image:
	$(CONTAINER) build --build-arg VERSION=$(VERSION) -t service-vault:$(VERSION) .

cdk-test:
	cd cdk && npm ci && npm run typecheck && npm test
