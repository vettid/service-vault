GO      ?= go
BIN     ?= bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: all build svctl test race lint vet staticcheck fmt scan tidy clean integration image cdk-test devstack-up devstack-test verify-image

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/service-vault ./cmd/service-vault

# svctl: the operator CLI over the SDK (README "svctl").
svctl:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/svctl ./cmd/svctl

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
	test -z "$$(gofmt -l $$(git ls-files '*.go'))" || { gofmt -l $$(git ls-files '*.go'); exit 1; }

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

# ---- End to end against a real member vault (not in CI) ----------------
# vettid-vault's dev stack at the commit pinned in go.mod (its README,
# "Local dev stack"): about 8 GB of memory, podman or docker compose. Run
# `make devstack-up` in one terminal and `make devstack-test` in another;
# SV_DEVSTACK_DATA picks the stack's data directory (default: the user
# cache directory's vettid-devstack).
VAULT_VERSION = $(shell $(GO) list -m -f '{{.Version}}' github.com/vettid/vettid-vault)

devstack-up:
	$(GO) run -tags devenclave github.com/vettid/vettid-vault/cmd/devstack@$(VAULT_VERSION) $(if $(SV_DEVSTACK_DATA),-data $(SV_DEVSTACK_DATA))

devstack-test:
	$(GO) test -count=1 -tags devstack -timeout 30m -v ./devstack/

# Check an image's signed build provenance before deploying it (README,
# "Verifying an image"): built by this repository's CI from main on a
# GitHub-hosted runner. IMAGE=ghcr.io/vettid/service-vault@sha256:<digest>
verify-image:
	@case "$(IMAGE)" in ghcr.io/vettid/service-vault@sha256:*) ;; *) echo 'IMAGE=ghcr.io/vettid/service-vault@sha256:<digest>' >&2; exit 2;; esac
	gh attestation verify oci://$(IMAGE) --repo vettid/service-vault \
	  --signer-workflow vettid/service-vault/.github/workflows/ci.yml \
	  --source-ref refs/heads/main --deny-self-hosted-runners
