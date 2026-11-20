# syntax=docker.io/docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# VettID service vault: small, non-root, static image (MEMBER-SERVICE-PLAN §9).
#   docker build -t service-vault .
#   docker buildx build --platform linux/amd64,linux/arm64 -t service-vault .
# Binary path is stable: /service-vault.

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=""
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -buildid= -X main.version=${VERSION}" -o /out/service-vault ./cmd/service-vault \
 && test -s /etc/ssl/certs/ca-certificates.crt

# scratch rather than distroless: every base image comes from VettID's
# mirror in CI, and the mirror carries the Go builder only. The binary is
# static; it needs the CA bundle (relay, AWS APIs, webhooks) and nothing else.
FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/service-vault /service-vault
USER 65532:65532
ENV SV_LISTEN=:8080
EXPOSE 8080
ENTRYPOINT ["/service-vault"]
CMD ["serve"]
