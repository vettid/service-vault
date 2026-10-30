# Pinned sources

The service vault builds on vettid-vault's wire packages (`vms/*`) and
vettid-relay's `relayclient` instead of reimplementing the protocol
(MEMBER-SERVICE-PLAN §7.2). They are pinned to one commit; a change to a
pin is its own PR, with any vectors copied from the new commit and their
tests passing. `deps_test.go` fails to compile if a pinned package moves
or its exported API changes shape.

| Module | Version in `go.mod` | Commit | Date (UTC) |
|---|---|---|---|
| `github.com/vettid/vettid-vault` | `v0.0.0-20261030182642-1115d2708edd` | `1115d2708edd05f99702ca47203bc9c2dfe5ebfc` (`feat/authn-withdraw-0.80`, vettid-vault #168, not yet merged: re-pin to `main` once it is; `peerwire` `connection.authenticate.withdraw`) | 2026-10-30 18:26:42 |
| `github.com/vettid/vettid-relay` (newer than vettid-vault requires: `relayclient` token jtis from crypto/rand) | `v0.0.0-20261027144202-528df9b0bf76` | `528df9b0bf769608ec0172571ff89301d0d4e237` (`main`, #19) | 2026-10-27 14:42:02 |

Other direct dependencies are ordinary tagged releases chosen in the PR
that adds them, with their licence checked for AGPL-3.0 compatibility:

| Module | Version | Licence | Used by |
|---|---|---|---|
| `github.com/aws/aws-sdk-go-v2` (`service/kms`) | `kms` v1.62.1 | Apache-2.0 | `internal/keystore` (KMS envelope) |
| `github.com/aws/aws-sdk-go-v2` (`service/dynamodb`) | `dynamodb` v1.72.2 | Apache-2.0 | `internal/store` (keystore blobs, the peer's records) |
| `github.com/aws/aws-sdk-go-v2` (`service/ssm`) | `ssm` v1.81.1 | Apache-2.0 | `cmd/service-vault` (publishes the TLS key pin), `cmd/svctl` (reads it) |
| `filippo.io/edwards25519` | v1.1.0 | BSD-3-Clause | `vote` (BALLOT-PROTOCOL §2's canonical-encoding and small-order checks, which `crypto/ed25519` doesn't make) |
| `rsc.io/qr` | v0.2.0 | BSD-3-Clause | `cmd/svctl` (the invitation's QR code in the terminal; pure Go, its cgo `libqrencode` subpackage is not used) |
