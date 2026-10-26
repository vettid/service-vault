# Pinned sources

The service vault builds on vettid-vault's wire packages (`vms/*`) and
vettid-relay's `relayclient` instead of reimplementing the protocol
(MEMBER-SERVICE-PLAN §7.2). They are pinned to one commit; a change to a
pin is its own PR, with any vectors copied from the new commit and their
tests passing. `deps_test.go` fails to compile if a pinned package moves
or its exported API changes shape.

| Module | Version in `go.mod` | Commit | Date (UTC) |
|---|---|---|---|
| `github.com/vettid/vettid-vault` | `v0.0.0-20261026162438-7eae0a6d36b7` | `7eae0a6d36b722b1ebdce1704aa1d38499ecbd4b` (`main`, #150) | 2026-10-26 16:24:38 |
| `github.com/vettid/vettid-relay` (the version vettid-vault requires) | `v0.0.0-20261015153542-cc3ce892f9dc` | `cc3ce892f9dcb990e9e9752f19c3e0e296dd12b9` (`main`, RELAY-PROTOCOL 0.9.4 byte budgets, #14) | 2026-10-15 15:35:42 |

Other direct dependencies are ordinary tagged releases chosen in the PR
that adds them, with their licence checked for AGPL-3.0 compatibility:

| Module | Version | Licence | Used by |
|---|---|---|---|
| `github.com/aws/aws-sdk-go-v2` (`service/kms`) | `kms` v1.61.1 (the version vettid-vault uses) | Apache-2.0 | `internal/keystore` (KMS envelope) |
