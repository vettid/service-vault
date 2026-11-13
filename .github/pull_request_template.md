## What changes

## Tested

<!-- What was run, where, and the result. Say what was not run. -->

## Vault interface

<!-- Keep this section if the change touches what the service exchanges with
member vaults (handshake, peerwire messages, features, invitations, ballot
documents and bundles, trust roots, the vms/* pin); otherwise delete it.
Rules: vettid.org docs/VAULT-SERVICE-INDEPENDENCE.md (R1-R3). -->

- [ ] **Against the previous vault release:** how this behaves with a member vault on the previous supported release, and on the current one:
- [ ] **Negotiable change:** gated on a feature both sides advertise, with the old behaviour kept while the peer lacks it (R1, R3). No connection is ended or refused on a version alone.
- [ ] **Public documents and what the vault checks of what the service signs** are service-first: this release already meets the strictest check of every supported vault release, before the vault tightens it (R1). Not gated on a feature.
- [ ] **A `vms/*` pin change** is its own PR, and `docs/SOURCE.md` is regenerated (`go run ./internal/sourcemd -w`).
