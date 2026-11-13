## What changes

## Tested

<!-- What was run, where, and the result. Say what was not run. -->

## Vault interface

<!-- Keep this section if the change touches what the service exchanges with
member vaults (handshake, peerwire messages, features, invitations, ballot
documents and bundles, trust roots, the vms/* pin); otherwise delete it.
Rules: vettid.org docs/VAULT-SERVICE-INDEPENDENCE.md (R1-R3). -->

- [ ] **Against the previous vault release:** how this behaves with a member vault on the previous supported release, and on the current one:
- [ ] **Negotiable change:** gated on a feature both sides advertise, with the old behaviour kept while the peer lacks it (R1, R3). No connection is ended or refused, and no peer's state is refused: a peer that lacks the feature is held and shown, not ended.
- [ ] **Downgrade rule:** a feature only chooses a format (never one weaker than the current minimum) or opts in to stricter handling. Nothing here lets a feature or `contract` relax a check that protects the member (R1).
- [ ] **Not negotiable, so service-first or a planned flag day with an owner go** (R1, R3), never gated on a feature:
  - a public document, or a stricter vault check of what the service signs: this release already meets the strictest check of every supported vault release;
  - a new signature suite;
  - rotating Sigstore roots, the timestamp authority or `vote_site_key`;
  - the invitation: the service still issues the oldest supported format.
- [ ] **A `vms/*` pin change** is its own PR, and `docs/SOURCE.md` is regenerated (`go run ./internal/sourcemd -w`).
