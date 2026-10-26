# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

The VettID service vault (`service-vault`): a Go daemon an application
runs to connect with VettID members. It is a VMS v2 peer on the relay —
to a member's vault it is an ordinary `connection` (VAULT-MESSAGING §6.4)
— and it serves the application a private HTTPS API and signed webhooks.
It runs as one container with no enclave; it holds the service's keys,
connection records and contracts, never member secrets.

The plan, its decisions and its phases are in
[MEMBER-SERVICE-PLAN](https://github.com/vettid/member-service/blob/main/docs/MEMBER-SERVICE-PLAN.md)
(§3, §7.2, §8, §10); read it before starting a PR and do not reopen its
decisions. The retired NATS prototype in `vettid/vettid-service-vault` is
not reused.

## Build and test

```sh
go build -o bin/service-vault ./cmd/service-vault
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go test -race -count=1 ./...
```

## Conventions

- Standard library first: `flag`, `log/slog`, `net/http`. No frameworks.
- VMS v2 comes from `github.com/vettid/vettid-vault` `vms/*` and relay
  access from `github.com/vettid/vettid-relay/relayclient`, at the
  commits pinned in `go.mod` and recorded in `docs/SOURCE.md`. What they
  lack is added upstream, not forked here.
- Package layout per MEMBER-SERVICE-PLAN §7.2. Only `internal/keystore`
  touches private keys at rest; only `internal/peer` touches relay
  mailboxes and VMS sessions.
- Logs carry ids, types, sizes and error codes, never message bodies,
  emails, match codes, tokens or keys.
- Emails are stored only as an HMAC under a server-side pepper; lookups
  answer uniformly whether or not the email is known.

## Coordination rules

1. **Scope.** Work in this repository. Read vettid-vault, vettid-relay,
   vettid-agent and vettid.org; open PRs there only when the owner
   assigns them.
2. **Small PRs**, one per row of MEMBER-SERVICE-PLAN §10, each with its
   tests passing locally before it is pushed; titles name the row
   (`1.4: email sign-in`). The owner merges; the agent never merges.
3. **Public text** (commits, PRs, issues, code comments) never mentions
   reviews, finding ids, private files or local paths outside the
   repository. Cite specifications by document and section.
4. **Spec questions go to the owner** as a vettid.org issue, never as an
   edit to a specification. Where the spec is silent, choose, mark it
   "(chosen; not in the spec)" in the PR, and ask.
5. **No secrets in the repository**: no keys, tokens, API keys, peppers
   or member data; test keys only from fixed, public test seeds;
   gitleaks runs in CI.
6. **Vectors** copied from vettid-vault are stop-and-report items: never
   edit or skip one that stops matching.
7. **Commit trailers and PR bodies**: as the harness provides them; no
   other attribution.
