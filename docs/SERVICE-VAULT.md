# Service Vault — Architecture

**Status:** outline (Phase 0). Sections fill in as the phases of
MEMBER-SERVICE-PLAN §10 land.

## 1. Role

Three parties: the **member** (VettID app and the member's vault in a
Nitro Enclave), the **service vault** (this daemon), and the
**application** (for example member.vettid.org). The application calls
the service vault through the SDK over a private HTTPS endpoint; the
service vault calls the application back with signed webhooks. The
service vault reaches members only through their vaults over the relay.

## 2. Trust model

- Member secrets live only in the member's vault. Anything signed with
  the member's credential key — sign-in, contract acceptance,
  completions, the voting key — is signed there; the phone approves.
- The service vault holds the service's own keys (envelope-encrypted
  under KMS, readable by the operator at runtime, as any service's own
  keys are), connection records, contracts and its audit log. It runs in
  a plain container for that reason.
- A service cannot push to a phone. Requests go to the member's vault,
  which turns them into feed events on the member's own terms.

## 3. Components

| Package | Responsibility |
|---|---|
| `internal/peer` | Relay mailbox, suite-2 handshake, connection tokens, `connection.removed` |
| `internal/connect` | Invites, connection lifecycle, email index |
| `internal/signin` | Uniform-response lookup, `connection.authenticate` challenges, match codes |
| `internal/approval` | Admin approvals, configurable m-of-n |
| `internal/contract` | Offers, acceptance, completions (Phase 3) |
| `internal/ballot` | Certification, ballot box, publication (Phase 5) |
| `internal/keystore` | KMS envelope; Ed25519, suite-2 KEM, RSA for blind signing |
| `internal/store` | DynamoDB: connections, pending challenges, audit |
| `internal/webhook` | HMAC over `timestamp.body`, retries |
| `internal/api` | Private HTTPS API, API keys |

## 4. Deployment

One ARM64 Fargate task in public subnets with egress-only security
groups, no NAT Gateway, the DynamoDB gateway endpoint only, Spot,
Container Insights off; the API is reachable only from the application.

## 5. The peer (`internal/peer`)

To a member's vault the service vault is an ordinary connection
(VAULT-MESSAGING §1.1, §6.4). `internal/peer` mirrors the member vault's
behaviour as a connection's **inviter**; it never accepts invitations,
never answers challenges and never rotates its identity.

- **Invitations** are in person only: 10 minutes, `remote: false`
  (§6.4). The bundle's hint name and the shared profile's core are the
  service's names (`Profile`: first and last name; for vettid.org
  "VettID" / "Member Service").
- **Connecting.** A valid `hs.init` on a live invitation is answered at
  once with `hs.resp` and a request token (§6.4, §7.1). When `hs.fin`
  checks out the SAS is known: the service approves its own side at
  once (auto-approval is allowed for in-person invitations; the member
  always approves) and tells the application (`connection.pending` with
  the SAS), which shows it so the member can compare it on the phone.
  The member's `connection.approved` activates the connection; the
  member's vault then gets `profile.update` with the service's names and
  identity key (§10.8), and the application `connection.added`.
- **Sessions** use the vault-to-vault policy (24 h or 10,000 messages,
  §6.5). The peer answers the member vault's rekeys and starts its own
  when its epoch reaches the limit; crossing rekeys are settled by `th1`.
  It answers reconnects (§6.6) without identity rotations.
- **Tokens** (§7.1, §7.2): standing and reconnect tokens are re-minted
  below 10 and 60 days and sent as `relay.token.issued`;
  `relay.token.refresh` is answered with the hourly / daily `too_soon`
  bounds; the peer asks for a fresh standing token below 3 days and after
  `token_expired`. Removal and every request that ends unapproved
  denylist the tokens issued for it by `jti` (§7.4).
- **Sign-in** is `connection.authenticate.challenge` (§10.4) with the
  match code in its context and an inner `exp`; a signed response is
  verified against the challenge and the member's credential key pinned
  at the first success (a later key that no rotation chain reaches is
  reported as `key_changed`).
- **Delivery** (§8): each collected message is deduplicated (relay
  `msg_id` and inner `id`, 16 days), handled, and its changes written to
  the store before it is acked; deposits wait in a persisted outbox,
  kept in order per mailbox. Events for the application are persisted
  with the changes that cause them and delivered at least once.
- **State** lives in a `Store` of records (connections with their
  keyrings, invitations, handshakes and requests in flight, the `jti`
  registry, the outbox, challenges, events, dedupe markers). Every record
  is written on the version it was read at; a conflict means a second
  writer and stops the peer.
