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
| `vote` | The ballot protocol's encodings, documents, Merkle trees and checks, with no messaging dependency: shared with votes.vettid.org |
| `internal/ballot` | The ballot box, proposals, counting and publication (Phase 5) |
| `anchor` | Anchoring documents in Rekor (Phase 5); public, for the votes repository's signer function (key protection) |
| `internal/keystore` | KMS envelope; Ed25519, suite-2 KEM, the P-256 anchor key |
| `internal/store` | DynamoDB: connections, pending challenges, audit |
| `internal/webhook` | HMAC over `timestamp.body`; the outbox: in order, retried with backoff, dropped at 24 h |
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
- **Contract** (§10.8, 0.90.10; VAULT-SERVICE-CONTRACT §1). Every
  `profile.update` the service sends carries `contract: "1.0"`, the
  contract version this release implements. The service keeps the value
  it last sent to each connection; at a start under a release whose value
  differs (or that never sent one), each active connection gets an update
  with its next `version`, retried at the next housekeeping until it is
  queued. That version is at least the clock's Unix seconds, so one sent
  after a rollback or a restore set the record back is still higher than
  any the member's vault applied. Once queued it counts as sent: if the
  outbox later gives it up (the window passed, the connection ended or
  went stale), it is not sent again, as with the update at activation.
  From a member's `profile.update` it keeps the contract claimed
  (a string of the §10.8 form; any other value counts as none and is
  audited `profile_contract_malformed`, and the update is still applied).
  The value is informational: nothing selects behavior or holds a
  connection by it. `vote` and `approval_document` are judged from the
  last `profile.update` applied only, never from a message's inner
  `features`.
- **Sessions** use the vault-to-vault policy (24 h or 10,000 messages,
  §6.5). The peer answers the member vault's rekeys and starts its own
  when its epoch reaches the limit; crossing rekeys are settled by `th1`.
  It answers a member's reconnect (§6.6) without identity rotations,
  only when `ctx` names its last epoch, refuses a `th1` it answered
  before (marks kept 16 days + 5 minutes), and changes nothing (tokens,
  chain, active or stale) until `sig_I` verifies at `hs.fin`. It starts
  reconnects only after a restore (§6.6 "After a restore", 0.72.0):
  `table restore` leaves a marker (`run#restored`), and the next start
  reconnects every active or stale connection on the reconnect token it
  holds, naming its last epoch, before any rekey, then deletes the
  marker. The member's vault accepts that older epoch from its history
  and answers with its rotations since it, which the service follows.
  While a reconnect is open nothing is sent on the connection; a restart
  keeps the stored initiator (an unconfirmed deposit is resent with the
  same bytes), and a new `hs.init` goes out only when that state was
  lost, at most 3 per restore (the counters restart with each restore);
  after 7 days it fails and the connection is stale. Crossing reconnects
  (0.72.1): a member's reconnect arriving meanwhile (its `ctx` matching
  ours) is answered and ours yields (no `hs.fin`; its tokens revoked);
  if the member's `hs.fin` doesn't come within an hour (chosen; not in
  the spec), a new try starts. The stored initiator keeps the member's
  followed chain (vettid-vault #159), so the member's answer may start
  with links already followed. The service never rotates its identity.
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

## 6. Email binding and sign-in (`internal/service`, `internal/signin`)

- **Binding** (MEMBER-SERVICE-PLAN §4.1 step 4). Only a verified email
  is bound: `POST /v1/invites` requires `email_verified`, which the
  application sends as `true` only after verifying, with a one-time code
  it emails, that the member controls the address (the service vault
  cannot send email). With `false` the invitation carries no email and
  its connection is never bound. A verified invitation carries
  the email's index key (HMAC under the pepper, `internal/connect`). On
  `connection.added` the key is bound to the connection with a write
  conditional on no binding existing; the first active connection keeps
  it, a later one with the same email is not bound
  (`email_bound: false`), and removing the bound connection frees it for
  the next. Creating an invitation answers the same either way.
- **Starting a sign-in** (§4.2). Under a per-email lock, the start is
  counted against the rate limits. If it is within the limits, the
  email's pending sign-in (if any) is superseded — it reads `expired`
  and its challenge is cancelled on the service's side, so a later
  answer to it matches nothing — and, if the email is bound to an active
  connection, the challenge goes out. A start over a limit makes its own
  sign-in, which only expires, and leaves the email's pending sign-in
  alone: otherwise anyone who knows a member's email could cancel the
  member's sign-in by starting more (chosen; not in the spec). All of
  this happens inside the uniform response floor, and the answer is the
  same in every case.
- **Rate limits.** Fixed-window counters per email key and per source
  key (the source the application passes, HMAC'd under the pepper with
  its own label), one DynamoDB item per window updated with an atomic
  `ADD` and a TTL past the window. Defaults 5/15 min and 20/24 h per
  email, 20/15 min per source (configurable). Over a limit the sign-in
  sends no challenge, supersedes nothing and expires; only a count is
  logged.
- **Outcomes.** An approved, denied or expired challenge settles a
  pending sign-in and sends its webhook (`key_changed` with
  `signin.approved`); an outcome for a sign-in that was superseded in the
  meantime is dropped without a webhook.

## 7. Admin approvals (`internal/approval`)

MEMBER-SERVICE-PLAN §4.5 and §5.2; the operator's view is in the README,
"Admin approvals".

- **Admin set.** Connection ids in one record. The first admin comes from
  `SV_ADMIN_BOOTSTRAP_EMAIL` while the set is empty: at `connection.added`
  for the connection that binds that email (only a verified email binds),
  or at a periodic tick for one that is bound and active already. The
  bootstrap is one-shot: a bootstrap-state record (`admin_boot`) is
  written with the first admin, and from then on the setting is ignored,
  even if the set empties. A store with a non-empty set and no such
  record is marked at the start. `service-vault admin bootstrap -email E`
  (the operator, with the daemon's environment) arms a new one-shot
  bootstrap for E in that record, only while the set is empty, and
  audits it without the email. Changing the set is an approval
  (`admin_set.add`, `admin_set.remove`) applied by the service vault; a
  removed connection leaves the set, also one a new connection replaces
  (it comes back only by approval or bootstrap), and a removal that
  leaves fewer than m logs ERROR `alarm: admins_short`; the set never
  becomes empty by approval.
- **Creating an approval.** The action, summary and payload are checked;
  the payload is put in RFC 8785 canonical form and
  `action_hash = SHA-256(JCS({action, payload, summary}))`. m (the
  configured threshold) must not exceed the admins there are. The
  approval records m and the admins asked, and a
  `connection.authenticate.challenge` whose context names the action and
  the first 16 hex digits of the hash, after a label the service sets by
  action (`New vote:`, `Extend vote:`, `Add admin:`, `Remove admin:`,
  `Contract template:`, `Push assignment:`; for a vote and for `admin_set.*`
  the summary is the service's, built from the payload and the connection's
  self-declared name, activation date and identity-key fingerprint it
  holds), goes to each of them
  (10-minute inner `exp`); the service name is at most 32 bytes, and a
  summary built from a payload is shown whole or refused, never cut. Request, record and audit entry are written together.
  For `proposal.create` and `vote.extend` the application gives no
  summary: the service builds it from the payload (binding or advisory,
  window, quorum, choices and title; for an extension the proposal and
  the new close), and refuses a payload that is not the canonical full
  form of the input or whose text it cannot show whole.
- **Using an approval** (`Manager.Consume`; `internal/ballot` calls it).
  `POST /v1/proposals` and `/extend` need an approval of the exact
  input, used once: under the manager's lock it must be approved (the
  signatures of the admins in the set now still meet the threshold now),
  for
  that action (`proposal.create`; `vote.extend` with the proposal id in
  its payload), not past its expiry, and its payload must equal the
  canonical form of the input byte for byte. The use is one write: an
  `apv_used` record with a condition that it does not exist, and an
  `approval.consumed` audit entry. The order is check, consume, execute:
  refusals of the input come first and leave the approval usable; a
  failure after the use (storing, publishing, sending) leaves it used and
  the admins approve again (fail closed). For `vote.extend` the order is: refusals, sign, store the signed extension as pending on the proposal (conditional on its version), use the approval (refused: the pending one is cleared and the approval is unused), publish, mark in effect (BALLOT-PROTOCOL §10.2): a failure after the store leaves it pending, and the same request again publishes the same bytes repeating the use of the same approval (`Consume` with `Use.Retry` accepts the repeat of the same proposal and number, never a second use); the RFC 3161 time of the bundle the service anchored (kept in the record store, never the site's copy), not the clock, decides whether it applies; it is verified first (message imprint, and the TSA's signature chaining to the root pinned in the release for the Sigstore instance). The site also refuses a first upload by its own clock. `/close` reconciles the extensions with the site's files before it counts (a pending one is dropped only after an upload of its bytes is refused `too_late`) and refuses (`site_mismatch`) while they differ in a way that can't be resolved (a probe answered 422 with a code other than `too_late` fails every close until the site accepts the document or the pending extension is removed by hand); it also repeats an upload whose index update the site reported as failed. `/close` stays API-key only: it
  counts a vote that has already closed.
- **Answers** arrive as the peer's challenge outcomes, now carrying the
  evidence (context, credential key, signature, `signed_at`). Each answer
  is audited with it, together with a marker of the peer event, so a
  redelivered event changes nothing. An answer counts when it is to the
  admin's outstanding challenge, the admin is still in the set and has
  not answered, and the approval is pending and not past its time; a bad
  signature never counts. m approvals settle it `approved`; when the
  approvals plus the admins who can still answer fall below m, `denied`.
  Settling cancels the other admins' challenges on the service's side.
  With `SV_LONG_APPROVAL_CHALLENGES` a challenge's `exp` is the approval's
  own expiry, at least 10 minutes and at most 24 hours after it is sent
  (VAULT-MESSAGING 0.82.0 §10.4), and a reminder goes only to admins
  holding no live challenge. The service cannot see a member vault clamp a
  challenge (the vault drops it silently), which is why the flag is off by
  default and why `internal/peer` sends at most 2 long challenges per
  connection at a time, as a member vault keeps (a third goes with 10
  minutes). Otherwise a challenge lasts 10 minutes, and a reminder challenges every admin who has not answered. When a
  challenge expires unanswered before the approval's own expiry and the
  approval is still pending, the service logs INFO `approval challenge expired`
  (ids only), queues the `approval.challenge_expired` webhook with the
  save, and the approval's status lists the admin in `remind_needed`
  (admins asked, not answered, holding no live challenge) until a
  reminder sends a new one. An admin at the ask limit (approval
  challenges still counting, against the member vault's ask gate of 5
  per 24 hours) is skipped by every send and
  shows in `remind_needed`, and in an optional `ask_budget` list
  (`[{connection_id, next_ask_at}]`, on the create, remind and status
  answers) with when it can be asked again; creating an approval answers `ask_budget`
  (409) when fewer admins than the threshold can be asked, and a plain
  reminder when none can, before anything is sent or withdrawn. For
  every action but `admin.repin`, `admin_set.add` and `admin_set.remove`,
  the limit is 4: the fifth is kept for those repair actions, so a burst
  of ordinary approvals from a runaway or buggy application cannot leave
  the admins unaskable for a change to the admin set. It does not stop a
  holder of the API key who means harm: repair approvals of their own
  spend the fifth. A declined approval challenge starts no cooldown in a
  member vault from VAULT-MESSAGING 0.83.10 (an older one still starts a
  7-day cooldown, §10.4.1). Creating an approval is also limited per
  group of actions (the repair ones, and all the others), by default 2
  per hour and 4 per 24 hours each, in fixed windows
  (`SV_APPROVAL_LIMITS`): past it, `rate_limited` (429), counted once
  the request passes every other check, the ask budget included.
- **Periodic work** (every 15 s and at once after a change): bootstrap,
  expiry (`expired`), re-checking open approvals after admins left, and
  webhook delivery. Webhooks are written to an outbox in the same write
  as the change that causes them and delivered in order, at least once.
- **Audit log.** One record per entry under its own partition, ids
  increasing in the order written (ULIDs, made monotonic in process),
  written with a condition that the entry does not exist and never
  updated or deleted; `GET /v1/audit` reads it with one Query per page.
- **Trust.** An approval is as strong as the admins' credential keys and
  the member vault's own checks: the service vault verifies each
  signature over the challenge it sent and pins the key per connection
  (a different key is reported as `key_changed`). The governance
  actions (`admin_set.add`, `admin_set.remove`, `admin.repin`,
  `proposal.create`, `vote.extend`, `contract_template.change`) count an
  approval only if it is signed with the admin's *governance key*: the
  credential key at the time the connection became an admin, moved on by a
  rotation chain from it and otherwise only by `admin.repin`, which the
  other admins approve (m of them, or all the other admins if fewer, never fewer than one: owner decision of 2026-11-02; never the admin re-pinned; a sole admin
  has none to confirm it: the connection is removed and a bootstrap armed).
  Before approving, the other admins ask the admin out of band (by phone or
  in person) "did you recover or replace your vault's keys at <the time in
  the summary>?" and approve only on a clear yes; a member's app will show
  its own credential-key fingerprint in a later release (the
  `vettid/vms/2/ck-fp` label will then be specified in VAULT-MESSAGING). A
  stolen copy holding the old key can rotate the governance key away and
  lock the real admin out, who then needs a re-pin. Governance keys of
  existing admins are pinned from the audit log's earliest signed approval
  (`gov_key.migrated`), a new admin's from the key their `admin_set.add`
  summary showed, the first admin's only after the operator confirms its
  fingerprint. Any other key is recorded with `counted: false`
  and audited with reason `key_changed` or `not_repinned`; it does not
  count toward the threshold, `Consume` does not count it and nothing is
  applied on it. Ordinary sign-ins and votes follow the credential key as
  before. `assignment.push` is not governance and counts as before. The
  ask gate of VAULT-MESSAGING §10.4.1 applies: a suppressed challenge
  reads as a denial (owner decision of 2026-11-04). The service cannot
  tell a person's denial from their vault's automatic one (a muted or
  paused service), so `svctl` shows the admins who did not approve as
  `not_approved_by`, never "declined by", and an admin who mutes the
  service abstains from its approvals.
