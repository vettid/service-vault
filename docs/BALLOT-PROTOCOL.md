# Ballot Protocol

**Status:** 0.9.0 (2026-10-29), for review before more ballot code
(MEMBER-SERVICE-PLAN §10, item 5.0). The plan-level design is
MEMBER-SERVICE-PLAN §8. This document marks two kinds of choice, all
listed in §12 for the owner:
- **(chosen; differs from the plan)**: where it departs from the plan.
- **(chosen; not in the spec)**: what the plan and the specifications
  leave open.

The message types here (§4) are not yet in VAULT-MESSAGING. Today it
lets a service connection send only `connection.authenticate.challenge`
(with a known `purpose`) and the upkeep and profile types, and a
member's vault send a service only `connection.authenticate.response`
and `.rotated`, upkeep and profile (VAULT-MESSAGING §6.4 "Service
connections", 0.69.0). Item 5.1 registers the vote types there, with
wire vectors; this document is its source. Nothing here needs a relay
change.

**In one paragraph.** The service publishes a signed proposal and
anchors it in a public log. Each eligible member gets a random tag for
that proposal. A member votes once: their vault signs the ballot with a
key made for that proposal only, sends it over the member's ordinary
connection, and gets a signed receipt. At the close the service
publishes every tag with its ballot or none, and the tally. Anyone can
check the signatures, the one-ballot-per-tag rule and the tally; each
member's vault checks its own row. The public sees tags and keys, never
names, emails or connections. The service knows who voted how, and keeps
that for its records.

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only an eligible member (§3.2) can cast a ballot that counts. |
| One vote | One ballot per member per proposal. It is final: there is no changing it. |
| Pseudonymity | The published results name no member: no name, email, connection or VettID key, and nothing that links one member's ballots across proposals. **Not secret:** the service vault, and through it the organisation, knows how each member voted, and keeps that record (owner decision 2026-10-29). |
| Transparency | Every proposal, extension and result is signed, published on votes.vettid.org and anchored in Rekor (§3.3), so everyone sees the same documents, and a changed document is detectable. |
| Verifiability | Anyone can check every ballot's signature, that no tag votes twice, that there are no more ballots than eligible members, and the tally (§8.4). Each member's vault checks that its own row is what it sent, or "didn't vote" if it didn't (§8.3), and holds a signed receipt for its ballot. |
| Availability | No one but the member can stop an eligible member from voting, except the service itself; against the service the protocol detects rather than prevents (§10). |
| Coercion resistance, receipt-freeness | Out of scope (owner decision). |

## 2. Notation and primitives

- `‖` is concatenation. `u16` and `u64` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- **Labels** follow the VMS convention (VAULT-MESSAGING §4.1): ASCII
  strings embedding the version, `vettid/vote/1/...`. **(chosen;
  differs from the plan:** the plan's `"vettid-vote-v1"` follows
  vettid-dev.)
- **Signatures:** `Sign(sk, label, m)` is `suite.Sign` from vettid-vault
  `vms/suite`, Ed25519 over `label ‖ 0x00 ‖ m`. Every signature the
  service identity key makes, in VMS and here, is over a label-prefixed
  string, so the two can't be confused. Hashed strings that start with
  a label have the `0x00` written out.
- **Ed25519 verification,** by every verifier (the service vault, the
  member vault, observers and the site), is exactly:
  1. `A` (the public key) and `R` are 32 bytes whose `y` is below p, and
     not `x = 0` with the sign bit set;
  2. `[8]A` is not the identity (no small-order key);
  3. `S < L`;
  4. `[S]B = R + [k]A`, cofactorless, with `k = SHA-512(R ‖ A ‖ m) mod L`.

  Go's `ed25519.Verify` does steps 3 and 4, and Go's point decoding
  accepts a non-canonical `y`, so Go code makes steps 1 and 2 itself.
  Libraries in the apps are checked against §11's vectors.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
- **Documents** (the proposal, an extension, the results, the service
  list; §8.5) are JCS (RFC 8785). A verifier parses strictly
  (VAULT-MESSAGING §5.3: no duplicate names), re-serializes per RFC 8785
  and refuses the document unless the bytes are identical. Each is
  signed with a detached signature over a string containing
  `H(document bytes)`. Times in them are Unix seconds; binary values
  are standard base64 with padding. **(chosen; not in the spec.)**
- **Message bodies** follow VAULT-MESSAGING §5.3; a document travels in
  a body as the base64 of its bytes.
- **Sorting** of tags and keys is by their raw bytes.
- **The signing key:** the service identity key that signs a proposal
  signs every document, receipt and refusal of it. The service starts no
  `identity.rotate` between a proposal's creation and its results.
- **Anchoring** uses ECDSA P-256 with SHA-256 under the service's anchor
  key (§3.3): what Rekor's `hashedrekord` and the standard Sigstore
  tools verify.

## 3. Proposal

### 3.1 Contents

The proposal is a document (§8.5).

| Field | Meaning |
|---|---|
| `proposal_id` | A ULID. |
| `service` | The service identity key that signs it. |
| `title`, `text` | UTF-8; `title` ≤ 200 bytes, `text` ≤ 16 KiB. |
| `choices` | 3–17 entries `{id, label}`, in display order, with `id` matching `[a-z0-9-]{1,32}` and unique: at least two real choices, and `abstain`, reserved and always present, for a member who wants to be counted without choosing. |
| `quorum` | The quorum rule, as text, and the number of ballots it needs. `abstain` counts toward it. |
| `binding` | Whether the organisation treats the result as binding. The protocol is the same either way. |
| `record_at` | The roster snapshot, at or before creation (§3.2). |
| `opens_at`, `closes_at` | The voting window: a ballot counts if the relay received it in `[opens_at, closes_at)`. At most 30 days. |
| `eligible`, `record_root` | The number of eligible members and the Merkle root of their tags (§3.2). |
| `outage_rule` | The rule of §10.2, as text. |

- **Signature:** `proposal_sig = Sign(service IK, "vettid/vote/1/proposal", H(proposal_bytes))`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds every ballot to
  this one proposal.

### 3.2 Eligible members and tags

- **Eligible members** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended, and with
  a vault that advertised the vote feature (how it advertises is item
  5.1's). One connection is one member, so a person holding several
  VettID accounts is several members, which the organisation sees in its
  own roster.
- **Tags:** for each eligible member the service draws a 32-byte random
  `record_secret`. The member's tag is
  `record_tag = H("vettid/vote/1/record" ‖ 0x00 ‖ proposal_id ‖ record_secret)`.
  `record_root` is the RFC 6962 root (§8.2) over the tags, sorted, and
  `eligible` their number.
- **Delivery:** each member receives, in `vote.proposal` (§4.1), their
  `record_secret` and an inclusion proof of their tag. The vault checks
  the proof at once against `record_root` (RFC 9162 §2.1.3.2). The
  secret lets the member show later, to anyone, that a tag is theirs.
- Tags are new for every proposal, so nothing links a member's rows
  across proposals.

### 3.3 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public, write-once store run by VettID (its
design: vettid/votes, docs/VOTES-SITE.md).

- **The service list** (§8.5), signed by the site and anchored under the
  site's key (pinned in the vault's release config), names each
  registered service, its identity keys and its anchor keys. VettID
  maintains it; a service is added by the owner. Each version names the
  hash of the previous one and keeps all its entries. A vault accepts a
  proposal's `service` only if it is its own connection's identity key
  (current, or a past one learned through `identity.rotate`); the list
  only adds which anchor keys that service uses.
- **The anchor key:** each service has one long-lived ECDSA P-256 key,
  sealed in its keystore, certified by its identity key:
  `anchor_cert = Sign(service IK, "vettid/vote/1/anchor-key", H(anchor_key SPKI DER))`.
- **Documents,** uploaded in this order:
  1. the proposal, before it is sent to any member;
  2. any extensions, before the `closes_at` they extend (§10.2);
  3. the results (§7), after `closes_at`.
- **The anchor:** before uploading, the service anchors each document in
  Rekor: a `hashedrekord` entry with `H(document bytes)` and an ECDSA
  signature over the document under its anchor key. The Sigstore bundle
  goes up with the document and with the message that carries it to
  vaults (§8.5 "Rekor profile").
- **The site checks** the service is listed, the signatures, the exact
  JCS bytes, the bundle under a listed anchor key, and the order above.
- **Write-once:** each document has one path; the site accepts the same
  bytes again, refuses different bytes, and never changes or removes a
  document.
- **Discovery:** the site keeps an index of proposals open or closed in
  the last 30 days. The app fetches it, with no session, on a fixed
  hourly schedule, and hands the vault the entries of its services.

## 4. Messages

Session-mode messages on the service connection (VAULT-MESSAGING §5.3).
Each is answered with a response that names it (`re`). A vault without
the vote feature answers `unsupported_type`, which today's rules would
instead drop and audit; that needs the §6.4 change of item 5.1.

### 4.1 From the service

| Type | Body | When |
|---|---|---|
| `vote.proposal` | `{proposal, proposal_sig, bundle, record_secret, record_proof}` | To every eligible member, once the proposal is published. `record_proof` is `{index, tree_size, path}` (§8.5). |
| `vote.extended` | `{proposal_id, extension, extension_sig, bundle}` | To every eligible member, once an extension is published (§10.2). |
| `vote.closed` | `{proposal_id, results_hash}` | To every eligible member, once the results are published. |

- **The vault keeps** a proposal whose signature verifies under its
  connection's identity key and whose bundle verifies under that
  service's listed anchor key. A second, different proposal under the
  same `proposal_id` is kept as evidence and not used.

### 4.2 From the member's vault

| Type | Body | Answer |
|---|---|---|
| `vote.cast` | `{proposal_id, record_tag, vk, choice_id, ballot_sig}` (§5) | `{proposal_id, accepted_ms, receipt_sig}`, or a refusal |
| `vote.status` | `{proposal_id}` | `{proposal_id, ballot?, accepted_ms?, receipt_sig?}`: the ballot the service holds for this connection, if any |
| `vote.request` | `{proposal_id}` | `vote.proposal` as the response, or a refusal |

**Refusals** are signed, so a member can show them to anyone:
`refusal_sig = Sign(service IK, "vettid/vote/1/refusal", lp(proposal_id) ‖ u64(now_ms) ‖ lp(record_tag) ‖ lp(type) ‖ lp(code))`,
in the error body as `{refusal_sig, now_ms}`, with `record_tag` empty
when the connection has none. A vault treats an unsigned refusal as no
answer. The codes:

| Code | For | Meaning |
|---|---|---|
| `not_eligible` | `vote.cast`, `vote.request` | The connection has no tag for this proposal. |
| `not_open`, `closed` | `vote.cast` | Outside the window. |
| `already_voted` | `vote.cast` | A different ballot is already recorded for this tag; the body also carries that ballot and its receipt. |
| `bad_ballot` | `vote.cast` | The tag isn't the connection's, the choice isn't the proposal's, or the signature fails. |
| `unknown_proposal` | `vote.request` | No such proposal. |

## 5. The ballot

- **The voting key:** when the vault keeps a proposal, it makes a fresh
  random Ed25519 key `vk` for it and stores it in its encrypted state.
  It is used for that proposal only.
- **The ballot:**
  - `ballot_msg = proposal_hash ‖ record_tag ‖ lp(choice_id)`;
  - `ballot_sig = Sign(vk, "vettid/vote/1/ballot", ballot_msg)`.
- **Casting:** the member chooses in the app, between `opens_at` and
  `closes_at`. The vault signs only with the member's approval inside
  the credential's unlock window (VAULT-MESSAGING §3.5.3); it is not an
  ask. It stores the ballot before sending it, and sends exactly those
  bytes until it has an answer. After that the app doesn't offer the
  vote again.
  - The app refuses to cast in the last two minutes before `closes_at`,
    by the vault's clock.
- **The receipt:**
  `receipt_sig = Sign(service IK, "vettid/vote/1/receipt", proposal_hash ‖ H(ballot_leaf) ‖ u64(accepted_ms))`,
  where `ballot_leaf` is §8.2's and `accepted_ms` the relay's receipt
  time of the message (§6). The vault verifies and keeps it.
- **After a restore** (the VMS restore event), the vault asks
  `vote.status` for every proposal it holds, and takes the service's
  record of its ballot and receipt. A restored vault with no ballot and
  no record may vote, with a new key.

## 6. What the service does

- **On `vote.cast`,** in order:
  1. the proposal is open: the relay's receipt time of the message (the
     time of its `msg_id`, RELAY-PROTOCOL §6.2) is in
     `[opens_at, closes_at)`, as extended (§10.2), so a ballot queued
     during an outage still counts;
  2. the connection is eligible and `record_tag` is its tag;
  3. `choice_id` is the proposal's and `ballot_sig` verifies under `vk`
     (§2);
  4. **one per tag:** a conditional write stores the ballot only if the
     tag has none. If it has the same ballot, the stored receipt is sent
     again; if it has a different one, the answer is `already_voted`.
  5. It signs the receipt and answers.
- **The record** of each connection's tag and ballot is kept for the
  organisation's records (owner decision 2026-10-29), in the service
  vault's table, sealed like its other records. It is not published.
  The organisation reads it through the service vault's admin API.
- **No running tally:** the service vault exposes no count before
  `closes_at`. That rests on the service being honest; the protocol
  can't stop a service from reading its own table.
- **Removal or suspension during the vote:** a connection removed or
  suspended after `record_at` keeps its tag; whether it may still vote is
  the organisation's rule, stated in the proposal, and the results count
  such members.

## 7. Results

- **At `closes_at`** (as extended), plus the relay's delivery delay
  (the service collects until its mailbox has been empty for 10 minutes
  after `closes_at`), the service builds `results.json` (§8.5):
  - the proposal and any extensions, each with its signature;
  - every tag, sorted, with its ballot `{vk, choice_id, ballot_sig}` or
    `null`;
  - the tally per choice, and the counts: `eligible`, `ballots`, and
    members removed or suspended during the vote.
- **Signature:** `results_sig = Sign(service IK, "vettid/vote/1/results", proposal_hash ‖ H(results_bytes))`.
- **Published** on votes.vettid.org, anchored (§3.3), and announced in
  `vote.closed`.
- Receipt times are not published: with outside knowledge of when a
  member was active, they could narrow down whose row is whose.

## 8. Verification

### 8.1 What the documents bind

Every ballot names the proposal's hash and its tag, so it counts for one
proposal and one tag only. Every tag is in `record_root`, which the
signed proposal fixed before anyone voted.

### 8.2 Merkle trees and the ballot leaf

- RFC 6962 §2.1 with SHA-256; proofs verified per RFC 9162 §2.1.3.2:
  leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`, split
  at the largest power of two below n, the empty tree `H("")`. The
  record leaf is the 32-byte tag, in sorted order.
- **Ballot leaf** (for receipts):
  `ballot_leaf = record_tag ‖ lp(vk) ‖ lp(choice_id) ‖ lp(ballot_sig)`.

### 8.3 What a member's vault checks

At `vote.closed`, and in any case at `closes_at` + 2 h, retrying with
backoff for 7 days (the app runs pending checks whenever it opens):
1. the app fetches the results from votes.vettid.org, whole, with no
   session;
2. `results_sig` holds; the bundle verifies; the proposal and any
   extensions are the ones the vault received; the tags reach
   `record_root`;
3. **its row:** if it voted, its tag carries exactly its `vk`, its
   choice and its `ballot_sig`; if it didn't, its tag carries `null`;
4. the counts and the tally recompute.

A failure is shown to the member with the evidence: the signed proposal,
the receipt or refusals, and the results. The receipt proves the service
accepted a ballot that the results lack or changed; a ballot under a tag
that never voted proves the service voted for the member. The app can
export the evidence; what the organisation does with it is its own
governance.

### 8.4 What an observer checks

From votes.vettid.org alone:
1. every signature holds under the service's identity key, every bundle
   under a listed anchor key, and the service list verifies;
2. the tags are unique, number `eligible` and reach `record_root`;
3. every ballot's `ballot_sig` verifies under its `vk` for
   `ballot_msg(proposal_hash, tag, choice_id)`, and its choice is one of
   the proposal's;
4. `vk`s are unique;
5. `ballots ≤ eligible`, and the tally recomputes;
6. extensions are timestamped (by their Rekor bundles) before the
   `closes_at` they extend, and total at most 24 h.

### 8.5 Schemas

A verifier refuses unknown, missing or mistyped fields. `b64` is
standard base64; `hash` the `b64` of 32 bytes; `sig` the `b64` of 64
bytes; `time` a JSON integer of Unix seconds; `spki` the `b64` of a DER
SubjectPublicKeyInfo.

- **Proposal:** `{v: 1, proposal_id, service: b64, title, text, choices: [{id, label}], quorum: {text, min_ballots: int}, binding: boolean, record_at: time, opens_at: time, closes_at: time, eligible: int, record_root: hash, outage_rule: string}`.
- **Extension:** `{v: 1, proposal_id, n: int (≥ 1), closes_at: time, outage: {from: time, to: time, source: string}}`;
  signature `Sign(IK, "vettid/vote/1/extended", proposal_hash ‖ H(bytes))`.
- **Results:** `{v: 1, proposal_id, proposal: {doc: b64, sig: sig}, extensions: [{doc: b64, sig: sig}], rows: [{record_tag: hash, ballot: {vk: b64, choice_id: string, ballot_sig: sig} | null}], tally: {<choice id>: int}, counts: {eligible: int, ballots: int, removed: int}}`,
  `rows` sorted by `record_tag`, `tally` naming every choice.
- **`record_proof`:** `{index: int, tree_size: int, path: [hash]}`, the
  audit path from the leaf up, with `tree_size = eligible`.
- **Service list:** `{v: 1, version: int, previous: hash, site_anchor_key: spki, services: [{service_id: string, name: string, iks: [b64], anchor_keys: [{key: spki, anchor_cert: sig, ik: b64}]}]}`,
  `service_id` the lower-case hex of `H(first ik)[0:16]`, `previous`
  all-zero for the first version.
- **Rekor profile:** a `hashedrekord` entry (digest SHA-256 of the
  document bytes; key the anchor key as PKIX DER; ASN.1 DER ECDSA
  signature) in a Rekor log named in the Sigstore trusted root pinned in
  the vault's release config, with an RFC 3161 timestamp from that
  root's timestamp authority, packaged as a Sigstore bundle (v0.3). A
  verifier checks that the entry names exactly `H(document)` and the
  anchor key, the signature, the inclusion proof and checkpoint, and the
  timestamp. Entries with the same digest are one document. The Rekor
  version and trusted root are pinned in item 5.4.

## 9. Trust

### 9.1 What each party learns

- **The service vault and the organisation:** who is eligible, and how
  each member voted, when. They keep it (§6).
- **VettID's relay and hosts:** which vaults sent a message to the
  service and when, as for any message; not the ballot, which is inside
  the session's encryption.
- **The public:** tags, voting keys, choices and the tally. Nothing that
  names a member, or links a member's rows across proposals.

### 9.2 What the protocol does not prevent

- **Phantom members:** connections the service controls, added before
  `record_at`. Only `eligible` and outside knowledge of the membership
  show them.
- **Voting for members who never check:** the service can put a ballot
  under the tag of a member who didn't vote. That member's vault catches
  it (§8.3); a member whose app never runs after the vote doesn't.
- **Dropping a ballot:** caught by its member, who holds the receipt.
- **Refusing a member:** the vault has the signed refusal, or no answer,
  as evidence.
- **A running tally:** the service can read its own table before close.
- **Forks:** a different document under the same slot can't be uploaded
  to the site, and a vault checks its proposal against the site before
  casting when it can (§10.1); a member shown a different proposal finds
  that the results don't contain its ballot, and its receipt proves what
  the service accepted.
- **The site:** votes.vettid.org can withhold a document, not alter one.

## 10. Availability

### 10.1 Failures

| Failure | What happens |
|---|---|
| The service doesn't send the proposal | The vault sees it on the site's index and asks with `vote.request`. A refusal is evidence. |
| The service refuses or ignores a ballot | The vault retries the same bytes until `closes_at`. A wrong refusal or no answer is evidence. |
| The service vault or relay is down | Messages wait in the relay (14 days) and count by the relay's receipt time (§6). Beyond §10.2's bound, the vote is extended. |
| votes.vettid.org is down | The vault checks the proposal from the bundle its message carried, and checks the site again when it can. |
| Rekor is down | The service can't publish or extend; it publishes when Rekor is back. |
| The member's vault is locked | Voting needs the app, so an unlocked vault. The app reminds the member a day before `closes_at`. |
| Clock skew | The relay's receipt time decides (§6); the app stops two minutes early. |
| A restore of the member's vault | `vote.status` (§5). |

### 10.2 Extensions

If the relay's status page or the service vault's health checks show an
outage of more than 1 hour within the window, the service may extend
`closes_at` by the outage, rounded up to the hour, by extensions
totalling at most 24 h. Each extension is published and anchored before
the `closes_at` it extends, then sent as `vote.extended`. **(chosen; not
in the spec.)**

## 11. Test vectors

Produced by the reference implementation (item 5.4) and copied by
vettid-vault; a copied vector that stops matching is a stop-and-report
item.
1. `record_tag`, `ballot_msg`, `ballot_sig`, `ballot_leaf`, a receipt
   and a refusal, from fixed keys.
2. Merkle: trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion proof
   for every leaf of the 5-leaf tree.
3. Documents: a proposal, an extension and results, with their
   signatures and anchor bundles; refusals of non-canonical bytes and
   duplicate names.
4. Ed25519: every §2 rule: small-order keys, including non-canonical
   encodings; `y ≥ p`; `x = 0` with the sign bit set; a non-canonical
   `S`; valid signatures.

## 12. Decisions for the owner

**Decided 2026-10-29:**
1. **Pseudonymous, not secret, ballots.** The public sees tags and keys;
   the service knows who voted how, and keeps that record (§1, §6).
2. **One vote, final** (§5).
3. **No enclaves, mixes, blind signatures or relay changes.** The
   earlier designs (0.2.0–0.8.0) are superseded.
4. **votes.vettid.org** publishes proposals and results, anchored in
   Rekor (§3.3).

**Choices this document makes:**

5. **Labels:** `vettid/vote/1/...`, the VMS convention (§2).
6. **Ballots go over the member's connection,** with a signed receipt
   (§4, §5).
7. **The relay's receipt time decides** whether a ballot is in the
   window (§6).
8. **Refusals are signed** (§4.2).
9. **JCS documents** are verified as exact bytes, with detached
   signatures (§2).
10. **Extensions** of up to 24 h for outages (§10.2).
11. **Receipt times are not published** (§7).

## Changes

- **0.9.0 (2026-10-29):** owner decision: a simpler design. Ballots are
  pseudonymous rather than secret, signed by a per-proposal key, sent
  over the member's connection, and final. Blind certificates, admission
  tokens, the mix, registration, the timelock, mirrors, declines and
  reports are gone, and with them the relay revision. Publication on
  votes.vettid.org with Rekor anchoring stays.
- **0.2.0–0.8.0 (2026-10-28 and 29):** successive secret-ballot designs
  with blind certificates, superseded by 0.9.0.
- **0.1.0:** first full draft.
