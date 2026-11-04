# Ballot Protocol

**Status:** 0.13.4 (2026-11-04)
(MEMBER-SERVICE-PLAN §10, item 5.0). It replaces the secret-ballot
design of MEMBER-SERVICE-PLAN §8 (owner decision 2026-10-29); the plan
in member-service is to be updated to point here. Choices are marked:
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
key made for that proposal only, and also signs it with the member's
credential key, so the ballot is provably theirs. It goes over the
member's ordinary connection, and the service answers with a signed
receipt. At the close the service publishes every tag with its ballot
or none, and the tally. Anyone can check the signatures, one ballot per
tag and the tally; each member's vault checks its own row. The public
sees tags and per-proposal keys, never names, emails or connections.
The service knows who voted how, and keeps that record, with the
members' signatures, for the organisation.

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only an eligible member (§3.2) can cast a ballot that counts. |
| One vote | One ballot per member per proposal. It is final. |
| Pseudonymity | The published results name no member: no name, email, connection or VettID key, and nothing that links one member's rows across proposals. **Not secret:** the service vault, and through it the organisation, knows how each member voted, and keeps that record (owner decision 2026-10-29). In a small electorate, knowing who voted can reveal how. **Members are told this before they vote** (§5). |
| Transparency | Every proposal, extension and result is signed, published on votes.vettid.org and anchored in Rekor (§3.3). |
| Verifiability | Anyone can check every ballot's signature, that no tag votes twice, and the tally (§8.4). Each member's vault checks that its own row is what it sent, or empty if it didn't vote (§8.3), and holds a signed receipt. The organisation's record holds each ballot with the member's credential signature, so a disputed row can be settled by an audit (§6). |
| Availability | No one but the member and the service can stop an eligible member from voting; against the service the protocol detects rather than prevents (§9.2, §10). |
| Coercion resistance, receipt-freeness | Out of scope (owner decision). |

## 2. Notation and primitives

- `‖` is concatenation. `u16` and `u64` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- **Labels** follow the VMS convention (VAULT-MESSAGING §4.1): ASCII
  strings embedding the version, **each ending in a `0x00` byte**, for
  example `"vettid/vote/1/ballot\x00"`. **(chosen; differs from the
  plan:** the plan's `"vettid-vote-v1"` follows vettid-dev.)
- **Signatures:** `Sign(sk, label, m)` is `suite.Sign` from vettid-vault
  `vms/suite`: Ed25519 over `label ‖ m`, with the label's own `0x00`
  separating it from `m`. Every signature the service identity key
  makes, in VMS and here, is over a label-prefixed string, so the two
  can't be confused. A hashed string that starts with a label includes
  the label's `0x00`.
- **Ed25519 verification,** by every verifier (the service vault, the
  member vault, the app, observers and the site), is exactly:
  1. `A` (the public key) and `R` are 32 bytes whose `y` is below p, and
     not `x = 0` with the sign bit set;
  2. neither `[8]A` nor `[8]R` is the identity (no small-order key or
     `R`);
  3. `S < L`;
  4. `[S]B = R + [k]A`, cofactorless, with `k = SHA-512(R ‖ A ‖ m) mod L`.

  Go's `ed25519.Verify` does steps 3 and 4, and Go's point decoding
  accepts a non-canonical `y`, so Go code makes steps 1 and 2 itself.
  §11's vectors pin the rules for every library.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
- **Documents** (the proposal, an extension, the results, the service
  list; §8.5) are JCS (RFC 8785). A verifier parses strictly
  (VAULT-MESSAGING §5.3: no duplicate names, byte order mark or unpaired surrogate escape), re-serializes per RFC 8785
  and refuses the document unless the bytes are identical. Each is
  signed with a detached signature over a string containing
  `H(document bytes)`. Times in them are Unix seconds; binary values
  are standard base64 with padding. **(chosen; not in the spec.)**
- **Message bodies** follow VAULT-MESSAGING §5.3; a document travels in
  a body as the base64 of its bytes.
- **Sorting** of tags is by their raw bytes.
- **The signing key:** the service identity key that signs a proposal
  signs every document, receipt and answer of it. The service starts no
  `identity.rotate` between a proposal's creation and its results.
- **Anchoring** uses ECDSA P-256 with SHA-256 under the service's anchor
  key (§3.3): what Rekor's `hashedrekord` and the standard Sigstore
  tools verify; Ed25519 there would need its pre-hashed variant.

## 3. Proposal

### 3.1 Contents

The proposal is a document (§8.5).

| Field | Meaning |
|---|---|
| `proposal_id` | A ULID. |
| `service` | The service identity key that signs it. |
| `title`, `text` | UTF-8; `title` 1–200 bytes, `text` at most 16,384 bytes. |
| `choices` | 3–17 entries `{id, label}`, in display order, with `id` matching `[a-z0-9-]{1,32}` and unique and `label` UTF-8 of 1–200 bytes: at least two real choices (16 at most), and `abstain`, reserved and always present, for a member who wants to be counted without choosing. The service vault assigns the ids itself (`c1`, `c2`, …, §3.4) and always adds `abstain`; a member's vault checks only this grammar. |
| `quorum` | The quorum rule, as text (UTF-8, at most 1,024 bytes, may be empty), and the number of ballots it needs (`min_ballots`, at least 0). `abstain` counts toward it. |
| `binding` | Whether the organisation treats the result as binding. The protocol is the same either way. |
| `removed_may_vote` | Whether a member removed or suspended after `record_at` may still vote. |
| `record_at` | The roster snapshot, at or before creation (§3.2) and at or before `opens_at`. |
| `opens_at`, `closes_at` | The voting window, `opens_at` before `closes_at`: a ballot counts if the relay received it in `[opens_at, closes_at)` (§6). At most 7 days (owner decision). |
| `eligible`, `record_root` | The number of eligible members, at least 1, and the Merkle root of their tags (§3.2). |
| `outage_rule` | The rule of §10.2, as text (UTF-8, at most 1,024 bytes). |

The proposal document is at most 65,536 bytes. Member vaults apply the
same bounds: the service refuses a proposal outside them before signing
it, the site refuses to publish one, and a member's vault refuses one it
receives.

- **Signature:** `proposal_sig = Sign(service IK, "vettid/vote/1/proposal\x00", H(proposal_bytes))`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds every ballot to
  this one proposal.

### 3.2 Eligible members and tags

- **Eligible members** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended, and with
  a vault that advertised the vote feature: the last `profile.update`
  the service holds from the connection carries `features` with
  `"vote"` (VAULT-MESSAGING §10.8, §10.19.1). A vault that advertises
  nothing is not eligible, so a proposal reaches only vaults that can
  vote. One connection is one member, so a person holding several
  VettID accounts is several members, which the organisation sees in its
  own roster.
- **Tags:** for each eligible member the service draws a 32-byte random
  `record_secret`. The member's tag is
  `record_tag = H("vettid/vote/1/record\x00" ‖ proposal_id ‖ record_secret)`.
  `record_root` is the RFC 6962 root (§8.2) over the tags, sorted, and
  `eligible` their number.
- **Delivery:** each member receives, in `vote.proposal` (§4.1), their
  `record_secret` and an inclusion proof of their tag. The vault checks
  the proof at once against `record_root` (RFC 9162 §2.1.3.2).
- Tags are new for every proposal, so nothing links a member's rows
  across proposals.

### 3.3 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public, write-once store run by VettID (its
design: vettid/votes, docs/VOTES-SITE.md).

- **The service list** (§8.5) names each registered service, its
  identity keys and its anchor keys. VettID maintains it; a service is
  added by the owner. The site signs each version with its own Ed25519
  key, pinned in the vault's release config:
  `Sign(site key, "vettid/vote/1/service-list\x00", H(bytes))`. Each
  version has a higher `version`, names the hash of the previous one
  and keeps all its entries; a vault keeps the latest it has verified
  and accepts a new one only if it chains. Keeping its entries means
  every earlier `service_id` is still listed, with every identity key
  it had (by bytes) and every anchor key it had (by `key`); these are
  only ever added to. A `name` may change and services may be added.
  Since the list only grows, it has no limit on the number of services
  or keys: each `name` is 1–100 bytes of UTF-8, and `services.json` is
  at most 4,194,304 bytes, which holds thousands of services. A vault
  that is given a list over its cap, or one it can't otherwise take,
  keeps the last list it verified and goes on with the services that
  list names; that is not an error, and a later release can raise the
  cap. (chosen; not in the spec)
  - A vault accepts a proposal's `service` only if it is its own
    connection's identity key (current, or a past one learned through
    `identity.rotate`). The list only adds which anchor keys that
    service uses.
- **The anchor key:** each service has one long-lived ECDSA P-256 key,
  sealed in its keystore, certified by its identity key:
  `anchor_cert = Sign(service IK, "vettid/vote/1/anchor-key\x00", H(anchor_key SPKI DER))`.
- **Documents,** uploaded in this order:
  1. the proposal, before it is sent to any member;
  2. any extensions, before the `closes_at` they extend (§10.2);
  3. the results (§7).
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
- **The upload's answer (the publisher contract):** `201` or `200` counts
  as published. The answer may carry `index_updated`: if it is `false`,
  the document is written but the index update failed, and the service
  uploads the identical bytes again until it is `true` (the only repair:
  nothing rebuilds the index from the documents): an extension at each
  reconcile and close, the results at each close once it is recorded as
  not updated; a proposal's entry is added by the next upload of its
  extensions or results. A missing field means updated, as older sites
  send none. `409` is a different document at
  that path. The service never depends on the index to find a document:
  it reads `extension-<n+1>` until a 404, when it reconciles and at the
  close (§10.2).
- **Discovery:** the site keeps an index of proposals open or closed in
  the last 30 days, with their extensions. The app fetches it, with no
  session, on a fixed hourly schedule, and hands the vault the entries
  of its services.

### 3.4 Who may create a proposal, and what an approval carries

The service creates a proposal only with the admins' approval of exactly
its input (MEMBER-SERVICE-PLAN §4.5, §5.2), and uses that approval once;
holding the application's API key is not enough. The approval is for the
action `proposal.create`, and it is approved when m distinct admins have
signed the challenge (VAULT-MESSAGING §10.4). A signature made with a
credential key other than the admin's governance key (the key pinned
when the connection became an admin, which moves only by a rotation chain
from it or by the other admins' `admin.repin`) does not count, here or
when the service counts again before using the approval: someone else
may now hold that credential. An admin whose key changed is re-pinned only
by the other admins' approval, who first ask them out of band whether they
reset their credential at the time the summary names (the expected
cause: a rotation of the key moves the governance key by its verified
chain, with no re-pin), and then compare the summary's `new key` with the credential-key
fingerprint that admin reads to them from their own app (Settings → Vault
status; VAULT-MESSAGING 0.83.8 §10.8). It is the same string: the first
16 hex digits, in 4 groups of 4, of SHA-256("vettid/vms/2/ck-fp" || key).
An app that does not show it yet (one built before VAULT-MESSAGING
0.83.8) shows no fingerprint, and then the question alone is the check.
Before approving an `admin_set.add`, the admins likewise compare its
`cred key` with the fingerprint the new admin reads from their own app.

A denial may be the admin's own or their vault's: a vault answers a
challenge it suppresses (its member muted or paused the service, the
decline cooldown, the pending cap or the rate) exactly as a decline,
after a random delay, so that the service cannot tell (VAULT-MESSAGING
§10.4.1; owner decision a of 2026-11-04). The service counts both alike,
so an admin who mutes the service abstains from its approvals, and it
shows the admins who did not approve as such, never as having declined.
Creating an approval is rate-limited, and the admins' last approval ask
of each 24 hours is kept for `admin.repin` and `admin_set.*`, so whoever
holds the API key cannot leave the admins unaskable for a change to the
set.

The governance key is pinned at exactly these moments: when the
connection first signs a response (the first sign-in), when
`admin_set.add` is applied (the credential key whose fingerprint the
approval showed, and only if it is still the connection's), when the
bootstrap makes the first admin (only if none is pinned yet), and, for an
admin from before the governance key existed, at the migration (the key of
the earliest signed approval in the audit log, else the current credential
key). Nothing else moves it but a rotation chain that starts at it and the
other admins' `admin.repin`. Known limits: the migration can only use
the approvals the audit log holds, so an admin who never approved is pinned
to whatever key they hold then; and the fingerprints shown to the admins
are 64 bits (16 hex digits) of a SHA-256.

A re-pin (`admin.repin`) is approved by the other admins only, and needs
the threshold or all the other admins who are admins at that moment,
whichever is fewer (never fewer than one; owner decision of 2026-11-02):
with two admins at m = 2 the other admin alone re-pins, after asking out
of band. Removing admins to lower that number takes `admin_set.remove`
approvals at the full threshold, or an admin leaving on their own, and the approvals of the removed no
longer count. A sole admin cannot be re-pinned this way (`sole_admin`).

The `proposal.create` approval's payload is the input
in JCS form with every field present, parsed strictly (§2).

Before creating, the service checks, in one step that no other request
can interleave with, that the approval is approved (counting again the
signatures of the admins in the set now, against the larger of the
threshold the approval was made with and the threshold now), that the
summary the admins read is the one the service builds from the payload
(an approval made with any other is refused),
is for `proposal.create`, has not run out and has not been used, and
that its payload equals, byte for byte, the JCS form of the input it is
about to execute. It then records the approval as used, and only then
makes, publishes and sends the proposal. An approval used for a proposal
that then fails to be made or published is not usable again; the admins
approve again. The use is recorded with what it was used for: the
proposal's id (and, for an extension, its number), in the `apv_used`
record, in the `approval.consumed` audit entry and in the approval's
status (`used: {at, proposal_id, n}`). After a lost answer or a crash,
the operator reads the status: if `used` is there, the proposal (or the
extension) was started, and its status says whether it was published
(`/publish` finishes one that was not); if it is not, nothing was made
and the same approval can be used again.

**What the admins read.** The challenge's context (VAULT-MESSAGING
§10.4, at most 256 bytes) is
`Approve on <service>: New vote: <summary> — ref <16 hex of the action hash>`.
The label `New vote:` is the service's, put before every summary of this
action (and `Extend vote:` before an extension's); the application
writes no text of either. The summary is built from the payload: binding
or advisory, the window, the quorum's minimum, the choices' labels and
the title, all shown whole: an input whose summary does not fit the
context is refused, never
cut, so a title that equals the motion can't hide the rest of it. For an extension it is the proposal (its title, from
the service's copy, and its id), the new close, the outage and its source.

**Every field of the executed proposal is shown, set by the service, or
refused:**

| Field | In the approval | Executed |
|---|---|---|
| `title` | shown whole; printable ASCII and Latin-1 letters only | as approved |
| `choices` | shown: the labels, in order, each at most 24 characters, printable ASCII and Latin-1 letters only, distinct (also ignoring case) and none `Abstain`; an `id` is refused | the service assigns `c1`, `c2`, … in that order (matching §3.1's id grammar) and adds `abstain` (label `Abstain`) last, always |
| `binding`, `removed_may_vote` | shown | as approved |
| `opens_at`, `closes_at` | shown | as approved |
| `quorum.min_ballots` | shown | as approved |
| `quorum.text` | refused unless empty | empty |
| `text` | refused unless empty or equal to `title` (the motion is the title) | as approved |
| `outage_rule` | refused unless empty or the rule of §10.2 ("Extended by a relay outage over 1 hour, 24 h at most.") | always that rule |
| `proposal_id`, `service`, `record_at`, `eligible`, `record_root` | not in it: the service's, at the moment of use | the roster at the moment of use (§3.2), the time of use |
| the tags and secrets | not in it | drawn at the moment of use |

Titles and labels use printable ASCII and Latin-1 letters only
(`unsupported_characters`), so that two labels can't differ only by a
look-alike letter from another script (a Cyrillic `е` for `e`); a wider
character set waits for a check for confusables. An extension's summary
shows the stored title whole too, in the same character set. So that
every vote can be extended, a title is accepted at creation only if it
fits whole in the longest extension summary (the longest source, the
widest times): **at most 35 bytes** (`MaxTitleBytes`, computed from the
same summary builder), and with the choices' labels it must fit the
creation summary too.

A refused field makes the approval request fail (`field_not_shown`, or
`invalid_payload`), and the proposal request fail with nothing made and
the approval unused. A longer motion, a quorum text or another outage
rule can be put to the admins only once approval challenges carry the
full document; until then the service refuses them. **(chosen; not in
the spec.)**

## 4. Messages

Session-mode messages on the service connection (VAULT-MESSAGING §5.3).
Each request is answered with a response that names it (`re`). A vault
without the vote feature answers `unsupported_type`, which today's rules
would instead drop and audit; that needs the §6.4 change of item 5.1.

### 4.1 From the service

| Type | Body | When |
|---|---|---|
| `vote.proposal` | `{proposal, proposal_sig, bundle, record_secret, record_proof}` | To every eligible member, once the proposal is published. `record_proof` is `{index, tree_size, path}` (§8.5). |
| `vote.extended` | `{proposal_id, extension, extension_sig, bundle}` | To every eligible member, once an extension is published (§10.2). |
| `vote.closed` | `{proposal_id, results_hash}` | To every eligible member, once the results are published. `results_hash` is `H(results_bytes)`, the SHA-256 of the exact `results.json` document (§8.5). Optional: the vault checks at a fixed time anyway (§8.3). |

The vault answers each with `{proposal_id}` or an error. The service
acknowledges and drops every answer, whatever its body: it changes
nothing, and a member it missed asks `vote.status` (§4.2).

**The vault keeps** a proposal whose signature verifies under its
connection's identity key and whose bundle verifies under that service's
listed anchor key. A second, different proposal under the same
`proposal_id` is kept as evidence and not used.

### 4.2 From the member's vault

| Type | Body | Answer |
|---|---|---|
| `vote.cast` | `{proposal_id, record_tag, vk, choice_id, ballot_sig, cast_sig, pad?}` (§5) | `{proposal_id, msg_ms, receipt_sig}`, or a refusal |
| `vote.status` | `{proposal_id}` | `{proposal_id, proposal, proposal_sig, bundle, record_secret, record_proof, ballot?, msg_ms?, receipt_sig?, status_sig}`, or a refusal |

Every JSON object above that carries a member's `choice_id` (the
`vote.cast` body, the `ballot` of the `vote.status` answer and the
`ballot` of the `already_voted` refusal) also carries `pad`: a string of
ASCII `0` characters whose length is 32 minus the byte length of
`choice_id` (empty for a foreign `choice_id` longer than 32 bytes). The
relay sees the padded size of every message, and `pad` keeps it the same
for every choice. No signature's message covers `pad` (they cover binary
messages, not the JSON), with one exception: a refusal to a body too
malformed to form them signs `H(the request body)`, pad included. `pad`
is in no published document. A receiver checks neither its type, its
value nor its length, and does not require it, so a sender without it
still works; VAULT-MESSAGING §5.3's strict-JSON rules (no duplicate
names, depth, UTF-8) still apply to it (the service does not yet refuse
a duplicate name in `vote.cast`). The service keeps nothing of it. The vault's `vote.evidence` export (VAULT-MESSAGING)
holds the service's answers as the service sent them, byte for byte, so
the service's padding is what keeps those exports one size for every
choice. See VAULT-MESSAGING 0.83.6 §10.19.5.

- **`vote.status`** gives a vault what the service holds for its
  connection: the proposal with its signature and anchor bundle, and its
  tag (as in `vote.proposal`), and the ballot with its receipt if one is
  recorded. `ballot` is `{vk, choice_id, ballot_sig, pad}`; `ballot`,
  `msg_ms` and `receipt_sig` come together or not at all, and every
  other member is always present. A proposal not yet published (with no
  bundle) is `unknown_proposal`, so a vault can check one learned this
  way without the site. The answer is signed:
  `status_sig = Sign(service IK, "vettid/vote/1/status\x00", lp(proposal_id) ‖ lp(record_tag) ‖ H(ballot_leaf))`,
  where with no ballot `H` is taken of the empty string.
  A vault asks it for a proposal on the site's index that it doesn't
  hold, after a restore (§5), and when a cast has had no answer for 24
  hours.
- **Refusals** are signed, so a member can show them:
  `refusal_sig = Sign(service IK, "vettid/vote/1/refusal\x00", lp(proposal_id) ‖ lp(connection) ‖ lp(record_tag) ‖ lp(type) ‖ lp(code) ‖ u64(msg_ms) ‖ request_hash)`,
  in the error body as `{refusal_sig, msg_ms, connection, record_tag}`,
  where `connection` is `H(the connection's peer identity key)`,
  `record_tag` is empty when the connection has none, `msg_ms` is the
  relay's time of the request (§6), and `request_hash` is
  `H(ballot_leaf)` for `vote.cast` and `H(proposal_id)` for
  `vote.status`, or `H(the request body)` when the body is too malformed
  to form them. A request that names no valid `proposal_id` gets an
  unsigned refusal, whose `refusal_sig` is `null`. A vault treats an
  unsigned refusal as no answer.

| Code | For | Meaning |
|---|---|---|
| `not_eligible` | both | The connection has no tag for this proposal. |
| `not_open`, `closed` | `vote.cast` | The relay's time is outside the window. |
| `not_active` | `vote.cast` | Removed or suspended, and `removed_may_vote` is false. |
| `not_signed_in` | `vote.cast` | The member has never signed in, so no credential key is pinned (§5). |
| `already_voted` | `vote.cast` | A different ballot is already recorded for this tag; the body also carries that ballot as `ballot` `{vk, choice_id, ballot_sig, pad}`, with its `ballot_msg_ms` and `receipt_sig`. |
| `bad_ballot` | `vote.cast` | The tag isn't the connection's, the choice isn't the proposal's, or a signature fails. After a credential-key rotation (`connection.authenticate.rotated`, VAULT-MESSAGING §10.4) the vault may sign `cast_sig` again under its current key and send the same ballot once more; the service checks `cast_sig` under the key pinned when the cast arrives. |
| `late` | `vote.cast` | The window was open, but the results were already published (§7). |
| `unknown_proposal` | `vote.status` | No such proposal. |

## 5. The ballot

- **The voting key:** when the vault keeps a proposal, it makes a fresh
  random Ed25519 key `vk` for it and stores it in its encrypted state.
  It is used for that proposal only.
- **The ballot:**
  - `ballot_msg = proposal_hash ‖ record_tag ‖ lp(choice_id)`;
  - `ballot_sig = Sign(vk, "vettid/vote/1/ballot\x00", ballot_msg)`;
  - `ballot_leaf = record_tag ‖ lp(vk) ‖ lp(choice_id) ‖ lp(ballot_sig)`;
  - `cast_sig = Sign(credential key, "vettid/vote/1/cast\x00", proposal_hash ‖ H(ballot_leaf))`,
    under the member's credential key, which the service already pins
    at the member's first sign-in (SERVICE-VAULT.md §5). It is never
    published.
  - **A member must have signed in once before voting.** The pinned key
    comes from a signed sign-in the member's own vault records, so a
    ballot the service made up couldn't carry the member's signature. A
    key the ballot named itself would prove nothing: the service could
    make up both. A member who has never signed in is refused
    `not_signed_in`, and the app asks them to sign in first.
- **Disclosure:** before the member approves a ballot, the app shows a
  fixed sentence, in the app's own words and not the proposal's: *"<the
  service's name> will see how you vote and keep that record. The
  published results show only an anonymous code for you."* No proposal
  can change or leave it out. **(Owner decision 2026-10-29.)**
- **Casting:** the member chooses in the app, between `opens_at` and
  `closes_at`. The vault signs only with the member's approval inside
  the credential's unlock window (VAULT-MESSAGING §3.5.3); it is not an
  ask. It stores the ballot before sending it, and re-sends exactly
  those bytes until it has a receipt or `already_voted`. `not_open`, no
  answer, and network errors are retried; after 24 hours without an
  answer it asks `vote.status`.
  - The app refuses to cast in the last two minutes before `closes_at`,
    by the vault's clock.
- **The receipt:**
  `receipt_sig = Sign(service IK, "vettid/vote/1/receipt\x00", proposal_hash ‖ H(ballot_leaf) ‖ u64(msg_ms))`,
  with `msg_ms` the relay's time of the `vote.cast` message (§6). The
  vault verifies and keeps it. The vote is then final: the app doesn't
  offer it again.
- **After a restore of the member's vault** (the vault finds its state
  older than its last run, or is re-enrolled from a backup), it asks
  `vote.status` for every proposal of its services on the site's index.
  If the service names a ballot, the vault checks its `vk` against its
  own copy when it has one; without a copy, the app shows the recorded
  choice and asks the member to confirm it, and a "no" is evidence.
- **A member vault restored past an epoch change** needs a new
  invitation (VAULT-MESSAGING §6.6). The new connection has no tag, so
  the member can't vote in, or recover a receipt for, a proposal whose
  `record_at` came before it. The organisation can settle it from its
  record.

## 6. What the service does

- **On `vote.cast`,** in order:
  1. **Idempotency:** if the tag already has exactly this ballot, the
     stored receipt is sent again, whenever the request arrives.
  2. **Window:** the relay's time of the message (the time of its
     `msg_id`, RELAY-PROTOCOL §6.2, as `msg_ms`) is in
     `[opens_at, closes_at)`, as extended (§10.2). A ballot queued at
     the relay during an outage still counts.
  3. **Eligibility:** the connection is eligible, `record_tag` is its
     tag, and it is active or `removed_may_vote` is true.
  4. **Ballot:** `choice_id` is the proposal's, `ballot_sig` verifies
     under `vk`, and `cast_sig` verifies under the connection's pinned
     credential key (§2); with no key pinned, `not_signed_in`.
  5. **One per tag:** a conditional write stores the ballot, with
     `cast_sig` and `msg_ms`, only if the tag has none; otherwise the
     answer is `already_voted`.
  6. It signs the receipt and answers.
- **Durability:** each accepted ballot is also written, write-once, to a
  store outside the service vault's table (one object per tag), so a
  table restore can't lose it or let a second ballot in. After a
  restore, the service rebuilds the table's ballots from that store.
- **The record** of each connection's tag, ballot, `cast_sig` and
  `msg_ms` is kept for the organisation's records (owner decision
  2026-10-29), sealed like the service vault's other records. It is not
  published. The organisation reads it through the service vault's admin
  API, and an auditor can check any row against the member's credential
  signature.
- **No running tally:** the service vault exposes no count before the
  results. That rests on the service being honest; the protocol can't
  stop a service from reading its own table.

## 7. Results

- **Collecting:** the relay delivers a mailbox's messages in `msg_id`
  order (RELAY-PROTOCOL §6.2), so once the service has handled a message
  whose `msg_ms` is at least `closes_at` + 1 min, with no earlier one
  still leased, it has every ballot of the window. A `vote.cast` handled
  after that gets `late`.
- **A message left unacked** (one the service couldn't handle yet, and
  the relay hands out again) holds the count at most 24 hours from when
  it was first left (owner decision 2026-10-30), however often it comes
  back; past that, or once the relay drops it unhandled (its TTL), the
  count goes ahead without it. `counts.unhandled` says how many such
  messages the relay received in `[opens_at, closes_at)`, with
  `closes_at` after any extensions: each may have held a ballot that
  doesn't count, so a non-zero value is for observers to weigh. A
  message in the minute after `closes_at` is left out: a cast in it is
  late anyway.
- **The results** are two parts (§8.5):
  - **`rows.json`:** every tag, sorted, with its ballot
    `{vk, choice_id, ballot_sig}` or `null`;
  - **`results.json`:** the proposal and any extensions with their
    signatures, `rows_hash = H(rows bytes)`, `rows_root` (the Merkle
    root over the row leaves, §8.2), the tally per choice, and the
    counts: `eligible`, `ballots`, `removed` (members removed or
    suspended after `record_at`), and `unhandled` (messages of the
    window the count went ahead without, above).
- **Signature:** `results_sig = Sign(service IK, "vettid/vote/1/results\x00", proposal_hash ‖ H(results_bytes))`.
- **Published** on votes.vettid.org, both parts, with `results.json`
  anchored (§3.3); announced in `vote.closed`.
- Receipt times are not published: with outside knowledge of when a
  member was active, they could narrow down whose row is whose.

## 8. Verification

### 8.1 What the documents bind

Every ballot names the proposal's hash and its tag, so it counts for one
proposal and one tag only. Every tag is in `record_root`, which the
signed proposal fixed before anyone voted. Every ballot the service
accepted carries the member's credential signature in its record.

### 8.2 Merkle trees and leaves

- RFC 6962 §2.1 with SHA-256; proofs verified per RFC 9162 §2.1.3.2:
  leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`, split
  at the largest power of two below n, the empty tree `H("")`.
- **Record leaf:** the 32-byte tag, in sorted order (`record_root`).
- **Row leaf:** `ballot_leaf` for a row with a ballot, or the 32-byte
  tag alone for an empty row, in the order of `rows` (`rows_root`).

### 8.3 What a member's vault checks

At `vote.closed`, and in any case at `closes_at` + 2 h (as extended),
retrying with backoff for 7 days; the app runs pending checks whenever
it opens. After 7 days the vault records that it gave up, and still
judges a later check (VAULT-MESSAGING 0.83.6 §10.19.6): a service that
publishes its results has every member's check settle by itself.
1. **The app** fetches `results.json`, `rows.json` and the bundle from
   votes.vettid.org, with no session, verifies them as an observer does
   (§8.4), and hands the vault `results.json`, the bundle, the vault's
   own row and its inclusion proof to `rows_root`.
2. **The vault** checks `results_sig` and the bundle; that the proposal
   and extensions in `results.json` are the ones it received; and its
   row's proof.
3. **Its row:**
   - it holds a receipt: the row carries exactly that ballot;
   - it never cast: the row is empty;
   - it cast but has neither receipt nor refusal: the row may carry its
     ballot or be empty; either is shown as "unconfirmed", not as a
     failure.
4. **Outcome:** a failure is shown to the member with the evidence: the
   signed proposal, the receipt or signed refusals, and the results. The
   app can export it. A receipt for a ballot the results lack or change
   proves the service at fault. A ballot under the tag of a member who
   says they never voted is settled by the organisation's record: the
   service holds the member's `cast_sig` for it, or it doesn't.

### 8.4 What an observer checks

From votes.vettid.org alone:
1. `results_sig` and every document's signature hold under the service's
   identity key; every bundle verifies under a listed anchor key; the
   service list verifies;
2. `H(rows bytes)` is `rows_hash`; the tags are unique, number
   `eligible` and reach `record_root`; the rows reach `rows_root`;
3. every ballot's `ballot_sig` verifies under its `vk` for
   `ballot_msg(proposal_hash, tag, choice_id)`, and its choice is one of
   the proposal's;
4. the tally and `ballots` recompute;
5. each extension is timestamped (by its bundle) before the `closes_at`
   it extends, and they total at most 24 h.

### 8.5 Schemas

A verifier refuses unknown, missing or mistyped fields. `b64` is
standard base64; `hash` the `b64` of 32 bytes; `sig` the `b64` of 64
bytes; `time` a JSON integer of Unix seconds; `spki` the `b64` of a DER
SubjectPublicKeyInfo; `?` marks a field present only where stated.

- **Proposal:** `{v: 1, proposal_id, service: b64, title, text, choices: [{id, label}], quorum: {text, min_ballots: int}, binding: boolean, removed_may_vote: boolean, record_at: time, opens_at: time, closes_at: time, eligible: int, record_root: hash, outage_rule: string}`.
- **Extension:** `{v: 1, proposal_id, n: int (≥ 1), closes_at: time, outage: {from: time, to: time, source: string}}`;
  signature `Sign(IK, "vettid/vote/1/extended\x00", proposal_hash ‖ H(bytes))`.
  `outage.from` is before `outage.to`, `source` is 1–1,024 bytes of
  UTF-8 (where the outage was reported, such as the relay's status
  page), and the document is at most 65,536 bytes. That the outage is
  over an hour, within the window, and that the extension rounds it up
  to the hour (§10.2) are checked by the service before it signs.
- **Rows:** `{v: 1, proposal_id, rows: [{record_tag: hash, ballot: {vk: b64, choice_id: string, ballot_sig: sig} | null}]}`,
  `rows` sorted by `record_tag`.
- **Results:** `{v: 1, proposal_id, proposal: {doc: b64, sig: sig}, extensions: [{doc: b64, sig: sig}], rows_hash: hash, rows_root: hash, tally: {<choice id>: int}, counts: {eligible: int, ballots: int, removed: int, unhandled: int}}`,
  `tally` naming every choice.
- **`record_proof`, row proofs:** `{index: int, tree_size: int, path: [hash]}`,
  the audit path from the leaf up.
- **Service list:** `{v: 1, version: int, previous: hash, services: [{service_id: string, name: string, iks: [b64], anchor_keys: [{key: spki, anchor_cert: sig, ik: b64}]}]}`,
  `service_id` the lower-case hex of `H(first ik)[0:16]`, `previous`
  all-zero for the first version. Published with its signature as
  `services.json` and `services.json.sig`.
- **Message bodies** are as §4 gives them, with these types: `proposal`,
  `extension` `b64`; `*_sig` `sig`; `record_secret`, `results_hash`,
  `record_tag` `hash`; `vk` `b64`; `msg_ms` a JSON integer; `bundle` a
  Sigstore bundle as JSON.
- **Rekor profile:** a `hashedrekord` entry (digest SHA-256 of the
  document bytes; key the anchor key as PKIX DER; ASN.1 DER ECDSA
  signature) in a Rekor log named in the Sigstore trusted root pinned in
  the vault's release config (earlier roots are kept, so old bundles
  still verify), with an RFC 3161 timestamp from that root's timestamp
  authority, packaged as a Sigstore bundle (v0.3). A verifier checks
  that the entry names exactly `H(document)` and the anchor key, the
  signature, the inclusion proof and checkpoint, and the timestamp. The
  entry is `hashedrekord` version 0.0.1, entered through Rekor's v1
  API; the bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`)
  carries `publicKey`, `tlogEntries` and `timestampVerificationData`.
  Each pinned trusted root is a Sigstore TrustedRoot document
  (`application/vnd.dev.sigstore.trustedroot+json;version=0.1`, as
  Sigstore's TUF repository serves `trusted_root.json`); §11 item 3 is a
  bundle that verifies against the staging one.

## 9. Trust

### 9.1 What each party learns

- **The service vault and the organisation:** who is eligible, and how
  and when each member voted. They keep it (§6).
- **VettID's relay and hosts:** which vaults sent a message to the
  service and when, as for any message; not the ballot, which is inside
  the session's encryption.
- **The public:** tags, per-proposal keys, choices, the tally and the
  counts. Nothing that names a member, or links a member's rows across
  proposals.

### 9.2 What the protocol does not prevent

- **Phantom members:** connections the service controls, added before
  `record_at`. Only `eligible` and outside knowledge of the membership
  show them. Equally, a member left off the roster at `record_at` is
  shown only by that member asking (`vote.status` answers
  `not_eligible`, signed).
- **Voting for members who don't vote:** the service can put a ballot
  under such a member's tag. The member's vault sees it (§8.3), and the
  organisation's record shows the service holds no `cast_sig` for it; a
  member whose app never runs after the vote sees nothing.
- **Dropping a ballot it dislikes:** the service sees the choice before
  it answers, so it can stay silent. The member's vault retries and
  asks `vote.status`; silence proves nothing to a third party, but a
  ballot with a receipt that the results lack does.
- **A member holding up the count:** a member can keep a message coming
  back unhandled. The count waits for it 24 hours at most, then goes
  ahead and says so (`counts.unhandled`); if that message was a ballot
  cast in time, it doesn't count.
- **Delays by VettID's relay:** the relay could hold or drop one
  member's messages. The window counts by the relay's own time, so a
  held ballot still counts; a dropped one is retried.
- **Withholding the results, or extending after reading the running
  tally:** visible to everyone (no results; an extension with its
  stated outage), not prevented.
- **A split view:** the site refuses a second document at one path, and
  every vault checks its own proposal and row against the site, but
  Rekor proves only existence and time, so a site and service colluding
  could show different readers different results. Each reader's own
  checks still hold for what they were shown.
- **The site alone** can withhold a document, not alter one.

## 10. Availability

### 10.1 Failures

| Failure | What happens |
|---|---|
| The service doesn't send the proposal | The vault sees it on the site's index and asks `vote.status`. A signed `not_eligible` is evidence the member can show the organisation. |
| The service refuses or ignores a ballot | The vault retries the same bytes, then asks `vote.status`. A wrong signed refusal is evidence. |
| The service vault is down | Messages wait in the relay (14 days) and count by the relay's time (§6). |
| The relay is down | Members can't send. Beyond §10.2's bound, the vote is extended. |
| votes.vettid.org is down | The vault checks the proposal from the bundle its message carried, and the site again when it can. |
| Rekor is down | The service can't publish or extend; it publishes when Rekor is back. |
| The member's vault is locked | Voting needs the app, so an unlocked vault. The app reminds the member a day before `closes_at`. |
| Clock skew | The relay's time decides (§6); the app stops two minutes early, and `not_open` is retried. |
| A restore of the member's vault | §5. |
| A restore of the service vault's table | §6 "Durability". |

### 10.2 Extensions

If the relay's status page shows an outage of more than 1 hour within
the window, the service may extend `closes_at` by the outage, rounded up
to the hour, by extensions totalling at most 24 h. Each extension is
published and anchored before the `closes_at` it extends, listed in the
site's index, and sent as `vote.extended`; a vault also learns of it
from the index. An extension needs the admins' approval, as creating a
proposal does (§3.4): an approval of the action `vote.extend`, whose
payload is `{proposal_id, closes_at, outage}` in JCS form, checked and
used once before the extension is published; the outage's `source` is an
`https://` URL of at most 32 bytes of visible ASCII (so no
internationalised look-alike domain), shown to the admins whole. An
extension asked for less than 1 minute before the close it extends (the
`CollectMargin` that the count already allows after the close) is refused
as too late (`too_late`) before the approval is looked at, so that the
approval stays usable: one published later may not reach the close in time.

The extension is **stored before it is published**, because the site's
copy is write-once. The service signs the extension and stores it as *pending* on the
proposal record (a write conditional on the record's version) **before the
approval is used**; if that store fails (a conflict), nothing is used and
the request can be retried; if the approval is then refused, the pending
extension is cleared and the approval is as it was. It then uses the
approval, publishes the extension, and marks it in effect (appended to the
extensions, `closes_at` moved, pending cleared). A retry repeats the use
of the same approval for the same extension, which the approvals accept
once (never a second use). A
retry, or a restart, publishes the same bytes, never a new signature,
and uses no second approval; while one is pending a different extension
is refused (`extension_pending`, 409). **Whether an extension is in
effect is decided by the RFC 3161 time (`genTime`) in the Sigstore bundle
the service anchored for it**, as the site decides (VOTES-SITE §4) and a
vault does (VAULT-MESSAGING §10.19.6): before the `closes_at` it extends,
or it does not apply (`too_late`). The service reads that time only from
the bundle it kept itself, never from the one the site serves, and only
after verifying the token: its message imprint is SHA-256 of the bundle's
message signature (the ECDSA signature the anchor timestamps), the bundle's
message digest is SHA-256 of the document, and the CMS signature chains
from the TSA's certificate to a root pinned in the release (per Sigstore
instance's Sigstore trusted root; judged at the token's own time, which must fall in that authority's `validFor`), as an end-entity certificate
with the single, critical time-stamping usage. Anything that doesn't
verify applies nothing. The site also refuses a first upload by its own
clock, once the close it extends has passed there, whatever the bundle
says (`too_late`, which the service treats as `too_late`, not as an
outage). A retry
that was never anchored must leave the 1-minute margin; one with a kept
bundle is judged by its time. Before counting, the close **reconciles**
the store with the site: it reads `extension-1`, `extension-2`, … to the
first 404 to find them. A pending extension the site has is put in
effect; one the site has and the store lacks is adopted only if it
carries the service's signature, this proposal, the next number, the 24 h
limit and a kept bundle of the service's own with a time before the close
it extends (none kept, as after a restore of the table: refused). A 404
is not proof of absence (it may be cached): before a pending extension is
dropped, once the close and the margin have passed, its stored bytes are
uploaded again; `200` or `201` says the site has it (it is adopted), `422
too_late` says it does not (it is dropped), anything else is an error and
nothing is dropped. Any other difference (the store holds an extension
the site lacks or has other bytes; the site's extension doesn't verify)
is refused: nothing is counted and the error is logged (`site_mismatch`,
409). The last extension is uploaded again at each reconcile, which also
finishes the index (§3.3).

**Known limits.** (1) A 404 on an extension's signature or bundle file
(cached) can delay a close by the CDN's error time to live: liveness
only. (2) An extension with no bundle of the service's own is never
adopted. (3) A probe answered `422` with a code other than `too_late`
(`bad_anchor`, `unknown_service`) is an error: every close fails, and
nothing is dropped or counted, until the site accepts the document. The
operator corrects the cause at the site (for instance the service list
entry naming the anchor key) and closes again; if the site can never
accept it, the pending extension has to be removed from the proposal's
record by hand (there is no API for it), after which the close counts
without it. **(chosen; not in the spec.)** Counting the votes after the close (§7) needs no approval: it
decides nothing that the window and the ballots have not.

## 11. Test vectors

Produced by the reference implementation (item 5.4) and copied by
vettid-vault; a copied vector that stops matching is a stop-and-report
item.
1. `record_tag`, `ballot_msg`, `ballot_sig`, `ballot_leaf`, `cast_sig`,
   a receipt, a status answer and a refusal, from fixed keys.
2. Merkle: trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion proof
   for every leaf of the 5-leaf tree.
3. Documents: a proposal, an extension, rows and results, with their
   signatures; refusals of non-canonical bytes and duplicate names. An
   anchor bundle can't be made from fixed seeds, so its vector
   (`vote/testdata/anchor-vector.json`) is a proposal captured from the
   staging site with its bundle, its anchor key and certificate, and the
   Sigstore staging trusted root it verifies under.
4. Ed25519: every §2 rule: small-order keys and `R`, including
   non-canonical encodings; mixed-order keys; `y ≥ p`; `x = 0` with the
   sign bit set; a non-canonical `S`; valid signatures.

## 12. Decisions for the owner

**Decided 2026-10-29:**
1. **Pseudonymous, not secret, ballots.** The public sees tags and keys;
   the service knows who voted how, and keeps that record (§1, §6).
2. **One vote, final** (§5); members are told before voting that the
   service sees their vote (§5).
3. **No enclaves, mixes, blind signatures or relay changes.** The
   earlier designs (0.2.0–0.8.0) are superseded.
4. **votes.vettid.org** publishes proposals and results, anchored in
   Rekor (§3.3).

**Choices this document makes:**

5. **Labels:** `vettid/vote/1/...\x00`, the VMS convention (§2).
6. **Ballots go over the member's connection,** signed by a
   per-proposal key and by the member's credential key, with a signed
   receipt (§5).
7. **The relay's time decides** whether a ballot is in the window (§6).
8. **Refusals and status answers are signed** (§4.2).
9. **JCS documents** are verified as exact bytes, with detached
   signatures (§2).
10. **Extensions** of up to 24 h for relay outages (§10.2), and
    proposals, each only with the admins' approval of the exact input,
    used once (§3.4).
11. **Receipt times are not published** (§7).
12. **Accepted ballots are also kept outside the table,** write-once
    (§6).

## Changes

- **0.13.4 (2026-11-04):** §3.4: a denial may be an automatic one, from
  a vault that suppressed the challenge, and counts as a denial (owner
  decision a); creating approvals is rate-limited, and each admin's last
  approval ask of a day is kept for the actions that repair the admin
  set. No change to the messages, the documents or the vectors.
- **0.13.3 (2026-11-04):** §3.4: before re-pinning an admin whose key
  changed, the other admins compare the summary's `new key` with the
  credential-key fingerprint that admin reads from their own app
  (VAULT-MESSAGING 0.83.8 §10.8, the same string as the summaries), and
  the admins compare an `admin_set.add`'s `cred key` the same way. No
  change to the service, the messages, the documents or the vectors; a
  test pins the fingerprint to VAULT-MESSAGING's §16 vector.
- **0.13.2 (2026-11-03):** §4.2: every JSON object that carries a
  member's `choice_id` also carries `pad` (the `vote.cast` body, and the
  `ballot` of the `vote.status` answer and of the `already_voted`
  refusal), so the relay sees one message size for every choice id
  (VAULT-MESSAGING 0.83.6 §10.19.5). `pad` is outside every signature,
  receivers ignore it and do not require it. No change to the
  signatures or the documents; the vectors gain `credential.cast_body`
  (the padded `vote.cast` body, 418 bytes) and its SHA-256.
- **0.13.1 (2026-11-02):** §10.2: an extension is stored (pending) before
  it is published (and before its approval is used), a retry publishes the
  same bytes, the verified bundle's RFC 3161 time (read from the service's own kept bundle)
  decides whether it applies, and the close reconciles with the site
  before counting, probing before it drops a pending extension. §3.3: the publisher contract for the upload's
  answer (`index_updated`). No change to the messages or documents.
- **0.13.0 (2026-11-02):** creating a proposal (§3.4) and extending one
  (§10.2) need the admins' m-of-n approval of the exact input, used
  once; the API key alone no longer starts or extends a vote. §2 says
  what a strict parse refuses: duplicate names, a byte order mark and an
  unpaired surrogate escape (VAULT-MESSAGING §5.3). No change to the
  messages, the documents or the vectors. §3.4 lists, field by field,
  what the admins are shown, what the service sets (the choice ids
  `c1`, `c2`, … and `abstain`, `outage_rule`, `record_at`, the roster)
  and what it refuses (`text` other than the title, `quorum.text`, any
  other `outage_rule`, labels over 24 characters); every approval's
  challenge starts with a label the service sets.
- **0.12.5 (2026-10-30):** §3.3: the service list has no limit on the
  number of services or keys (a list that only grows would have kept
  them forever), only a cap of 4,194,304 bytes; a vault given a list it
  can't take keeps the last one it verified. Replaces 0.12.4's bounds.
  No change to the vectors.
- **0.12.4 (2026-10-30):** spelled out with the member vault's
  checks (VAULT-MESSAGING §10.19): `record_at` at or before `opens_at`
  (§3.1); an extension's outage has `from` before `to` and a `source`
  of 1–1,024 bytes, and the document is at most 65,536 bytes (§8.5);
  what keeping a service list's entries means, and the list's bounds
  (§3.3); an unsigned refusal's `refusal_sig` is `null` (§4.2); the
  Rekor entry type and the trusted root's form (§8.5). No change to the
  vectors.
- **0.12.3 (2026-10-30):** §11 adds the anchor-bundle vector, captured
  from staging. No change to the documents or the other vectors.
- **0.12.2 (2026-10-30):** §3.2 names how a vault advertises the vote
  feature (VAULT-MESSAGING 0.81.0 `features`). No change to the
  documents or the vectors.
- **0.12.1 (2026-10-30):** §4.2 lists the `vote.status` answer as
  the service sends it (`proposal_sig` and `bundle`, and every member
  but the ballot's always present); §4.1 says what the vault answers and
  that the service drops it, and what `results_hash` is hashed over;
  `bad_ballot` after a rotation may be retried once with a new
  `cast_sig`. No change to the documents or the vectors.
- **0.12.0 (2026-10-30):** the proposal's bounds are the same as a
  member vault's (§3.1): each choice label 1–200 bytes, `quorum.text`
  and `outage_rule` at most 1,024 bytes each, `eligible` at least 1, and
  the document at most 65,536 bytes. No change to the vectors.
- **0.11.1 (2026-10-30):** `counts.unhandled` covers the window
  `[opens_at, closes_at)` and includes messages the relay dropped
  unhandled; a message's 24-hour wait doesn't restart when it comes
  back. No change to the documents or the vectors.
- **0.11.0 (2026-10-30):** the results' counts gain `unhandled`: how
  many messages from before the close the count went ahead without,
  after waiting 24 hours for a message left unacked (owner decision
  2026-10-30). The vectors change with it (the results document).
- **0.10.1 (2026-10-29):** a member must have signed in once before
  voting (`not_signed_in`): a credential key named by the ballot itself
  proved nothing, since the service could make up both the key and the
  signature. The `credential_key` field is gone.
- **0.10.0 (2026-10-29):**
  - Ballots carry an unpublished `cast_sig` under the member's
    credential key, so the organisation's record proves who cast each
    ballot.
  - Retries are idempotent before the window check; `vote.status`
    (signed, and replacing `vote.request`) recovers a ballot after a
    restore or a lost answer.
  - Accepted ballots are kept write-once outside the table.
  - Refusals name the connection, the tag and the request, and use the
    relay's time; a `late` refusal; collection ends by the relay's
    ordering.
  - Ed25519 rejects a small-order `R`; labels carry their own `0x00`,
    as `suite.Sign` signs `label ‖ m`.
  - Results in two parts with a rows Merkle root, so the vault needs only
    its row; the vault's check has an "unconfirmed" state.
  - `removed_may_vote`; the site's signature on the service list;
    message body types; §9.2 lists every known limit.
  - The `vk` uniqueness and `ballots ≤ eligible` checks are gone.
  - Members are told before voting that the service sees their vote;
    the window is at most 7 days.
- **0.9.0 (2026-10-29):** owner decision: pseudonymous signed ballots
  over the member's connection, final; the secret-ballot machinery and
  the relay revision gone.
- **0.2.0–0.8.0 (2026-10-28 and 29):** successive secret-ballot designs
  with blind certificates, superseded by 0.9.0.
- **0.1.0:** first full draft.
