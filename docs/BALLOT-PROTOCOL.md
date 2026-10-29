# Ballot Protocol

**Status:** 0.8.0 (2026-10-29), for review before more ballot code
(MEMBER-SERVICE-PLAN §10, item 5.0). The plan-level design is
MEMBER-SERVICE-PLAN §8. This document marks two kinds of choice, all
listed in §12 for the owner to decide before code:
- **(chosen; differs from the plan)**: where it departs from the plan.
- **(chosen; not in the spec)**: what the plan and the specifications
  leave open.

The message types here (§4–§6) are not yet in VAULT-MESSAGING. Today it
lets a service connection send only `connection.authenticate.challenge`
(with a known `purpose`) and the upkeep and profile types. A member's
vault sends a service only `connection.authenticate.response` and
`.rotated`, upkeep and profile (VAULT-MESSAGING §6.4 "Service
connections", 0.69.0). Votes are listed there as planned, not specified
(§1.1). Item 5.1 registers the types of both directions there, with
wire vectors; this document is its source. The relay's part, admission
tokens and the mix, is a RELAY-PROTOCOL revision (§3.3).

**Two kinds of vote.** A proposal is binding or not (§3.1), and the two
run differently:

| | Non-binding | Binding |
|---|---|---|
| Eligible | The roster at `record_at`, each with a record tag (§3.2) | The same |
| Members of record | All the eligible | The eligible whose vault registered a record key before `register_until` (§3.5) |
| Certification | At opening, automatically (§5.2) | At the member's first cast (§5.2) |
| Deposits | To the ballot mailbox, with admission tokens the relay checks (§3.3) | To the mix, an attested enclave, with admission tokens it checks; it forwards each voter's last ballot at the close, shuffled (§3.3) |
| Deposits per voter | One per cast | Exactly `max_casts` (§6.4) |
| A member who doesn't vote | Their vault declines after the close (§6.5) | Nothing: they never certify |
| After the close | The service publishes | The service publishes; if it doesn't, a timelocked key lets anyone count (§7.4) |

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only a member of record obtains a certificate, one per proposal. |
| One vote | At most one counted ballot per certificate: the valid ballot with the highest `seq` for a voting key counts (§7.2). A member can change their vote until close by casting again, up to `max_casts` times. |
| Secrecy of the choice | **Binding votes:** no one can tell how a member voted: not the service vault (which is also the ballot box), the relay, the vault hosts, the mirror or the site. The mix runs in an attested enclave; its secrecy rests on that enclave and its published code (§3.3, §9.2). **Non-binding votes:** the same against the service from the ballot alone, but a ballot's arrival time is a link for whoever knows when the member was active, and VettID's operator can join host and relay records (§9.1, §9.2). Each proposal's `statement` says which applies. **Not secret in either:** *whether* a member voted (§9). A choice is hidden only among those who voted, so a vote with very few voters hides little; the `statement` says so. |
| Results only at close | No one sees a tally before the close (§7.1). A dishonest box could open deposits early in a non-binding vote; in a binding one the mix holds them. |
| Verifiability | A member confirms that their ballot is counted as cast, or their decline recorded, and that everyone sees the same documents (§8.3). An observer confirms that every counted ballot has a valid certificate, that no voting key counts twice, the counts of §8.4, and the tally. |
| Publicity | Every proposal and its documents are published on votes.vettid.org and anchored in Rekor under the service's listed anchor key (§3.4), so a member learns of a proposal without the service, and a forked document is visible to anyone watching that key. Binding votes add an independent mirror. |
| Availability | No one but the member can stop an eligible member from casting a counted ballot. Each member holds only their own admission tokens (§3.3). Against the service itself the protocol detects rather than prevents (§10), and in a binding vote the service can't cancel the count after the close (§7.4). |
| Receipt-freeness | Out of scope (owner decision). The vault's post-vote check (§8.3) shows the member their counted choice, and so works as a receipt. Casting again gives no protection against a coercer who checks the outcome. |

## 2. Notation and primitives

- `‖` is concatenation. `u16`, `u32` and `u64` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- **Labels** follow the VMS convention (VAULT-MESSAGING §4.1): ASCII
  strings embedding the version, `vettid/vote/1/...`. Every signature
  the service identity key makes, in VMS and here, is over a
  label-prefixed string, so the two can't be confused.
  **(chosen; differs from the plan:** the plan's `"vettid-vote-v1"`
  follows vettid-dev.)
- **Signatures:** `Sign(sk, label, m)` is `suite.Sign` from vettid-vault
  `vms/suite`, Ed25519 over `label ‖ 0x00 ‖ m`.
- **Hashed strings** that start with a label have the `0x00` written
  out. **HKDF `info`** values are the label's ASCII bytes with no
  separator, followed by `u32(i)` where an index is shown (§5.1).
- **Ed25519 verification,** by every verifier (the service vault, the
  member vault, observers and the site), is exactly:
  1. `A` (the public key) and `R` are 32 bytes whose `y` is below p, and
     not `x = 0` with the sign bit set;
  2. `[8]A` is not the identity (no small-order key);
  3. `S < L`;
  4. `[S]B = R + [k]A`, cofactorless, with `k = SHA-512(R ‖ A ‖ m) mod L`.

  Go's `ed25519.Verify` does steps 3 and 4, and Go's point decoding
  accepts a non-canonical `y`, so Go code makes steps 1 and 2 itself.
  §11 item 8 has vectors for each rule.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
  Another form is refused.
- **Documents** (the proposal, the roster, an extension, the closing,
  the mix list, the results, the service list; §8.5) and **deposit
  bodies** are JCS (RFC 8785). A verifier parses strictly
  (VAULT-MESSAGING §5.3: no duplicate names), then re-serializes per RFC
  8785 and refuses the bytes unless they are identical. Documents are
  signed with a detached signature over a string that contains
  `H(document bytes)` (§8.5). **(chosen; not in the spec.)**
  - Times in them are Unix seconds, as JSON integers.
  - Binary values are standard base64 with padding (VAULT-MESSAGING
    §5.3).
  - **Message bodies** follow VAULT-MESSAGING §5.3; a document travels in
    a body as the base64 of its bytes. Where a signature covers a
    message body, it covers `H(JCS(body))`.
- **Sorting** of tags, keys and other binary values is by their raw
  bytes, never by their base64.
- **The signing key:** the service identity key that signs a proposal
  signs every document and message of that proposal. A service vault
  starts no `identity.rotate` from a proposal's creation until its
  results are published, or `count_until` + 7 days, whichever is first.
- **Blind signatures** are RFC 9474 RSABSSA-SHA384-PSS-Randomized: RSA
  with a modulus of exactly 2048 bits, `e = 65537`, SHA-384, MGF1-SHA-384,
  salt length 48, and a 32-byte message prefix.
  - The key is an id-RSASSA-PSS SubjectPublicKeyInfo carrying exactly
    those parameters, the form RFC 9578 §6.5 specifies for Privacy Pass
    (RFC 9474 §6.2 requires the OID; RFC 4055 §3.1 defines the
    parameters). The SHA-384 AlgorithmIdentifiers omit their parameters
    (RFC 5754 §2), and the trailer field is the default. The exact DER
    of a fixed key is a vector (§11 item 2). The member vault parses it
    by hand and refuses anything else; Go's `x509` does not parse it.
  - **The vault's key checks:** size and exponent; no prime factor below
    2^16 (trial division); and, when blinding, RFC 9474's checks that the
    encoded message and `r` are coprime to n. A failure of either reveals
    a factor of n: it is published evidence that the key is malformed.
  - A key is used for one purpose of one proposal only (RFC 9474 §6.2):
    certificates, admission tokens or report tokens.
  - The service vault uses `cloudflare/circl` `blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` in-repo with
    `math/big`, with a constant-time inverse of `r`. vettid-vault adds no
    third-party code to the enclave (vettid-vault README; V3-NOTES).
  - RSA-2048 is the plan's choice: the key lives for one vote and is
    destroyed at publication. Blinding hides the message whatever the
    signer's computing power (RFC 9474 security considerations).
- **Anchoring** uses ECDSA P-256 with SHA-256 (FIPS 186-5), under the
  service's anchor key (§3.4). It is what Rekor's `hashedrekord` and the
  standard Sigstore tools verify; Ed25519 there would have to be its
  pre-hashed variant.
- **Timelock** is drand's tlock (identity-based encryption to a future
  round of drand's `quicknet` chain), whose Go library the drand team
  maintains. A ciphertext to round `R` opens for anyone once drand
  publishes round `R`, and for no one before (§7.4).
- **The seal** is the VMS v2 envelope in sealed mode (§6.3).

## 3. Proposal

### 3.1 Contents

The proposal is a document (§8.5 has the schema).

| Field | Meaning |
|---|---|
| `proposal_id` | A ULID. |
| `service` | The service identity key that signs it (§2). |
| `title`, `text` | UTF-8; `title` ≤ 200 bytes, `text` ≤ 16 KiB. |
| `choices` | 3–17 entries `{id, label}`, in display order, with `id` matching `[a-z0-9-]{1,32}` and unique: at least two real choices, and `abstain`, which is reserved and always present for a member who wants to be counted without choosing. |
| `quorum` | The plan's quorum rule, as text, and the number of counted ballots it needs. `abstain` ballots count toward it; conflicts don't. |
| `binding` | Whether the vote is binding (the table at the top). |
| `record_at` | The roster snapshot, at or before the proposal's creation (§3.2). |
| `register_until` | Binding only: the end of registration (§3.5), at least 24 h after the proposal is published. |
| `opens_at` | Members can vote. For binding votes, at or after `register_until`. |
| `closes_at` | The last moment to cast: ballots deposited before it count. `closes_at − opens_at ≤ 7 days`. |
| `count_until` | Non-binding: `closes_at` + 26 h, the end of declines (§6.5). Binding: `closes_at` + 2 h. The box collects until then (§7.1). |
| `eligible`, `record_root` | The number of eligible members and the Merkle root of their record tags (§3.2). |
| `cert_key` | The RSA public key for certificates (§2). |
| `admission` | The admission key, the number of tokens per member, and where deposits go (§3.3). |
| `report_key` | The RSA public key for report tokens (§10.2). |
| `ballot_kem` | The box's KEM public key for this proposal. |
| `max_casts` | How many times a member may cast: 1–8. |
| `mirrors` | Binding only: the independent mirrors (§3.4), from the service list. |
| `escrow` | Binding only: `ballot_kem`'s secret, timelocked (§7.4). |
| `outage_rule` | The rule of §10.2, as text. |
| `statement` | What the vote does not protect, in words for members: the links of §9 that apply to it. |

- **Signature:**
  `proposal_sig = Sign(service IK, "vettid/vote/1/proposal", H(proposal_bytes))`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds the certificate,
  the tokens and the ballot to this one proposal (§5.1, §6.1).
- **Publicity:** the proposal is anchored and published before it is
  sent to anyone (§3.4). A vault certifies only under an anchored
  proposal, and deposits only under the published one (§5.2, §6.4).

### 3.2 Eligible members and record tags

- **Eligible members** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended, and with
  a vault that advertised the vote feature (how it advertises is item
  5.1's, and is fixed before any vote). One connection is one member.
  Two consequences, stated with the proposal:
  - A person holding several VettID accounts is several members.
  - A member whose connection is replaced after `record_at` (they
    connect again, for example after a suspension) is not eligible for
    this proposal.
- **Record tags:** for each eligible member the service vault draws a
  32-byte random `record_secret`. The member's tag is
  `record_tag = H("vettid/vote/1/record" ‖ 0x00 ‖ proposal_id ‖ record_secret)`.
  `record_root` is the RFC 6962 root (§8.2) over the tags, sorted
  bytewise, and `eligible` their number.
- **Delivery:** each member receives, in `vote.proposal` (§4.1), their
  `record_secret` and an inclusion proof of their tag, with
  `tree_size = eligible`. The vault checks it at once, against the root
  in the signed proposal (RFC 9162 §2.1.3.2).
- **What the results show against each tag:** whether it was issued a
  certificate (non-binding), or which record key registered it (binding;
  §3.5). Each member's vault checks its own tag (§8.3).
- The service knows every `record_secret`, so it can mark any tag. What
  stops it is the check by that member's vault. A member whose vault
  never checks is room the service can use; each proposal's `statement`
  says so.
- The service keeps the record secrets until the proposal leaves the
  site's index (§3.4), so a late vault can still ask for its proposal
  and check.

### 3.3 Admission tokens and the mix

**(Owner decisions 2026-10-28 and 2026-10-29:** admission tokens for
every vote; for binding votes, the mix, run by VettID in an attested
enclave.) They are a RELAY-PROTOCOL revision (vettid.org), to be
specified there. What this protocol needs from it:

- **In the proposal:** `admission = {key, tokens, to}`.
  - `key` is an RFC 9474 key (§2) for this proposal's admission tokens
    only.
  - `tokens = max_casts + 2`: one per cast, and two spare.
  - `to` is the ballot mailbox (relay URL and mailbox id, a relay
    keypair for this proposal only), and for a binding vote also the
    mix (relay URL, mailbox, receipt key and enclave measurements).
- **Issuance:** with the certificate (§5.2), the box blind-signs
  `tokens` token values for the member, the same number for everyone.
  No token is issued later, so issuance says nothing about how often a
  member casts.
  - Token `i` (from 0) is `token_value_i`, 32 bytes, signed as
    `token_msg_i = "vettid/vote/1/token" ‖ 0x00 ‖ proposal_hash ‖ token_value_i`,
    with its own prefix, salt and blinding factor (§5.1).
- **Checking:** the receiver of a deposit (the relay for the ballot
  mailbox in a non-binding vote, the mix in a binding one) verifies the
  token under `key`, refuses it if spent, and otherwise spends it.
  - It refuses deposits before `opens_at`, and at or after `closes_at`
    by its own clock, as extended by any extension published on
    votes.vettid.org (§10.2).
  - The same token with the same bytes is answered the same way again,
    so a retry after a lost answer costs nothing.
  - The relay learns nothing about the member, and the box nothing
    beyond the token's validity.
- **The mix (binding):**
  - **It runs in an AWS Nitro Enclave,** from open-source code built
    reproducibly. Its enclave measurements (PCR0–2) are published on the
    service list (§3.4) and in the proposal. Before its first deposit,
    the vault verifies the enclave's attestation document (COSE_Sign1
    under AWS's Nitro root, pinned in the vault's release config)
    against those measurements, and takes from it the enclave's
    deposit key.
  - **A deposit** is sealed to that deposit key (HPKE, VMS suite 2), so
    the host around the enclave sees only ciphertext:
    `{token, chain_tag, envelope}`, where `chain_tag` is derived per
    voter (§5.1). The vault sends its deposits one at a time, each after
    the previous one's receipt.
  - **The receipt:**
    `mix_receipt = Sign(mix receipt key, "vettid/vote/1/mix-receipt", proposal_hash ‖ chain_tag ‖ u32(counter) ‖ u64(accepted_ms) ‖ H(envelope))`,
    with the mix's time in milliseconds and the chain's counter, from 1.
    The receipt key is generated inside the enclave and named in its
    attestation.
  - **At the close** (§7.1), it keeps only the envelope with the highest
    counter of each `chain_tag`, erases every other deposit and every
    chain tag, forwards the kept envelopes to the ballot mailbox in a
    random order with no times, pacing so that the mailbox's 10,000
    messages are never exceeded, and publishes the **mix list**: the
    Merkle root and sorted hashes of the forwarded envelopes, with the
    envelopes themselves as a bulk file, signed with its receipt key
    (§8.5).
  - So the box sees one envelope per voter, and nothing of a voter's
    earlier casts; and nothing outside the enclave ever pairs a host or
    a time with an envelope.
  - The relay accepts the mix's batch under the mix's own credential.
  - VettID runs it for the first binding votes. A second mix, run by an
    independent party in sequence after it, can be added later; then
    either one being honest is enough (§9.2).
- **Effects:** a member can spend only their own tokens, so no member
  can exhaust anything for others; distribution is one message per
  member, at certification, whatever the number of members.
- **Until the revision exists,** no vote runs.

### 3.4 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public site run by VettID, separate from every
service vault (its design: vettid/votes, docs/VOTES-SITE.md).

- **The service list** (§8.5) is a document the site signs and anchors
  under its own anchor key, which is pinned in the vault's release
  config. For each registered service it names its identity keys, its
  anchor keys with their certificates, and the approved mirrors and
  mixes with their keys and enclave measurements. VettID maintains it;
  a service is added by the owner.
  - **Append-only, and checked:** each version has a higher `version`,
    the hash of the previous one, and every entry of the previous one.
    A new identity key carries a rotation signature from the service's
    previous identity key. A vault keeps the latest version it has
    verified, and accepts a new one only if its anchor bundle verifies,
    its version is higher, it chains to the one held, it keeps every
    entry, and every added identity key is signed by the previous one.
    The site's own watcher and the mirrors apply the same rules.
  - **A vault accepts a proposal's `service` only if** it is its
    connection's current identity key, or a past one it learned through
    `identity.rotate`. The list adds the anchor keys; it can't add an
    identity key that the vault would accept on its own.
- **The anchor key:** each service has one long-lived ECDSA P-256 anchor
  key, sealed in the service vault's keystore, certified by its
  identity key:
  `anchor_cert = Sign(service IK, "vettid/vote/1/anchor-key", H(anchor_key SPKI DER))`.
  Every document of every proposal of the service is anchored under it.
  A mix's anchor key is certified likewise by its receipt key.
- **The documents,** in order of upload:
  1. the proposal, before it is sent to any member;
  2. the roster (binding), after `register_until` and before `opens_at`
     (§3.5);
  3. any extensions (§10.2);
  4. the closing (§7.1);
  5. the mix list (binding; §3.3), uploaded by the mix;
  6. the results (§8.1).
- **The anchor:** before uploading, the service vault (the mix, for its
  list) anchors each document in Rekor: a `hashedrekord` entry with
  `H(document bytes)` and an ECDSA P-256 signature over the document
  bytes, with an RFC 3161 timestamp from a timestamp authority in the
  trusted root. The Sigstore bundle (§8.5 "Rekor profile") goes up with
  the document and with the message that carries it to vaults.
- **What the site checks** before it publishes an upload: the service is
  on the list; the signatures; the exact JCS bytes; the anchor bundle
  under a listed key, and its timestamp; the order above; the document's
  fields against the proposal.
- **Write-once:** each document has one path. The site accepts the same
  bytes again, refuses different bytes, and never changes or removes a
  document.
- **Discovery:** the site keeps an index of proposals open or closed
  within the last 30 days. The app fetches the whole index, with no
  session, and hands the vault the entries of its services. It then
  fetches the pages of those proposals on a fixed hourly schedule with
  random jitter, never in response to a cast, so the fetches say nothing
  about when the member votes.
- **Watching:** the site watches every log the Rekor profile pins for
  entries under every listed anchor key (Rekor's v2 log has no search by
  key, so watching means reading the whole log).
  - An entry that matches no published document is a **pending**
    alarm. A later upload of a valid document with that digest clears
    it, and is recorded as late.
  - Two anchored documents for the same slot (the proposal, the roster,
    extension `n`, the closing, the mix list, the results) with
    different bytes is a **fork**, published on the service's page.
  - Entries with the same digest are one document.
- **Time anchor:** for binding votes the site also stamps each
  document's hash with OpenTimestamps, upgrades the proof once Bitcoin
  confirms it, and publishes it. Vaults don't wait for it.
- **Independent mirrors (binding):** a binding vote names at least one
  mirror from the service list, run by a party other than VettID and
  the organisation. A mirror holds no secret (§7.4). **(Owner decision
  2026-10-29:** the first is a public GitHub repository owned outside
  VettID.) It runs the open-source watcher from vettid/votes on a
  schedule in GitHub Actions and publishes with GitHub Pages, so its
  code, every run's log and every output are public:
  - it watches the same logs for the listed anchor keys, and raises
    pending alarms and forks by the same rules;
  - it fetches each document from votes.vettid.org and verifies it, and
    also accepts any anchored document uploaded by anyone, so a vault
    can give it what the site withholds;
  - it republishes everything with its own index.

  Anyone may run more; the app checks the mirrors the proposal names. A
  proposal of its service on one and missing from another is evidence,
  and the vault asks for it (§4.1). A mirror that doesn't answer is
  recorded (`mirror_unreachable`), and the vote goes on.
- **What the site can and cannot do:**
  - It cannot alter a document or serve a fork that no one sees: a fork
    must be anchored under a watched key.
  - It could withhold a document, or refuse a reader. A vault checks
    anchors offline from the bundles its messages carry, so this delays
    the site checks rather than stopping a vote (§6.4), and in a binding
    vote the mirror has the documents.
  - It is independent of an organisation's service vault, not of VettID.
    For VettID's own member service, a non-binding vote's guarantee rests
    on VettID and on outside watchers of the anchor key, and its
    `statement` says so; a binding vote has the mirror.

### 3.5 Registration (binding)

**(Owner decision 2026-10-29.)**

- **Who may register:** the eligible members (§3.2).
- **How:** on a valid `vote.proposal`, the vault derives a record key
  `rk` for the proposal (§5.1), records "registering" in its backed-up
  participation record (§5.1), and sends
  `vote.register {proposal_id, record_tag, record_key, register_sig, report_blinded}`,
  with
  `register_sig = Sign(rk, "vettid/vote/1/register", proposal_hash ‖ record_tag)`.
  It needs no member action, and retries until `register_until`. A
  second registration from the same connection before `register_until`
  replaces the first (after a restore, §6.6). The answer carries the
  member's report token (§10.2).
- **The roster:** after `register_until` the service publishes the
  roster document: every eligible record tag, each with the record key
  and signature that registered it, or none; their Merkle root; and
  `members_of_record`, the number registered (§8.5). It is anchored and
  published before `opens_at`. Each registered vault gets its hash and
  bundle in `vote.roster`, and fetches the roster itself from the site.
- **The vault checks** that its tag carries its record key, or, if it
  never registered, no key, before it deposits and again in §8.3. A
  mismatch is evidence.
- **Members of record** are the tags with a key. A member whose vault
  was locked through the whole window can't vote in this vote; the app
  tells them. The outage rule covers the window (§10.2).
- **What it closes:** the service cannot claim a registered member
  certified, since issuance is that member's own signature (§5.3), and
  it cannot register a member who didn't without that member's vault
  seeing its tag carry a key. Room is left only in the tags of members
  whose vault never checks (§9.3).

## 4. Messages from the service

Session-mode messages on the service connection, in the standard VMS
inner (VAULT-MESSAGING §5.3). Each is answered with a response that
names it (`re`), so the service knows it arrived. A vault without the
vote feature answers `unsupported_type`, which today's rules would
instead drop and audit. That needs the §6.4 change of item 5.1.

**Refusals** of the vault's requests (§5.4) are signed:
`refusal_sig = Sign(service IK, "vettid/vote/1/refusal", lp(proposal_id) ‖ u64(now_ms) ‖ lp(member) ‖ lp(type) ‖ lp(code) ‖ H(JCS(request body)))`,
in the error body as `{refusal_sig, now_ms}`, where `member` is the
connection's record tag (or empty if it has none), `type` the request's
type and `code` the error code. A vault treats an unsigned refusal as no
answer. Only the refusals §10.2 names are evidence that the service
misbehaved.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, bundle, record_secret, record_proof}`
- `proposal` is the §3.1 bytes, in base64; `bundle` its Sigstore bundle;
  `record_secret` and `record_proof` `{index, tree_size, path}` (§8.5)
  are the only per-member part.
- **The vault keeps** a proposal whose signature verifies under an
  identity key it accepts (§3.4) and whose bundle verifies under a
  listed anchor key (§8.5 "Rekor profile"). Under one `proposal_id`, it
  uses the one the site publishes (§6.4) and keeps any other as evidence
  (§8.3). It certifies only once one is chosen this way, or, with the
  site unreachable, under the only anchored one it holds.
- It records the `proposal_id` in its participation record (§5.1), and,
  for a non-binding vote, asks for its report token with
  `vote.report-token` (§5.4).
- **Requested:** a vault that sees a proposal of its service on
  votes.vettid.org or a mirror but holds none sends `vote.request
  {proposal_id}` (§5.4), and the service answers with `vote.proposal` or
  refuses.

### 4.2 `vote.roster` (binding)

`{proposal_id, roster_hash, roster_sig, bundle}`, sent after
`register_until` to every registered vault, which fetches the roster
from the site and checks it against the hash.

### 4.3 `vote.extended`

`{proposal_id, extension, extension_sig, bundle}` (§10.2). The vault
uses it once its bundle verifies. It resumes pending and late deposits,
and redraws its deposit schedule (§6.4).

### 4.4 `vote.closing`

`{proposal_id, closing, closing_sig, bundle}`, sent when the closing is
published (§7.1). Vaults also learn it from the site.

### 4.5 `vote.closed`

`{proposal_id, results_hash}`. The vault doesn't depend on it: it runs
its check at `count_until` + 1 h anyway (§8.3).

## 5. Certification

### 5.1 The proposal seed and what is derived from it

- **The proposal seed** is 32 random bytes the vault draws when it first
  keeps a proposal (§4.1), and stores in its DEK-encrypted state as
  feature data (VAULT-MESSAGING §3.3) before using it. Because it is
  opened by the vault's unlock rather than by the password, the vault
  can register, certify and decline on its own.
  - The member's choice still needs the member's approval (§6.2).
  - **The seed and the vote state** (the voting key, the choice, the
    ballot, the evidence) **are kept out of the vault's backups,** and
    are erased once the §8.3 check has passed, leaving only its outcome.
    If the check fails, the evidence is kept for 30 days and then erased;
    it links the member to their ballot while it exists, and the vault
    says so. Without a passed check, they are erased 7 days after
    `count_until`.
  - So a later compromise of the vault, or of a backup, exposes no
    finished vote.
  - **(chosen; not in the spec;** it replaces 0.5.0's single vote root.)
- **The participation record** is backed up: for each proposal, its
  `proposal_id`, the stage reached (registered, asked, certified, cast,
  declined), the request hash and the record key's public half. It holds
  nothing that links a ballot. It is erased with the rest.
- **Derived values:** each is
  `HKDF-SHA256(ikm = proposal_seed, salt = proposal_hash, info, L)`,
  with `info` the ASCII label (and `u32(i)` where shown):

  | Value | `info` | `L` |
  |---|---|---|
  | `seed`, whose Ed25519 key is `vk` | `vettid/vote/1/voting-key` | 32 |
  | `msg_prefix` | `vettid/vote/1/msg-prefix` | 32 |
  | `pss_salt` (the salt of RFC 9474's EMSA-PSS encoding) | `vettid/vote/1/pss-salt` | 48 |
  | `blind_seed` | `vettid/vote/1/blind` | 32 |
  | The record key `rk`'s seed (binding) | `vettid/vote/1/record-key` | 32 |
  | `chain_tag` (binding) | `vettid/vote/1/chain` | 32 |
  | Token `i`'s value | `vettid/vote/1/token-value` ‖ `u32(i)` | 32 |
  | Token `i`'s prefix | `vettid/vote/1/token-prefix` ‖ `u32(i)` | 32 |
  | Token `i`'s salt | `vettid/vote/1/token-salt` ‖ `u32(i)` | 48 |
  | Token `i`'s blind seed | `vettid/vote/1/token-blind` ‖ `u32(i)` | 32 |
  | The report token's value | `vettid/vote/1/report-value` | 32 |
  | The report token's prefix | `vettid/vote/1/report-prefix` | 32 |
  | The report token's salt | `vettid/vote/1/report-salt` | 48 |
  | The report token's blind seed | `vettid/vote/1/report-blind` | 32 |

  So a retried request is identical, and these values stay secret
  because the seed is. The report token is blind-signed under
  `report_key` over
  `report_msg = "vettid/vote/1/report" ‖ 0x00 ‖ proposal_hash ‖ report_value`.
- **The blinding factor `r`** comes from a blind seed by rejection
  sampling. For `ctr = 0, 1, 2, …`:
  1. `c = SHA-384(blind_seed ‖ u32(ctr) ‖ 0x00) ‖ … ‖ SHA-384(blind_seed ‖ u32(ctr) ‖ 0x05)`,
     which is 288 bytes, truncated to its first 256.
  2. `r = OS2IP(c)`, taken if `0 < r < n`.
  3. Otherwise the next `ctr`.
  4. If `gcd(r, n) ≠ 1`, the key is malformed (§2): the vault stops and
     keeps `r` as evidence.

  The expected number of tries is under 2.
- **Blinding:** `blinded = r^e · OS2IP(EMSA-PSS-ENCODE(msg_prefix ‖ cert_msg; pss_salt)) mod n`
  (RFC 9474 §4.2 with the salt and `r` fixed, including its coprimality
  check). Tokens likewise, under their keys.
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_hash ‖ vk`.

### 5.2 Request and answer

- **When:**
  - **Non-binding:** at once on keeping a proposal (§4.1), at or after
    `opens_at`, with no member action. A vault unlocked at `opens_at`
    certifies then; a locked one when it is next unlocked, which may be
    just before its member casts (a link the `statement` names, §9.1).
  - **Binding:** at the member's first cast, just before the first
    deposit.
  - Either way it is a vault step, not an ask (VAULT-MESSAGING §10.4.1).
- **How:**
  1. The vault computes `blinded` and the `tokens` blinded token values,
     and records "asked", with the request hash, **before** sending
     `vote.certify {proposal_id, blinded, admission_blinded}`; for
     binding votes with
     `certify_sig = Sign(rk, "vettid/vote/1/issued", proposal_hash ‖ request_hash)`,
     where `request_hash = H(blinded ‖ admission_blinded_0 ‖ …)`.
  2. **The service vault** checks:
     - the proposal is open: `opens_at ≤ now < closes_at`;
     - the connection is a member of record and still active (binding:
       its registered `rk`, and `certify_sig` verifies);
     - this connection has no certificate yet, or has one for the same
       request.

     It records the issuance with a conditional write that succeeds only
     if no issuance exists for the connection, or one exists for the same
     request, and also writes it, write-once, to a store outside its
     table (§7.1). Only then does it sign: `blind_sig = BlindSign(cert_sk, blinded)`,
     and the tokens likewise.
     - It answers `vote.certified {proposal_id, blind_sig, admission_sigs}`.
     - A repeated request gets the stored answer.
     - Refusals are signed (§4): `already_certified`, `not_open`,
       `closed`, `not_of_record`, `not_active` or `bad_signature`.
  3. **The vault** computes `cert_sig = Finalize(cert_key, msg_prefix ‖ cert_msg, blind_sig, r)`,
     which includes verifying it, and the tokens likewise. It keeps
     `(cert_prefix = msg_prefix, cert_sig)` and the tokens, and records
     "certified".
     - If `Finalize` fails, it keeps `blinded` and `blind_sig` as
       evidence and reports `certification_failed` (§8.3). A retry would
       be identical, so it doesn't retry.
     - With no answer, it retries the same request with backoff until
       `closes_at`.
     - On `not_open`, it retries with backoff from `opens_at` + 1 min
       until `closes_at`, since its clock may lead; that refusal is not
       evidence.

The service sees `blinded` and `blind_sig`, which tell it nothing about
`vk`, `cert_sig` or the tokens without the blinding values.

### 5.3 The issuance list

The service vault records `connection, proposal_id, request, answer`
(the conditional write above). At publication (§8.1) it publishes:
- **non-binding:** which record tags were issued (§3.2);
- **binding:** each issuance as `{record_key, request_hash, certify_sig}`,
  which observers verify against the roster.

Then it deletes the records.

### 5.4 Messages from the member's vault

| Type | Body | Answer |
|---|---|---|
| `vote.register` | `{proposal_id, record_tag, record_key, register_sig, report_blinded}` (binding) | `{proposal_id, report_sig}`, or a refusal `not_eligible`, `closed`, `bad_signature` |
| `vote.report-token` | `{proposal_id, report_blinded}` (non-binding) | `{proposal_id, report_sig}`, or a refusal `not_eligible`, `already_issued` |
| `vote.certify` | `{proposal_id, blinded, admission_blinded, certify_sig?}` | `vote.certified {proposal_id, blind_sig, admission_sigs}`, or a refusal (§5.2) |
| `vote.decline` | `{proposal_id, vk, cert_prefix, cert_sig, decline_sig}` (non-binding; §6.5) | `ok`, or a refusal `not_certified`, `not_closed`, `too_late`, `bad_signature` |
| `vote.request` | `{proposal_id}` | `vote.proposal` (§4.1) as the response, or a refusal `not_eligible`, `unknown_proposal` |

A report token is issued once per eligible connection, by the same
conditional write as a certificate; a repeated identical request gets
the stored answer.

## 6. Casting

### 6.1 The ballot

- `ballot_msg = proposal_hash ‖ u32(seq) ‖ lp(choice_id)`
- `ballot_sig = Sign(vk, "vettid/vote/1/ballot", ballot_msg)`
- **`seq`** orders a member's casts without counting them:
  - the first cast draws `seq` uniformly from [1, 2^30);
  - each further cast adds a step drawn uniformly from [1, 2^16];
  - the vault stores the new `seq` before signing with it.

  The highest counts, so the order holds however deposits arrive, and
  the published `seq` says nothing about how often the member cast.
- **No timestamp.** **(chosen; differs from the plan:** a signed time
  would be published with the ballot.)

### 6.2 Choosing

- **Casting:** the member casts in the app, at any time from `opens_at`
  to `closes_at`, up to `max_casts` times. The vault signs only with the
  member's approval inside the credential's unlock window
  (VAULT-MESSAGING §3.5.3), and sends the ballot at once (§6.4). It is
  not an ask.
  - The app refuses to cast in the last two minutes before `closes_at`,
    by the vault's clock, so that skew doesn't drop a ballot.
- **Changing:** a new cast has a higher `seq`, and the highest counts
  (§7.2). **(chosen; not in the spec:** still one counted ballot per
  key.)
- **Not voting:** a member who never casts has no ballot. In a
  non-binding vote their vault declines after the close (§6.5); in a
  binding one it never certifies. **(Owner decisions 2026-10-29;** the
  earlier automatic abstain is gone.)
- **Reminders:** the app reminds the member a day before `closes_at`.

### 6.3 The deposit

- **The seal** is a VMS v2 envelope in sealed mode (VAULT-MESSAGING §5.2,
  §4.3), to `ballot_kem`:
  - `ver` 2, `suite` 2, `mode` sealed, `flags` 0; `sender_kid` all-zero
    (anonymous), `recipient_kid` the kid of `ballot_kem` (§4.4 there);
  - the HPKE `info` is VAULT-MESSAGING's `vettid/vms/2/sealed`, and the
    AAD is the header, as for every sealed envelope;
  - the inner plaintext is **the deposit body, not the §5.3 inner
    object**: it has no `id`, `type` or `ts`, so nothing in it carries
    the time. `ballot_kem` receives nothing else, so the recipient knows
    the format. Item 5.1 registers this exception to VAULT-MESSAGING
    §5.3.
- **`body`** is the JCS bytes of
  `{v: 1, proposal_id, vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`
  (§8.5), padded to exactly 1,024 bytes: `json ‖ 0x80 ‖ 0x00*`
  (VAULT-MESSAGING §5.4's bucket; an honest body is under 700 bytes).
  Every deposit is therefore a 2,180-byte envelope.
- Nothing in the deposit identifies the vault.

### 6.4 Sending it

1. **Site checks.** While a vote is open, the app fetches the proposal's
   page on votes.vettid.org and the mirrors on its hourly schedule
   (§3.4), and the vault checks:
   - the proposal it holds is the published one, and its anchor key is
     on the service list;
   - binding: its tag carries its record key in the roster;
   - any extension on the site is one it holds, and it uses the latest
     `closes_at`.

   A deposit uses the latest check. If no check has succeeded within
   the last 2 hours, the vault deposits on the strength of the bundles
   its messages carried, and records the site checks as deferred, to be
   made in §8.3. Any other failure is evidence (§8.3), and it doesn't
   deposit.
2. **Time.** At once, when the member casts (owner decision 2026-10-28).
   - **Binding:** every voter makes exactly `max_casts` deposits to the
     mix. The first goes when the member first casts. The rest are
     scheduled at times drawn uniformly between then and
     `closes_at − 2 min`, each a fresh seal of the latest ballot. A
     cast again is sent at once, using the next scheduled deposit (and
     replacing a deposit still being retried), and the remaining ones
     are drawn again. A slot missed while the vault was locked is sent
     when it unlocks, the missed ones spread at random over the time
     left; a slot that can't be sent by `closes_at − 2 min` is dropped.
     The mix and the operator can see a voter's fewer deposits as
     "locked or late"; the `statement` says so.
   - The ballot, the certificate, the tokens and the schedule are in the
     vault's encrypted state, and survive a restart.
3. **Token and bytes.** The next unspent admission token. The vault
   stores the envelope and its token before the first attempt, and every
   retry sends exactly those, under a fresh request signature.
4. **Key.** A fresh Ed25519 key for each deposit signs the request
   (RELAY-PROTOCOL §4.1), to the relay or the mix. An admission token
   needs no registered sender. Every attempt is signed anew, with a
   fresh timestamp; a byte-identical request within 90 s is refused as
   a replay.
5. **Outcomes** (the relay's or the mix's answers, as the relay
   revision defines them):

   | Answer | What the vault does |
   |---|---|
   | Accepted | Reads the receiver's time in the answer (the `msg_id` ULID at the relay; `accepted_ms` in the mix's receipt). Before `closes_at`, to the millisecond: records "cast" and keeps `vk`, the certificate, `ballot_sig`, `seq` and any receipt. At or after it: records "late". |
   | Token spent, with the same bytes | Treated as accepted: it was this deposit's own earlier attempt. |
   | Token spent, other bytes; token invalid | Drops the token and uses the next one (a spare), and reports `token_refused`. |
   | `429 rate_limited` | Waits `retry_after`, then retries. |
   | 5xx, network errors | Retries the same bytes, re-signed, with a backoff of up to 5 min. |
   | Mailbox `quota_exceeded` | Retries the same bytes, re-signed, with a backoff of up to 5 min, because the box frees storage as it collects (RELAY-PROTOCOL §7.1). |
   | `replay_detected`, `timestamp_stale`, `signature_invalid` | Re-signs and retries, once for `signature_invalid`, then reports `deposit_failed`. |
   | `400`, `payload_too_large`, `mailbox_unknown` | Reports `deposit_failed` (§8.3). |

   Retries continue until `closes_at`.

### 6.5 Declining (non-binding)

- **Who:** a vault that is certified, has never signed a ballot for the
  proposal, and is not `seed_lost`. Once it has declined it never casts.
- **When:** after the close (§7.1), at a time drawn uniformly over the
  first 24 hours after it. A vault locked then declines when it is
  unlocked. Declines are accepted until `count_until`, two hours after
  the end of that window.
- **How:** `vote.decline {proposal_id, vk, cert_prefix, cert_sig, decline_sig}`
  on the service connection (§5.4), with
  `decline_sig = Sign(vk, "vettid/vote/1/declined", proposal_hash)`,
  retried until `count_until`. The service refuses a decline before the
  close (`not_closed`; the vault retries), whose certificate or
  signature fails (`bad_signature`), from a connection it never
  certified (`not_certified`), or after `count_until` (`too_late`).
- **In the results:** every decline, with its `vk` and certificate. A
  `vk` that both declined and has a ballot is a conflict (§7.2).
- **What it does:** each certified member is accounted for by a ballot
  or a decline. A decline sent before `count_until` that wasn't answered
  `ok` is evidence (§8.3), so a service that drops declines to free
  their certificates is caught.
- It goes over the connection, not to the ballot mailbox, so nothing is
  deposited at a fixed time. It tells the service who didn't vote, and
  their `vk` (which has no ballot); §1 says so.
- **(chosen; not in the spec;** owner decision 2026-10-29, replacing the
  automatic abstain.)

### 6.6 After a restore

A vault restored from backup (the VMS restore event) has its
participation records (§5.1) but no proposal seeds. For every proposal
in them that is open or unchecked, it records `seed_lost`:
- it doesn't cast or decline in it, and runs only checks 1, 2 and 5 of
  §8.3, since its earlier requests can't be recomputed;
- a ballot it cast before the restore still counts;
- an `already_certified` refusal is then expected, not evidence;
- binding, before `register_until`: it registers again with a new seed,
  which replaces its record key (§3.5); after `register_until` it can't
  vote in that proposal;
- the app tells the member what they can no longer do in it.

A restore the operator triggers during a vote therefore costs members
their remaining casts; §10.1 states it.

## 7. The ballot box

### 7.1 Collecting and closing

- **When:** the ballot box (the service vault) collects from `opens_at`
  to `count_until` (non-binding), or until it holds every envelope of
  the mix list (binding), acknowledging each message once its write is
  durable.
- **Sealed until the close:** the box stores each deposit as received,
  with its `msg_id` and token, and opens none until the close.
- **The close is by rule:** if no extension is anchored by `closes_at`
  + 1 h, the vote is closed at that moment, whatever the service does.
  The relay and the mix refuse deposits from `closes_at` on; at the
  close the mix forwards and publishes its list, the box opens what it
  holds and runs §7.2, and vaults decline.
  - The hour lets an outage in the last hour be covered (§10.2).
  - **The closing document** confirms it: the service publishes it at
    the close, anchored, and sends `vote.closing`. Its absence is a
    recorded fault of the service, not a reason to hold the vote again.
- **The arrival cutoff** is `closes_at`, by the receiver's time, the
  same clock the vault reads (§6.4). The relay or the mix enforces it.
- **Publication** waits until the mailbox is empty at `count_until`, and
  then until collects have come back empty for 10 minutes.
  **(chosen; not in the spec.)**
- **Issuance records** are written, write-once, to a store outside the
  table as well (§5.2), so a table restore doesn't lose them.
- **A restore of the service vault's table:**
  - before the close, in a non-binding vote: acknowledged deposits are
    lost. The results say so (`restored: true`), and that counts as the
    service's fault. The vote is held again only if members' evidence
    shows ballots missing (§10.2).
  - in a binding vote, or after the close: nothing is held again. The
    mix list holds every counted envelope (§7.4), and the box counts
    from it.

### 7.2 Checks, in order

1. **Format:** the envelope is 2,180 bytes, its header is as §6.3
   states, it unseals, it has exactly the 1,024-byte padding, and `body`
   is valid JCS.
2. **Proposal and time:** `proposal_id` is this proposal's, and
   (non-binding) the deposit's `msg_id` time is before `closes_at`.
3. **Delivery:** non-binding: it came to the ballot mailbox on a token
   the relay accepted. Binding: it is in the mix list.
4. **Certificate:** `cert_prefix` is 32 bytes, and `cert_sig` verifies
   under `cert_key` for `cert_prefix ‖ cert_msg(proposal_hash, vk)`.
5. **Ballot:** `seq ≥ 1`, `vk` passes §2's checks, `ballot_sig` verifies
   under `vk` for `ballot_msg`, and `choice_id` is one of the
   proposal's.
6. **Repeats,** for each `vk`, over every ballot that passed 1–5 and
   every decline:
   - copies of one `(seq, choice_id)` are one ballot; if their
     `ballot_sig`s differ (only the holder of `vk` can make that), the
     lowest bytewise is kept, and the others are `copies`;
   - if the highest `seq` has two different choices, or the `vk` also
     declined, the `vk` is a **conflict**: neither its ballots nor its
     decline count, and all of them are published (§8.1). Only the
     holder of `vk` can make one, and an honest vault never does
     (§6.1, §6.5, §6.6);
   - otherwise the ballot with the highest `seq` counts, and lower ones
     are superseded.

- **What is kept:** a counted ballot as
  `{vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`.
- **What is not kept:** `msg_id`, the token and `sender` are used for
  checks 2 and 3, then discarded. No log line carries them.
- **Failures** are counted by reason (§8.5) and dropped. Every envelope
  the box received is accounted for once: counted, a copy, superseded,
  part of a conflict, or dropped by a reason.

### 7.3 Watch

- **Alarms:**
  - mailbox use above 20% of its quota (10,000 messages, 32 MiB;
    RELAY-PROTOCOL §7.2);
  - after the close, more than 10% of deposits failing checks 1–4
    (members can cause this with their spare tokens; it is an alarm, not
    evidence);
  - any conflict.

### 7.4 The timelocked key (binding)

**(Owner decision 2026-10-29,** replacing escrow with the mirror.)

- **At creation** the service timelocks `ballot_kem`'s secret (its
  32-byte seed) to the drand `quicknet` round due at `count_until` +
  48 h, the latest any extension can push it (§10.2), and puts the
  ciphertext in the proposal's `escrow` field. No one can open it
  before then, the service's mirrors, the mix and VettID included.
- **With the results** the service publishes `ballot_kem`'s secret, so
  anyone can open the mix list's envelopes and recount by §7.2. That
  reveals nothing new: the mix forwarded only each voter's final
  ballot, and erased the rest (§3.3).
- **If the service never publishes,** anyone opens the escrow once the
  round is out, opens the mix list's envelopes and counts by §7.2. The
  site and the mirrors do it automatically and publish the count, as a
  result the service didn't make.
- **If the escrow doesn't open to `ballot_kem`'s key,** that is
  published as the service's fault. A service that both forges its
  escrow and withholds its results can still void the vote; no one can
  check the escrow sooner without a proof of encryption that this
  version doesn't have (§9.3).
- **So after the close nothing re-runs a binding vote** except a mix
  that fails to publish its list by `count_until` + 24 h (§10.2).

## 8. Publication and verification

### 8.1 Results

- **`results.json`** is a document (§8.5) with:
  - the proposal, the roster, any extensions and the closing, each with
    its signature;
  - every record tag with what it shows (§3.2); non-binding: the
    declines; binding: the issuances (§5.3) and the mix list's root;
  - the counted ballots, sorted by `vk`, and `ballot_root`;
  - the conflicts, with all their ballots and declines;
  - the tally per choice, the counts, the failures by reason, and the
    count of members removed or suspended during the vote.
- **Signature:** detached,
  `results_sig = Sign(service IK, "vettid/vote/1/results", proposal_hash ‖ H(results_bytes))`.
- **Published and anchored** on votes.vettid.org (§3.4), and taken up by
  the mirrors. A binding vote's results come with `ballot_kem`'s secret
  (§7.4).
- **Then:** `vote.closed` to every member of record; the RSA private
  keys are destroyed once the site has accepted the results, and the
  issuance records deleted. The record secrets stay as §3.2 says.

### 8.2 Merkle trees

- RFC 6962 §2.1 with SHA-256; inclusion proofs are verified per RFC 9162
  §2.1.3.2:
  - leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`;
  - split at the largest power of two below n;
  - the empty tree is `H("")`;
  - inclusion proofs are audit paths.
  - This replaces vettid-dev's hex-string tree, which had no leaf/node
    separation and duplicated odd nodes.
- **Ballot leaf:**
  `lp(vk) ‖ lp(cert_prefix) ‖ lp(cert_sig) ‖ u32(seq) ‖ lp(choice_id) ‖ lp(ballot_sig)`.
  The certificate is in the leaf (plan §8). The leaves are in the order
  of `ballots` in the results: by `vk`.
- **Record leaf:** the 32-byte record tag, in sorted order.
- **Mix leaf:** the 32-byte hash of a forwarded envelope, in sorted
  order.

### 8.3 What a member's vault checks

The check runs on `vote.closed`, and in any case at `count_until` + 1 h.
Without the results it retries with backoff for 7 days, and raises an
alarm after `count_until` + 24 h. The app runs pending checks whenever it
opens.

1. **Fetch:** the app fetches the proposal's documents from
   votes.vettid.org and the mirrors whole, over HTTPS, with no session
   and no query naming a voting key. The proof is computed in the vault
   (plan item 5.7 adapts).
2. **The documents:**
   - each signature holds under the key that signed the proposal, and
     each anchor bundle verifies (§8.5 "Rekor profile");
   - neither the site nor a mirror shows a fork for the service;
   - the proposal, roster, extensions and closing it received equal the
     published ones;
   - any site check it deferred (§6.4) now passes;
   - `H(results)` equals `vote.closed`'s, if one came.
3. **Its standing:**
   - its record tag is present; binding: it carries its record key if it
     registered, and none if it didn't;
   - **issuance**, by what the vault recorded:

     | Vault's record | Issuance in the results |
     |---|---|
     | never asked | must be absent; present means its certificate went to someone else |
     | asked and certified | must be present |
     | asked, never answered or refused | if present, "certification withheld" |

   - **decline** (non-binding): if its decline was answered `ok`, it is
     in the results under its `vk`; if it was sent before `count_until`
     and refused or never answered, that is evidence ("decline
     refused").
4. **Its ballot:** if it cast, exactly one counted ballot under its
   `vk`, with its latest `seq`, its stored `cert_sig` and that cast's
   choice, and the inclusion proof reaches `ballot_root`. If it never
   cast, no ballot under its `vk`.
   - Binding: the envelope of its last receipt is in the mix list (by
     an inclusion proof to its root). If not, the mix dropped it; if it
     is there and its latest ballot isn't counted, the box did.
5. **Proposals it never received:** for each proposal of its service on
   the site or a mirror that it doesn't hold, it asks for it (§4.1). A
   refusal, when its connection was active at `record_at`, is evidence
   of exclusion.
6. **Outcome:** the vault shows the member the result. A failure names
   the check, and the vault keeps the evidence (§5.1): the documents and
   bundles it received, signed refusals, the certificate,
   `blinded`/`blind_sig`, `ballot_sig`, the deposit outcomes and
   receipts, and any second proposal.

### 8.4 What an observer checks

From the documents on votes.vettid.org or a mirror:
1. **Signatures and anchors:** every signature holds under the
   service's identity key; every document's bundle verifies under a
   listed anchor key, with its timestamp; the service list verifies as
   §3.4 says; no fork is shown for the service.
2. **Times:** each extension is timestamped before the close it
   extends (`closes_at` + 1 h of the `closes_at` then in force); each
   new `closes_at` is later than the last; extensions total at most
   24 h; `count_until` keeps its distance from `closes_at` (§3.1); the
   roster is timestamped before `opens_at`.
3. **Ballots:** every `cert_sig` holds under `cert_key` for
   `proposal_hash`; every `ballot_sig` under its `vk`; ballot,
   conflict and decline `vk`s are disjoint and each unique; every
   `choice_id` is one of the proposal's.
4. **Tags and issuance:** the record tags are unique, number `eligible`
   and reach `record_root`;
   - non-binding: `issued` is the number marked;
   - binding: every `register_sig` verifies over its tag; the tags with
     a key number `members_of_record`; every issuance's `record_key`
     belongs to one tag, once, and its `certify_sig` verifies.
5. **Counts:**
   - `ballots + conflicts + declined ≤ issued` (`conflicts` counts
     `vk`s), and
     `unaccounted = issued − ballots − conflicts − declined` is
     published: certified members with no counted ballot and no decline;
   - binding: `unaccounted` should be 0, since members certify only to
     cast. With `ballot_kem`'s secret (published with the results, or
     from the escrow), every envelope of the mix list opens, and each is
     counted, a copy, superseded, part of a conflict or dropped by a
     reason, exactly once.
6. **Tally and roots:** the tally and every root recompute.

### 8.5 Schemas

Every document is a JCS object (§2). A verifier refuses unknown fields,
missing fields, and fields of another type. `b64` is standard base64
with padding; `int` is a JSON integer (VAULT-MESSAGING §5.3); `time` is
an `int` of Unix seconds; `hash` is the `b64` of 32 bytes; `sig` the
`b64` of a 64-byte Ed25519 signature; `url` an https URL string; `spki`
the `b64` of a SubjectPublicKeyInfo in DER.

**Proposal:**

| Field | Type |
|---|---|
| `v` | `1` |
| `proposal_id` | string, a canonical ULID |
| `service` | `b64`, the 32-byte Ed25519 identity key |
| `title`, `text` | string |
| `choices` | array of `{id: string, label: string}` |
| `quorum` | `{text: string, min_ballots: int}` |
| `binding` | boolean |
| `record_at`, `opens_at`, `closes_at`, `count_until` | `time` |
| `register_until` | `time`, binding only |
| `eligible`, `record_root` | `int`, `hash` |
| `cert_key`, `report_key` | `spki` (§2) |
| `admission` | `{key: spki, tokens: int, mailbox: {relay: url, mailbox: string}, mix?: {relay: url, mailbox: string, receipt_key: b64, pcrs: [hash-384 as b64]}}`; `mix` binding only |
| `ballot_kem` | `b64` of the MLKEM768X25519 public key |
| `max_casts` | `int` |
| `mirrors` | binding only: array of `url`, at least one, each on the service list |
| `escrow` | binding only: `{round: int, ciphertext: b64}`, the tlock ciphertext of `ballot_kem`'s 32-byte seed |
| `outage_rule`, `statement` | string |

Signature: `Sign(IK, "vettid/vote/1/proposal", H(bytes))`.

**Roster** (binding): `{v: 1, proposal_id, entries: [{record_tag: hash, record_key?: b64, register_sig?: sig}], members_of_record: int, record_root: hash}`,
`entries` for every eligible tag, sorted by `record_tag`. Signature:
`Sign(IK, "vettid/vote/1/roster", proposal_hash ‖ H(bytes))`.

**Extension:** `{v: 1, proposal_id, n: int (≥ 1), register_until?: time, opens_at?: time, closes_at: time, count_until: time, outage: {from: time, to: time, source: url}}`.
Signature: `Sign(IK, "vettid/vote/1/extended", proposal_hash ‖ H(bytes))`.

**Closing:** `{v: 1, proposal_id, closes_at: time}`. Signature:
`Sign(IK, "vettid/vote/1/closing", proposal_hash ‖ H(bytes))`.

**Mix list** (binding): `{v: 1, proposal_id, count: int, root: hash, hashes: [hash]}`,
the sorted hashes of the forwarded envelopes, each distinct envelope
once, with their Merkle root (§8.2); the envelopes themselves are a
separate file, `mix-envelopes.bin`, concatenated in the order of
`hashes`. Signature:
`Sign(the proposal's mix receipt key, "vettid/vote/1/mix-list", proposal_hash ‖ H(bytes))`.

**`record_proof`:** `{index: int, tree_size: int, path: [hash]}`, where
`index` is the tag's position among the sorted tags and `path` the audit
path, from the leaf up.

**Deposit body:**
`{v: 1, proposal_id, vk: b64, cert_prefix: b64, cert_sig: b64, seq: int, choice_id: string, ballot_sig: sig}`,
as JCS bytes.

**Report:** `{v: 1, proposal_id, flags: [string], report_value: b64, report_prefix: b64, report_sig: b64}`,
posted to the site (§10.2).

**Results:**

| Field | Type |
|---|---|
| `v` | `1` |
| `proposal_id` | string |
| `proposal`, `roster`, `closing` | `{doc: b64, sig: sig}`; `roster` binding only |
| `extensions` | array of `{doc: b64, sig: sig}`, by `n` |
| `record_tags` | non-binding only: array of `{tag: hash, issued: boolean}`, sorted by `tag` |
| `issuances` | binding only: array of `{record_key: b64, request_hash: hash, certify_sig: sig}`, by `record_key` |
| `mix_root` | binding only: `hash`, the mix list's root |
| `ballot_kem_secret` | binding only: `b64`, the 32-byte seed (§7.4) |
| `declines` | non-binding only: array of `{vk, cert_prefix, cert_sig, decline_sig}`, by `vk` |
| `record_root`, `ballot_root` | `hash` |
| `ballots` | array of `{vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`, by `vk` |
| `conflicts` | array, by `vk`, of `{vk, ballots: [ballot], declines: [decline]}` |
| `tally` | object: every choice `id` → `int` |
| `counts` | `{eligible, members_of_record, issued, declined, ballots, conflicts, copies, superseded, unaccounted, removed}`, all `int`; `conflicts` counts `vk`s |
| `dropped` | object: reason → `int`, for every reason of `format`, `proposal`, `late`, `delivery`, `certificate`, `ballot`, `choice` |
| `restored` | boolean |

Signature: §8.1.

**Service list:**
`{v: 1, version: int, previous: hash, site_anchor_key: spki, services: [service], mirrors: [mirror], mixes: [mix]}`, where:
- `service` is `{service_id: string, name: string, iks: [{ik: b64, rotation_sig?: sig}], anchor_keys: [{key: spki, anchor_cert: sig, ik: b64}]}`,
  with `service_id` the lower-case hex of `H(first ik)[0:16]` and each
  `rotation_sig = Sign(previous ik, "vettid/vote/1/ik-rotation", H(ik))`;
- `mirror` is `{url: url, operator: string}`;
- `mix` is `{name: string, operator: string, relay: url, receipt_key: b64, anchor_key: spki, anchor_cert: sig, pcrs: [b64]}`;
- `previous` is the hash of the previous version (all-zero for the
  first).

Signed and anchored by the site under its anchor key.

**Rekor profile.**
- **Logs:** the Rekor logs named, by origin, in the Sigstore trusted
  root pinned in the vault's release config. A bundle from another log
  is refused, and watchers tail every pinned log.
- **Entry:** `hashedrekord`, as the pinned Rekor version defines it; the
  digest is SHA-256 of the document bytes; the key is the anchor key as
  PKIX DER; the signature is ASN.1 DER ECDSA.
- **Bundle:** a Sigstore bundle (v0.3) with the transparency log entry,
  its inclusion proof and checkpoint, and an RFC 3161 timestamp from a
  timestamp authority in the trusted root.
- **A verifier checks:** that the entry's body names exactly
  `H(document)` and the anchor key, and that the anchor key is on the
  service list; the ECDSA signature; the inclusion proof against the
  checkpoint; the checkpoint's signature under the log's key; and the
  timestamp, which gives the document's time.
- **Duplicates:** an anchor retried after a lost answer may make a
  second entry with the same digest; it is the same document.
- The Rekor version and trusted root are pinned in item 5.4, with a
  bundle vector for each document type (§11).

## 9. Trust boundaries

### 9.1 What the service vault learns

- **It learns:** who is eligible; which vaults registered (binding);
  when each vault certified (binding: when each member first cast);
  which members declined and their `vk` (non-binding); the ballots and
  the tally, at the close.
- **It does not learn,** from the ballot, certificate or token: whose a
  ballot is.
- **Non-binding votes:** ballots arrive the moment they are cast
  (§6.4), so an arrival time is a link for a service that also knows
  when the member was active:
  - a site visit or sign-in just before;
  - a certification just before, from a vault that was locked at
    opening (§5.2);
  - other traffic on the connection.

  A dishonest box could also open deposits before the close and see a
  running tally (§7.1). Each non-binding proposal's `statement` says so.
- **Binding votes:** the box receives one envelope per voter, at the
  close, shuffled and with no times, so arrival says nothing to it.

### 9.2 Operator metadata (D5)

VettID runs the relay, the member-vault hosts and the service vault.

**The link:** the host's forwarder can see which vault process opened a
connection at time t, and the relay records a deposit arriving at t. An
operator who instruments both can join them. Together with the ballot
box's decryption, that links a ballot to a member.

| Option | What it closes | Cost |
|---|---|---|
| A. State it | Nothing. Each proposal says so. | None. Non-binding votes only. |
| B. A mix | Deposits go to a mix that forwards each voter's last envelope at the close, shuffled and with no times (§3.3). | The relay revision. |
| C. Casting from the phone through an oblivious relay (RFC 9458) | The host sees no ballot traffic. | An OHTTP gateway, app work on both platforms, a third-party OHTTP relay. Phone hand-off times correlate with deposits. |
| D. The ballot box in an enclave (Phase 7) | The operator's access to decrypted ballots, but not the network link. | As planned. |

**Decided (owner, 2026-10-28 and 2026-10-29): B for binding votes, A
until then; the mix in an attested enclave run by VettID, a second
independent mix in sequence later.**

**What VettID's operator still learns in a binding vote:** which vaults
deposited to the mix, and when: whether, and from when, a member voted,
and how many deposits arrived (fewer than `max_casts` means locked or
late). Nothing joins a deposit to a ballot: deposits reach the enclave
sealed to its key, each the same size; the ballot carries no time and a
random `seq`; and the enclave forwards only each voter's last envelope,
at the close, in random order, with no times.

**What the secrecy rests on:** the enclave and its published code. An
operator who could read the enclave's memory (a flaw in the Nitro
hardware or hypervisor, or a build that doesn't match the published
measurements) could pair hosts with envelopes. Vaults check the
measurements; the code is reproducible and public. A second mix run by
an independent party, in sequence, removes even that: either mix alone
breaks the link.

### 9.3 Residual trust

- **Phantom members:** connections the service controls, added before
  `record_at`. Only `eligible` and outside knowledge of the membership
  show them. A binding vote publishes the roster before `opens_at` and
  invites an independent count.
- **Stuffing:** to add a ballot, the service needs a certificate, which
  it can mint for a `vk` of its own, and an issuance to cover it.
  - **Binding:** issuance is the member's signature under their
    registered key (§5.3); a key registered for a member who didn't is
    caught by that member's vault (§3.5). The room left is phantom
    members, and members whose vault never checks.
  - **Non-binding:** marking issued a member who certified, cast or
    declined is caught by observers or by that member (§8.3 check 3); a
    dropped decline is caught by its member. The room left is
    `unaccounted` (certified members whose vault neither cast nor
    declined), the removed count, and members whose vault never checks.
- **Withholding:** dropping a real ballot or decline is caught by that
  member (§8.3). In a binding vote the mix's receipts and list tell
  whether the mix or the box dropped it, and the timelock (§7.4) lets
  the count go ahead without the service.
- **The escrow:** no one can check that it opens to the right key before
  it opens. A service that forges it and withholds its results can void
  a binding vote, in a way everyone sees.
- **Forks:** every document is anchored under a listed anchor key, which
  the site, the mirrors and anyone else can watch (§3.4).
- **The site:** votes.vettid.org can withhold or delay, not alter. In a
  binding vote the mirror covers withholding. VettID maintains the
  service list, but a vault accepts only identity keys it learned from
  its own connection (§3.4).
- **The certification key:** a service that made a malformed modulus can
  make certification fail, which shows (§2); no proof of well-formedness
  is required beyond the vault's checks.
- **drand:** the timelock rests on most of the League of Entropy's
  members not colluding to release a round early.
- **Detection needs the app:** a member whose app never runs after the
  vote checks nothing.

## 10. Availability

### 10.1 Vectors

The requirement (owner decision 2026-10-26): no one other than the
member may prevent an eligible member from obtaining a certificate and
casting a counted ballot during the voting window. Against the service
itself, the protocol detects rather than prevents.

| Vector | How it is met, or what remains |
|---|---|
| Certification refused or ignored | The vault retries until `closes_at`. A wrongful refusal is evidence (§10.2). An outage is covered by §10.2. |
| Proposal not sent | The vault learns of it on votes.vettid.org or a mirror and asks (§4.1). A refusal is evidence. |
| Registration refused (binding) | A wrongful refusal is evidence; the roster shows the tag without a key (§3.5). |
| Ask gate (VAULT-MESSAGING §10.4.1) | Registering, certifying, depositing and declining are not asks. |
| Site sign-in blocked | Voting needs no site sign-in. |
| votes.vettid.org down, or refusing a reader | The vault deposits on the bundles it holds, and defers the site checks (§6.4). |
| Rekor or its timestamp authority down | The service can't anchor, so it can't open or extend a vote; §10.2 covers it. The close happens by rule (§7.1). |
| Deposits flooded with junk | Every deposit needs an admission token, and each member holds only their own (§3.3). |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits retry. |
| Service vault, relay, mix or host outage | Deposits wait in the ballot mailbox (14 days) or at the mix. Requests wait on the connection. Beyond the §10.2 bound, the vote is extended. |
| The member's vault locked, or its host restarted | Casting needs the app and so an unlocked vault. The app reminds the member before close. Binding registration needs the vault unlocked once in its window. |
| A restore of the member's vault | The member keeps their counted ballot but can't cast again or decline (§6.6). |
| Clock skew | The app stops casting two minutes before close; the vault and the box use the receiver's clock (§6.4, §7.1); `not_open` is retried (§5.2). |
| Removal during the vote | The member's certificate stays valid and their ballot counts. A non-binding member removed after certifying can't decline; the results count removals (§8.1). |
| The service after the close (binding) | The timelock lets anyone count (§7.4). |

### 10.2 The outage rule and evidence (fixed before opening)

- **What counts:** an outage shown by a party other than the service:
  the status page of the relay, the mix, votes.vettid.org, Rekor or its
  timestamp authority, or the mirror's record of failed fetches; longer
  than 1 hour within the registration window (binding) or the voting
  window.
- **Extension:** the service extends `register_until` (with `opens_at`,
  `closes_at` and `count_until` moving with it), before `register_until`,
  or `closes_at` and `count_until`, before the close (§7.1), by the
  outage rounded up to the hour, by extensions totalling at most 24 h.
  - An extension published after `closes_at` sets the new `closes_at` at
    least 1 hour after its own timestamp.
  - Each is anchored and published, then sent as `vote.extended`; the
    relay and the mix learn the new close from the site. The box has
    opened nothing, so the decision is made without a tally.
- **An outage at the close:** the close happens by rule (§7.1), so no
  outage after it voids a vote. If the mix's list isn't anchored by
  `count_until` + 24 h, a binding vote is void and held again: the mix
  failed, and nothing can count.
- **Reports:** a vault's evidence (§8.3) is shown to the member, who can
  post a report to votes.vettid.org after `count_until`, with no
  session. A report carries flags only: an outage of 30 minutes or more,
  certification refused or withheld, decline refused, proposal refused,
  the site or a mirror unreachable, and which §8.3 check failed. It
  carries the member's report token, an RFC 9474 token under
  `report_key` issued to every eligible member who asked (§5.4), so
  there is at most one report per member and it names no `vk`. The site
  publishes the counts per flag, as information.
- **Holding a non-binding vote again** needs evidence that anyone can
  check, of one of these kinds:
  - an anchored fork;
  - a signed `not_eligible` refusal, shown with the member's
    `record_secret` and proof of its tag;
  - a signed `not_certified` or `too_late` refusal of a decline whose
    `now_ms` is before `count_until`;
  - a signed `unknown_proposal` for a proposal anchored under the
    service's key;
  - a signed `not_eligible` refusal of a registration within its window.

  Other refusals, the service's own faults (a restore, a missing
  closing) and self-asserted flags are recorded, not grounds. A binding
  vote is never held again after the close, except as above.
- **(chosen; not in the spec.)**

## 11. Test vectors

Produced by the reference implementation (items 5.3 and 5.4) and copied
by vettid-vault; a copied vector that stops matching is a
stop-and-report item.
1. **Derivations:** every §5.1 value from a fixed `proposal_seed` and
   `proposal_hash`, including `r`, the tokens, the report token and
   `chain_tag`.
2. **RFC 9474:** the RFC's RSABSSA-SHA384-PSS-Randomized vectors, one
   each over a real `cert_msg`, `token_msg` and report message with fixed
   keys and the derived values, and the exact SPKI DER of a fixed key.
3. **Signatures:** `ballot_msg` and `ballot_sig`, a decline, a
   registration, a certify signature, a refusal, a mix receipt and an
   identity-key rotation.
4. **The deposit:** a body, its padding, and its sealed envelope with
   fixed keys and randomness; a timelock ciphertext with drand's test
   vectors.
5. **Merkle:** trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion
   proof for every leaf of the 5-leaf tree.
6. **Documents:** each document type's bytes, signature and anchor
   bundle, plus refusals: non-canonical bytes and duplicate names.
7. **Ballot box:** one deposit each for a bad certificate, a bad ballot
   signature, an unknown choice, a late deposit, and repeats (a copy;
   copies with different signatures; a lower `seq`; a conflict; a ballot
   and a decline).
8. **Ed25519:** every §2 rule: small-order keys, including their
   non-canonical encodings; `y ≥ p`; `x = 0` with the sign bit set; a
   non-canonical `S`; and valid signatures.

## 12. Decisions for the owner

Items 1–13 were approved by the owner on 2026-10-28, item 3 as amended
in 0.4.0. Items 14–23 were decided on 2026-10-29. Items 5, 6, 7, 9 and
20 changed later (marked).

**Departures from the plan:**
1. **Labels:** `vettid/vote/1/...`, the VMS convention (§2).
2. **No timestamp in the ballot** (§6.1).
3. **Ballots are sent the moment they are cast** (owner decision
   2026-10-28). For non-binding votes, arrival time is a stated link
   (§9.1); the mix removes it for binding votes (§3.3, §9.2).
4. **A lost answer is retried with the same token and bytes,** instead
   of stopping at "probably cast" (§6.4).
5. **Changed in 0.7.0:** the shared pool is gone; every vote uses
   admission tokens (item 19).

**Choices the plan and the specifications leave open:**

6. **Changed in 0.6.0:** a random **proposal seed** per proposal
   replaces the single vote root; it is kept out of backups, and the
   vote state is erased after the check (§5.1).
7. **Changed in 0.6.0:** blinding values are derived from the proposal
   seed (§5.1).
8. **The member may cast again until `closes_at`,** up to `max_casts`
   times; the highest `seq` counts (§6.1, §6.2).
9. **Changed in 0.5.0:** the seal is the VMS sealed envelope with the
   deposit body as its inner plaintext (§6.3).
10. **Publication** waits for the mailbox to drain (§7.1).
11. **Documents are anchored** in Rekor under a listed anchor key per
    service, with a timestamp (§3.4).
12. **The outage rule** counts only outages a party other than the
    service shows, with a 24-hour cap; only checkable evidence holds a
    vote again (§10.2).
13. **JCS documents** are verified as exact canonical bytes, with
    detached signatures (§2).

**Decided 2026-10-29:**

14. **votes.vettid.org** publishes every proposal and its documents, and
    members learn of proposals there (§3.4).
15. **No automatic abstain.** In a non-binding vote, a vault that didn't
    vote declines after the close (§6.5); in a binding vote, a member
    who doesn't vote never certifies (§5.2).
16. **Results only at close** (§7.1).
17. **Binding votes:** registration before opening (§3.5), certification
    at the first cast (§5.2), and exactly `max_casts` deposits per voter
    (§6.4).
18. **Binding votes need an independent mirror** of votes.vettid.org
    (§3.4).
19. **Admission tokens for every vote** (§3.3).
20. **Changed:** the ballot key is **timelocked with drand** rather than
    escrowed with the mirror (§7.4).
21. **The mirror** is a public GitHub repository owned outside VettID,
    running the open-source watcher (§3.4).
22. **The mix** runs in an attested AWS Nitro Enclave, operated by
    VettID, for the first binding votes (§3.3).
23. **A second, independent mix** in sequence is added once there is a
    partner (§9.2).

**Decided (owner, 2026-10-28):**
- **D5:** a mix for binding votes; non-binding votes state the boundary
  (§9.2).
- **D6 and D7:** relay admission tokens (§3.3), a RELAY-PROTOCOL
  revision; since 0.7.0, for every vote.
- **D8:** Sigstore Rekor as the anchor, plus OpenTimestamps for binding
  votes (§3.4).

## Changes

- **0.8.0 (2026-10-29):**
  - The ballot key is timelocked with drand, not escrowed; the mix
    erases what it doesn't forward; the key is published with the
    results so anyone can recount (§7.4).
  - The mix runs in an attested Nitro Enclave; deposits are sealed to
    its key; receipts carry its time and a counter; the mix list is a
    Merkle root with the envelopes in a separate file (§3.3, §8.5).
  - The first mirror is a public GitHub repository (§3.4).
  - The close happens by rule an hour after `closes_at`; the closing
    document confirms it, and a missing one is the service's fault
    (§7.1); `vote.closing` tells vaults.
  - Declines have their own 24-hour window, inside `count_until` (§6.5).
  - Binding votes reuse record tags: the roster shows each eligible tag
    with its key or none, and each vault checks its own (§3.2, §3.5).
  - The service list is verified as append-only by vaults; vaults accept
    only identity keys they learned from their connection (§3.4).
  - Refusals bind the time, the member and the request; only named
    refusals are evidence; only outages shown by others count (§4,
    §10.2).
  - Report tokens have their own key and go to every eligible member
    (§5.4, §10.2).
  - A backed-up participation record; restores and re-registration
    (§5.1, §6.6); issuance records kept outside the table (§7.1).
  - RSA key checks, a constant-time inverse, JCS deposit bodies, hourly
    site fetches, and further schemas and observer checks.

- **0.7.0 (2026-10-29):** admission tokens for every vote; the mix
  forwards each voter's last envelope; the ballot key escrowed with the
  mirror; issued marks on record tags; an anchored service list; signed
  refusals; RFC 3161 timestamps; report tokens; the seed kept out of
  backups.

- **0.6.0 (2026-10-29):** binding registration, certification at the
  first cast and a fixed number of deposits; one anchor key per service;
  signed declines; three-state issuance checks; a closing document; a
  per-proposal seed; exact Ed25519 checks.

- **0.5.0 (2026-10-29):** publication on votes.vettid.org with Rekor
  anchoring; the decline after close; results only at close; a random
  `seq`; the seal pinned.

- **0.4.1 (2026-10-28):** the PSS salt derived; the derivation of `r`
  fixed exactly.

- **0.4.0 (2026-10-28):** ballots sent the moment they are cast;
  re-casting with `seq`; an automatic abstain (since removed).

- **0.3.0 (2026-10-28):** owner decisions D5–D8.
- **0.2.0 (2026-10-28):** the first revision of the full design.
- **0.1.0:** first full draft.
