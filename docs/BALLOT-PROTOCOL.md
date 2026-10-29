# Ballot Protocol

**Status:** 0.7.0 (2026-10-29), for review before more ballot code
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
| Members of record | The roster at `record_at` (§3.2) | Vaults that registered a record key before `register_until` (§3.5) |
| Certification | At opening, automatically (§5.2) | At the member's first cast (§5.2) |
| Deposits | To the ballot mailbox, with admission tokens the relay checks (§3.3) | To the mix, with admission tokens the mix checks; the mix forwards each voter's last ballot at the closing, shuffled (§3.3) |
| Deposits per voter | One per cast | Exactly `max_casts` (§6.4) |
| A member who doesn't vote | Their vault declines after the closing (§6.5) | Nothing: they never certify |
| After close | The service publishes | The service publishes; if it doesn't, an escrowed key lets anyone count (§7.4) |

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only a member of record obtains a certificate, one per proposal. |
| One vote | At most one counted ballot per certificate: the valid ballot with the highest `seq` for a voting key counts (§7.2). A member can change their vote until close by casting again, up to `max_casts` times. |
| Secrecy of the choice | **Binding votes:** no one can tell how a member voted: not the service vault (which is also the ballot box), the relay, the vault hosts or the mix, unless the mix colludes with the operator or the service (§9.2). **Non-binding votes:** the same against the service from the ballot alone, but a ballot's arrival time is a link for whoever knows when the member was active, and VettID's operator can join host and relay records (§9.1, §9.2). Each proposal's `statement` says which applies. **Not secret in either:** *whether* a member voted (§9). |
| Results only at close | No one sees a tally before the closing (§7.1). A dishonest box could open deposits early in a non-binding vote; in a binding one the mix holds them. |
| Verifiability | A member confirms that their ballot is counted as cast, or their decline recorded, and that everyone sees the same documents (§8.3). An observer confirms that every counted ballot has a valid certificate, that no voting key counts twice, the counts of §8.4, and the tally. |
| Publicity | Every proposal and its documents are published on votes.vettid.org and anchored in Rekor under the service's listed anchor key (§3.4), so a member learns of a proposal without the service, and a forked document is visible to anyone watching that key. Binding votes add an independent mirror. |
| Availability | No one but the member can stop an eligible member from casting a counted ballot. Each member holds only their own admission tokens (§3.3). Against the service itself the protocol detects rather than prevents (§10), and in a binding vote the service can't cancel the count after the closing (§7.4). |
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
  the mix list, the results, the service list; §8.5) are JCS (RFC 8785).
  A verifier parses strictly (VAULT-MESSAGING §5.3: no duplicate names),
  then re-serializes per RFC 8785 and refuses the document unless the
  bytes are identical. Each is signed with a detached signature over a
  string that contains `H(document bytes)` (§8.5). **(chosen; not in the
  spec.)**
  - Times in them are Unix seconds, as JSON integers.
  - Binary values are standard base64 with padding (VAULT-MESSAGING
    §5.3).
  - **Message bodies** follow VAULT-MESSAGING §5.3; a document travels in
    a body as the base64 of its bytes.
- **Sorting** of tags, keys and other binary values is by their raw
  bytes, never by their base64.
- **The signing key:** the service identity key that signs a proposal
  signs every document and message of that proposal. A service vault
  starts no `identity.rotate` from a proposal's creation until its
  results are published. The service list keeps every past identity
  key, so old proposals still verify.
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
  - A key is used for one purpose of one proposal only (RFC 9474 §6.2):
    certificates or admission tokens.
  - The service vault uses `cloudflare/circl` `blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` in-repo with
    `math/big`. vettid-vault adds no third-party code to the enclave
    (vettid-vault README; V3-NOTES).
  - RSA-2048 is the plan's choice: the key lives for one vote and is
    destroyed at publication. Blinding hides the message whatever the
    signer's computing power (RFC 9474 security considerations). The
    vault checks only the key's size and exponent; blindness under a
    deliberately malformed modulus is a residual (§9.3).
- **Anchoring** uses ECDSA P-256 with SHA-256 (FIPS 186-5), under the
  service's anchor key (§3.4). It is what Rekor's `hashedrekord` and the
  standard Sigstore tools verify; Ed25519 there would have to be its
  pre-hashed variant.
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
| `count_until` | `closes_at` + 2 h: the box collects until then (§7.1). |
| `cert_key` | The RSA public key for certificates (§2). |
| `admission` | The admission key, the number of tokens per member, and where deposits go (§3.3). |
| `ballot_kem` | The box's KEM public key for this proposal. |
| `max_casts` | How many times a member may cast: 1–8. |
| `members_of_record` | Non-binding only: the count. Binding votes have it in the roster. |
| `record_root` | Non-binding only: the Merkle root of the record tags (§3.2). |
| `mirrors` | Binding only: the independent mirrors (§3.4), with their escrow keys (§7.4). |
| `escrow` | Binding only: the sealed copy of `ballot_kem`'s secret key (§7.4). |
| `outage_rule` | The rule of §10.2, as text. |
| `statement` | What the vote does not protect, in words for members: the links of §9 that apply to it. |

- **Signature:**
  `proposal_sig = Sign(service IK, "vettid/vote/1/proposal", H(proposal_bytes))`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds the certificate,
  the tokens and the ballot to this one proposal (§5.1, §6.1).
- **Publicity:** the proposal is anchored and published before it is
  sent to anyone (§3.4). A vault certifies only under an anchored
  proposal, and deposits only under the published one (§5.2, §6.4).

### 3.2 Members of record and record tags (non-binding)

- **Members of record** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended, and with
  a vault that advertised the vote feature (how it advertises is item
  5.1's). One connection is one member. Two consequences, stated with
  the proposal:
  - A person holding several VettID accounts is several members.
  - A member whose connection is replaced after `record_at` (they
    connect again, for example after a suspension) is not a member of
    record for this proposal.
- **Record tags:** for each member the service vault draws a 32-byte
  random `record_secret`. The member's tag is
  `record_tag = H("vettid/vote/1/record" ‖ 0x00 ‖ proposal_id ‖ record_secret)`.
  `record_root` is the RFC 6962 root (§8.2) over the tags, sorted
  bytewise.
- **Delivery:** each member receives, in `vote.proposal` (§4.1), their
  `record_secret` and an inclusion proof of their tag, with
  `tree_size = members_of_record`. The vault checks it at once, against
  the root in the signed proposal (RFC 9162 §2.1.3.2).
- **Issuance:** the results mark each record tag that was issued a
  certificate (§8.5), so the issued set is a published subset of the
  record tags.
- The service knows every `record_secret`, so it can mark any member
  issued. What stops it is that each member's vault checks its own mark
  (§8.3). A member whose vault never checks is room the service can
  use; non-binding votes state this, and binding votes use registration
  (§3.5) instead.
- The service keeps the record secrets until the proposal leaves the
  site's index (§3.4), so a late vault can still ask for its proposal
  and check.

### 3.3 Admission tokens and the mix

**(Owner decisions 2026-10-28 and 2026-10-29:** admission tokens for
every vote, and the mix for binding votes.) They are a RELAY-PROTOCOL
revision (vettid.org), to be specified there. What this protocol needs
from it:

- **In the proposal:** `admission = {key, tokens, to}`.
  - `key` is an RFC 9474 key (§2) for this proposal's admission tokens
    only.
  - `tokens = max_casts + 3`: one per cast, one report token (§10.2),
    and two spare.
  - `to` is the ballot mailbox (relay URL and mailbox id, a relay
    keypair for this proposal only) for a non-binding vote, or the mix
    (relay URL, mailbox and receipt key) for a binding one.
- **Issuance:** with the certificate (§5.2), the box blind-signs
  `tokens` token values for the member, the same number for everyone.
  No token is issued later, so issuance says nothing about how often a
  member casts.
  - Token `i` (from 0) is `token_value_i`, 32 bytes, signed as
    `token_msg_i = "vettid/vote/1/token" ‖ 0x00 ‖ proposal_hash ‖ token_value_i`,
    with its own prefix, salt and blinding factor (§5.1).
  - The last token, `i = tokens − 1`, is the report token.
- **Checking:** the receiver of a deposit (the relay for a ballot
  mailbox, the mix for a binding vote) verifies the token under `key`,
  refuses it if spent, and otherwise spends it.
  - It refuses deposits at or after `closes_at` by its own clock, as
    extended by any extension published on votes.vettid.org (§10.2).
  - The same token with the same bytes is answered the same way again,
    so a retry after a lost answer costs nothing.
  - The relay learns nothing about the member, and the box nothing
    beyond the token's validity.
- **The mix (binding):**
  - A deposit is `{token, chain_tag, envelope}`, where `chain_tag` is
    derived per voter (§5.1). The vault sends its deposits one at a
    time, each after the previous one's receipt.
  - The mix answers with a receipt:
    `mix_receipt = Sign(mix receipt key, "vettid/vote/1/mix-receipt", proposal_hash ‖ chain_tag ‖ H(envelope))`.
  - **At the closing** (§7.1), it keeps only the last envelope of each
    `chain_tag`, forwards those to the ballot mailbox in a random order
    with no times, pacing so that the mailbox's 10,000 messages are never
    exceeded, and publishes the **mix list**: the forwarded envelopes
    themselves, signed with its receipt key (§8.5).
  - So the box sees one envelope per voter, and nothing of a voter's
    earlier casts.
  - The relay accepts the mix's batch under the mix's own credential.
- **Effects:** a member can spend only their own tokens, so no member
  can exhaust anything for others; distribution is one message per
  member, at certification, whatever the number of members.
- **Until the revision exists,** no vote runs. **(chosen; differs from
  0.6.0,** whose shared pool for non-binding votes let one member spend
  every token.)

### 3.4 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public site run by VettID, separate from every
service vault (its design: vettid/votes, docs/VOTES-SITE.md).

- **The service list** (§8.5) is a document the site signs and anchors
  under its own anchor key, which is pinned in the vault's release
  config. It is append-only: each version contains the previous one's
  entries and its hash. For each registered service it names every
  identity key it has had, and its anchor keys with their certificates.
  VettID maintains it; a service is added by the owner. Vaults fetch it
  when they connect to a service and on every site check, keep the
  latest valid version, and accept an anchor key only if it is on it.
- **The anchor key:** each service has one long-lived ECDSA P-256 anchor
  key, sealed in the service vault's keystore, certified by its
  identity key:
  `anchor_cert = Sign(service IK, "vettid/vote/1/anchor-key", H(anchor_key SPKI DER))`.
  Every document of every proposal of the service is anchored under it.
  A new anchor key is certified the same way and added to the list; old
  ones stay listed and watched.
- **The documents,** in order of upload:
  1. the proposal, before it is sent to any member;
  2. the roster (binding), after `register_until` and before `opens_at`
     (§3.5);
  3. any extensions, before the closing (§10.2);
  4. the closing (§7.1);
  5. the mix list (binding; §3.3), uploaded by the mix;
  6. the results (§8.1).
- **The anchor:** before uploading, the service vault (the mix, for its
  list) anchors each document in Rekor: a `hashedrekord` entry with
  `H(document bytes)` and an ECDSA P-256 signature over the document
  bytes, with an RFC 3161 timestamp from a timestamp authority in the
  trusted root. The Sigstore bundle (§8.5 "Rekor profile") goes up with
  the document and with the message that carries it to vaults. The
  mix's anchor key is on the service list with the mix's receipt key.
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
  fetches the pages of those proposals, which tells the site (as any web
  server) which proposals that address reads.
- **Watching:** the site watches every log the Rekor profile pins for
  entries under every listed anchor key.
  - An entry that matches no published document is a **pending**
    alarm. A later upload of a valid document with that digest clears
    it.
  - Two anchored documents for the same slot (the proposal, the roster,
    extension `n`, the closing, the mix list, the results) with
    different bytes, or a pending alarm still open at `count_until` +
    24 h, is a **fork**, published on the service's page.
  - Entries with the same digest are one document.
- **Time anchor:** for binding votes the site also stamps each
  document's hash with OpenTimestamps, upgrades the proof once Bitcoin
  confirms it, and publishes it. Vaults don't wait for it.
- **An independent mirror (binding):** a binding vote names at least one
  mirror run by a party other than VettID and the organisation
  (`mirrors` in the proposal). It runs the open-source watcher from
  vettid/votes:
  - it watches the same logs for the listed anchor keys, and raises
    pending alarms and forks by the same rules;
  - it fetches each document from votes.vettid.org and verifies it, and
    also accepts any anchored document uploaded by anyone, so a vault
    can give it what the site withholds;
  - it republishes everything with its own index;
  - it holds its escrow key (§7.4) and nothing else.

  The app fetches the index from votes.vettid.org and from every mirror.
  A proposal of its service on one and missing from another is evidence,
  and the vault asks for it (§4.1). A mirror that doesn't answer is
  recorded (`mirror_unreachable`), and the vote goes on. The mirror's
  operator is chosen before the first binding vote, like the mix's.
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

- **Who may register:** the connections active at `record_at` whose
  vault advertised the vote feature.
- **How:** on a valid `vote.proposal`, the vault derives a record key
  `rk` for the proposal (§5.1), records "registering", and sends
  `vote.register {proposal_id, record_key, register_sig}`, with
  `register_sig = Sign(rk, "vettid/vote/1/register", proposal_hash)`.
  It needs no member action, and retries until `register_until`.
- **The roster:** after `register_until` the service publishes the
  roster document: the sorted record keys with their signatures, their
  Merkle root and their count, `members_of_record` (§8.5). It is
  anchored and published before `opens_at`, and sent to every
  registered vault in `vote.roster`.
- **The vault checks** that its record key is in the roster, before it
  deposits and again in §8.3. A missing key is evidence.
- **Members of record** are exactly the roster's keys. A member whose
  vault was locked through the whole window can't vote in this vote;
  the app tells them. The outage rule covers the window (§10.2).
- **What it closes:** the service cannot claim a registered member
  certified, since issuance is that member's own signature (§5.3). It
  can still add phantom keys to the roster, as it could add phantom
  members (§9.3), but only before `opens_at`, in a published count.

## 4. Messages from the service

Session-mode messages on the service connection, in the standard VMS
inner (VAULT-MESSAGING §5.3). Each is answered with a response that
names it (`re`), so the service knows it arrived. A vault without the
vote feature answers `unsupported_type`, which today's rules would
instead drop and audit. That needs the §6.4 change of item 5.1.

**Refusals** of the vault's requests (§5.4) are signed, so that a member
can show them:
`refusal_sig = Sign(service IK, "vettid/vote/1/refusal", proposal_hash ‖ lp(type) ‖ lp(code) ‖ H(request body))`,
in the error body as `{refusal_sig}`, where `type` is the request's type
and `code` the error code. A vault treats an unsigned refusal as no
answer.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, bundle, record_secret?, record_proof?}`
- `proposal` is the §3.1 bytes, in base64; `bundle` its Sigstore bundle.
- Non-binding: `record_secret` and `record_proof`
  `{index, tree_size, path}` (§8.5), the only per-member part.
- **The vault keeps** a proposal whose signature verifies under a listed
  identity key and whose bundle verifies under a listed anchor key (§3.4,
  §8.5 "Rekor profile"). Under one `proposal_id`, it uses the one the
  site publishes (§6.4) and keeps any other as evidence (§8.3). It
  certifies only once one is chosen this way, or, with the site
  unreachable, under the only anchored one it holds.
- **Requested:** a vault that sees a proposal of its service on
  votes.vettid.org or a mirror but holds none sends `vote.request
  {proposal_id}` (§5.4), and the service answers with `vote.proposal` or
  refuses.

### 4.2 `vote.roster` (binding)

`{proposal_id, roster, roster_sig, bundle}`, sent after `register_until`
to every registered vault.

### 4.3 `vote.extended`

`{proposal_id, extension, extension_sig, bundle}` (§10.2). The vault
uses it once its bundle verifies, and checks the site for any later one
before it next deposits or declines.

### 4.4 `vote.closed`

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

  So a retried request is identical, and these values stay secret
  because the seed is.
- **The blinding factor `r`** comes from a blind seed by rejection
  sampling. For `ctr = 0, 1, 2, …`:
  1. `c = SHA-384(blind_seed ‖ u32(ctr) ‖ 0x00) ‖ … ‖ SHA-384(blind_seed ‖ u32(ctr) ‖ 0x05)`,
     which is 288 bytes, truncated to its first 256.
  2. `r = OS2IP(c)`, taken if `0 < r < n` and `gcd(r, n) = 1`.
  3. Otherwise the next `ctr`.

  The expected number of tries is under 2.
- **Blinding:** `blinded = r^e · OS2IP(EMSA-PSS-ENCODE(msg_prefix ‖ cert_msg; pss_salt)) mod n`
  (RFC 9474 §4.2 with the salt and `r` fixed). Tokens likewise, under
  the admission key.
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_hash ‖ vk`.
- **A restore** (VMS restore event) brings back no seed, so the vault
  marks every proposal it held as `seed_lost` (§6.6).

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
     and records "asked", with them, **before** sending
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
     request. Only then does it sign: `blind_sig = BlindSign(cert_sk, blinded)`,
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
     - On `not_open`, it retries after `opens_at` + 1 min, since its
       clock may lead; that refusal is not evidence.

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
| `vote.register` | `{proposal_id, record_key, register_sig}` (binding) | `ok`, or a refusal `not_of_record`, `closed`, `bad_signature` |
| `vote.certify` | `{proposal_id, blinded, admission_blinded, certify_sig?}` | `vote.certified {proposal_id, blind_sig, admission_sigs}`, or a refusal (§5.2) |
| `vote.decline` | `{proposal_id, vk, cert_prefix, cert_sig, decline_sig}` (non-binding; §6.5) | `ok`, or a refusal `not_certified`, `not_closed`, `too_late`, `bad_signature` |
| `vote.request` | `{proposal_id}` | `vote.proposal` (§4.1) as the response, or a refusal `not_of_record`, `unknown_proposal` |

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
  non-binding vote their vault declines after the closing (§6.5); in a
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
- **`body`** is compact JSON (no whitespace),
  `{v: 1, proposal_id, vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`
  (§8.5), padded to exactly 1,024 bytes: `json ‖ 0x80 ‖ 0x00*`
  (VAULT-MESSAGING §5.4's bucket; an honest body is 649–702 bytes).
  Every deposit is therefore a 2,180-byte envelope.
- Nothing in the deposit identifies the vault.

### 6.4 Sending it

1. **Site checks.** While a vote is open, the app fetches the proposal's
   page on votes.vettid.org and the mirrors every hour, and before a
   cast, and the vault checks:
   - the proposal it holds is the published one, and its anchor key is
     on the service list;
   - binding: its record key is in the roster;
   - any extension on the site is one it holds, and it uses the latest
     `closes_at`.

   A deposit uses the latest check. If the site doesn't answer within
   `min(10 min, closes_at − now − 60 s)`, the vault deposits on the
   strength of the bundles its messages carried, and records the site
   checks as deferred, to be made in §8.3. Any other failure is
   evidence (§8.3), and it doesn't deposit.
2. **Time.** At once, when the member casts (owner decision 2026-10-28).
   - **Binding:** every voter makes exactly `max_casts` deposits to the
     mix. The first goes when the member first casts. The rest are
     scheduled at times drawn uniformly between then and
     `closes_at − 5 min`, each a fresh seal of the latest ballot. A
     cast again is sent at once, using the next scheduled deposit, and
     the remaining ones are drawn again. A slot missed while the vault
     was locked is sent when it unlocks, the missed ones spread at
     random over the time left; a slot that can't be sent before
     `closes_at − 5 min` is dropped.
   - The ballot, the certificate, the tokens and the schedule are in the
     vault's encrypted state, and survive a restart.
3. **Token and bytes.** The next unspent admission token (not the report
   token). The vault stores the envelope and its token before the first
   attempt, and every retry sends exactly those, under a fresh request
   signature.
4. **Key.** A fresh Ed25519 key for each deposit signs the request
   (RELAY-PROTOCOL §4.1), to the relay or the mix. An admission token
   needs no registered sender. Every attempt is signed anew, with a
   fresh timestamp; a byte-identical request within 90 s is refused as
   a replay.
5. **Outcomes** (the relay's or the mix's answers, as the relay
   revision defines them):

   | Answer | What the vault does |
   |---|---|
   | Accepted | Reads the receiver's time in the answer (the `msg_id` ULID at the relay; the receipt at the mix). Before `closes_at`, to the millisecond: records "cast" and keeps `vk`, the certificate, `ballot_sig`, `seq` and any receipt. At or after it: records "late". |
   | Token spent, with the same bytes | Treated as accepted: it was this deposit's own earlier attempt. |
   | Token spent, other bytes; token invalid | Drops the token and uses the next one (a spare), and reports `token_refused`. |
   | `429 rate_limited` | Waits `retry_after`, then retries. |
   | Mailbox `quota_exceeded`, 5xx, network errors | Retries the same bytes, re-signed, with a backoff of up to 5 min (RELAY-PROTOCOL §7.1: never unchanged). |
   | `replay_detected`, `timestamp_stale`, `signature_invalid` | Re-signs and retries, once for `signature_invalid`, then reports `deposit_failed`. |
   | `400`, `payload_too_large`, `mailbox_unknown` | Reports `deposit_failed` (§8.3). |

   Retries continue until `closes_at`.

### 6.5 Declining (non-binding)

- **Who:** a vault that is certified, has never signed a ballot for the
  proposal, and is not `seed_lost`. Once it has declined it never casts.
- **When:** after the closing is published (§7.1), at a time drawn
  uniformly from then to 90 minutes later. A vault locked then declines
  when it is unlocked, until `count_until`.
- **How:** `vote.decline {proposal_id, vk, cert_prefix, cert_sig, decline_sig}`
  on the service connection (§5.4), with
  `decline_sig = Sign(vk, "vettid/vote/1/declined", proposal_hash)`,
  retried until `count_until`. The service refuses a decline before the
  closing (`not_closed`; the vault retries), whose certificate or
  signature fails (`bad_signature`), from a connection it never
  certified (`not_certified`), or after `count_until` (`too_late`).
- **In the results:** every decline, with its `vk` and certificate. A
  `vk` that both declined and has a ballot is a conflict (§7.2).
- **What it does:** each certified member is accounted for by a ballot
  or a decline. A decline that wasn't answered `ok` is evidence (§8.3),
  so a service that drops declines to free their certificates is caught.
- It goes over the connection, not to the ballot mailbox, so nothing is
  deposited at a fixed time. It tells the service who didn't vote, and
  their `vk` (which has no ballot); §1 says so.
- **(chosen; not in the spec;** owner decision 2026-10-29, replacing the
  automatic abstain.)

### 6.6 After a restore

A vault restored from backup (the VMS restore event) has no proposal
seeds (§5.1). For every proposal open or unchecked at the time, it
records `seed_lost`:
- it doesn't cast, decline or run the tag checks of §8.3 for it;
- a ballot it cast before the restore still counts;
- an `already_certified` refusal is then expected, not evidence;
- the app tells the member they can't change their vote in it.

## 7. The ballot box

### 7.1 Collecting and closing

- **When:** the ballot box (the service vault) collects from `opens_at`
  to `count_until` (non-binding), or until it holds every envelope of
  the mix list (binding), acknowledging each message once its write is
  durable.
- **Sealed until the closing:** the box stores each deposit as received,
  with its `msg_id` and token, and opens none until the closing is
  published.
- **The closing:** at `closes_at` + 1 h, if no extension was published
  before then, the service publishes the closing document (§8.5),
  anchored and timestamped. It is the final close: from then on no
  extension is possible, the mix forwards, the box opens what it holds
  and runs §7.2, and vaults decline. The hour lets an outage in the last
  hour be covered (§10.2); deposits made in it are refused, as after
  `closes_at`, unless an extension reopens the vote.
- **The arrival cutoff** is `closes_at`, by the receiver's time, the
  same clock the vault reads (§6.4). The relay or the mix enforces it.
- **Publication** (non-binding) waits until the mailbox is empty at
  `count_until`, and then until collects have come back empty for 10
  minutes. **(chosen; not in the spec.)**
- **A restore of the service vault's table:**
  - before the closing, in a non-binding vote: acknowledged deposits are
    lost. The results say so (`restored: true`), and the vote is held
    again;
  - in a binding vote, or after the closing: nothing is held again. The
    mix list holds every counted envelope (§7.4), and the box counts
    from it.

### 7.2 Checks, in order

1. **Format:** the envelope is 2,180 bytes, its header is as §6.3
   states, it unseals, it has exactly the 1,024-byte padding, and `body`
   parses strictly.
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
- **Failures** are counted by reason (§8.5) and dropped.

### 7.3 Watch

- **Alarms:**
  - mailbox use above 20% of its quota (10,000 messages, 32 MiB;
    RELAY-PROTOCOL §7.2);
  - after the closing, more than 10% of deposits failing checks 1–4;
  - any conflict.

### 7.4 The escrowed key (binding)

**(Owner decision 2026-10-29.)**

- **At creation** the service seals `ballot_kem`'s secret key to each
  mirror's escrow key (a VMS suite-2 KEM key named in `mirrors`): the
  proposal's `escrow` field holds, per mirror, a sealed VMS envelope
  whose inner plaintext is the key, padded per VAULT-MESSAGING §5.4.
- **Release:** if the results aren't published by `count_until` + 24 h,
  a mirror opens its escrow and publishes the secret key with the
  proposal. Anyone can then open the envelopes of the mix list and count
  by §7.2.
- **Before then** the escrow gives a mirror nothing: the only envelopes
  it could open are in the mix list, which exists only after the
  closing.
- **So after the closing nothing re-runs a binding vote:** a fault of
  the service, such as a table restore or results never published, is
  recorded as its fault, and the count goes ahead without it.

## 8. Publication and verification

### 8.1 Results

- **`results.json`** is a document (§8.5) with:
  - the proposal, the roster, any extensions and the closing, each with
    its signature;
  - non-binding: `members_of_record`, the record tags with their issued
    marks, `record_root`, and the declines; binding: the issuances
    (§5.3) and the mix list's hash;
  - the counted ballots, sorted by `vk`, and `ballot_root`;
  - the conflicts, with all their ballots and declines;
  - the tally per choice, the counts, the failures by reason, and the
    count of members removed or suspended during the vote.
- **Signature:** detached,
  `results_sig = Sign(service IK, "vettid/vote/1/results", proposal_hash ‖ H(results_bytes))`.
- **Published and anchored** on votes.vettid.org (§3.4), and taken up by
  the mirrors.
- **Then:** `vote.closed` to every member of record; the RSA private
  keys and `ballot_kem`'s secret key are destroyed once the site has
  accepted the results, and the issuance records deleted. The record
  secrets stay as §3.2 says.

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
- **Record leaf:** the 32-byte record tag (non-binding) or the 32-byte
  record key (binding), in sorted order.

### 8.3 What a member's vault checks

The check runs on `vote.closed`, and in any case at `count_until` + 1 h.
Without the results it retries with backoff for 7 days, and raises an
alarm after `count_until` + 24 h. The app runs pending checks whenever it
opens. A `seed_lost` proposal gets checks 1, 2 and 5 only.

1. **Fetch:** the app fetches the proposal's documents from
   votes.vettid.org and the mirrors whole, over HTTPS, with no session
   and no query naming a voting key. The proof is computed in the vault
   (plan item 5.7 adapts).
2. **The documents:**
   - each signature holds under the key that signed the proposal, and
     each anchor bundle verifies (§8.5 "Rekor profile");
   - neither the site nor a mirror shows a fork for the service;
   - the proposal, roster and extensions it received equal the
     published ones;
   - any site check it deferred (§6.4) now passes;
   - `H(results)` equals `vote.closed`'s, if one came.
3. **Its standing:**
   - non-binding: its record tag is present;
   - binding: its record key is in the roster, if it registered;
   - **issuance**, by what the vault recorded:

     | Vault's record | Issuance in the results |
     |---|---|
     | never asked | must be absent; present means its certificate went to someone else |
     | asked and certified | must be present |
     | asked, never answered or refused | if present, "certification withheld" |

   - **decline** (non-binding): if its decline was answered `ok`, it is
     in the results under its `vk`; if it was refused or never answered,
     that is evidence ("decline refused").
4. **Its ballot:** if it cast, exactly one counted ballot under its
   `vk`, with its latest `seq`, its stored `cert_sig` and that cast's
   choice, and the inclusion proof reaches `ballot_root`. If it never
   cast, no ballot under its `vk`.
   - Binding: the receipt of its last deposit names an envelope in the
     mix list. If not, the mix dropped it; if it is there and its latest
     ballot isn't counted, the box did.
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
1. **Signatures and anchors:** every signature holds under a listed
   identity key of the service; every document's bundle verifies under a
   listed anchor key, with its timestamp; no fork is shown for the
   service.
2. **Times:** each extension's timestamp is before the closing in force
   when it was made; each `closes_at` is later than the last; the total
   is at most 24 h; `count_until = closes_at + 2 h`; the closing names
   the final `closes_at` and is timestamped at or after it + 1 h; the
   roster is timestamped before `opens_at`.
3. **Ballots:** every `cert_sig` holds under `cert_key` for
   `proposal_hash`; every `ballot_sig` under its `vk`; ballot,
   conflict and decline `vk`s are disjoint and each unique; every
   `choice_id` is one of the proposal's.
4. **Issuance:**
   - non-binding: the record tags are unique and number
     `members_of_record`; `issued` is the number marked;
   - binding: the roster's `register_sig`s verify and number
     `members_of_record`; every issuance's `record_key` is in the
     roster, once, and its `certify_sig` verifies.
5. **Counts:**
   - `ballots + conflicts + declined ≤ issued`, and
     `unaccounted = issued − ballots − conflicts − declined` is
     published: certified members with no counted ballot and no decline;
   - binding: `unaccounted` should be 0, since members certify only to
     cast; the mix list's envelopes number `ballots + conflicts + copies
     + superseded + dropped`, and opening them with a released escrow
     gives the same ballots.
6. **Tally and roots:** the tally and every root recompute.

### 8.5 Schemas

Every document is a JCS object (§2). A verifier refuses unknown fields,
missing fields, and fields of another type. `b64` is standard base64
with padding; `int` is a JSON integer (VAULT-MESSAGING §5.3); `time` is
an `int` of Unix seconds; `hash` is the `b64` of 32 bytes; `sig` the
`b64` of a 64-byte Ed25519 signature; `url` an https URL string.

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
| `cert_key` | `b64` of the SPKI DER (§2) |
| `admission` | `{key: b64 (SPKI DER, §2), tokens: int, to: {relay: url, mailbox: string, receipt_key?: b64}}`; `receipt_key` binding only |
| `ballot_kem` | `b64` of the MLKEM768X25519 public key |
| `max_casts` | `int` |
| `members_of_record`, `record_root` | `int`, `hash`; non-binding only |
| `mirrors` | binding only: array of `{url: url, escrow_key: b64}`, at least one |
| `escrow` | binding only: array of `b64` sealed envelopes, one per mirror in the same order (§7.4) |
| `outage_rule`, `statement` | string |

Signature: `Sign(IK, "vettid/vote/1/proposal", H(bytes))`.

**Roster** (binding): `{v: 1, proposal_id, members: [{record_key: b64, register_sig: sig}], members_of_record: int, record_root: hash}`,
`members` sorted by `record_key`. Signature:
`Sign(IK, "vettid/vote/1/roster", proposal_hash ‖ H(bytes))`.

**Extension:** `{v: 1, proposal_id, n: int (≥ 1), register_until?: time, opens_at?: time, closes_at: time, count_until: time, outage: {from: time, to: time, source: string}}`.
Signature: `Sign(IK, "vettid/vote/1/extended", proposal_hash ‖ H(bytes))`.

**Closing:** `{v: 1, proposal_id, closes_at: time}`. Signature:
`Sign(IK, "vettid/vote/1/closing", proposal_hash ‖ H(bytes))`.

**Mix list** (binding): `{v: 1, proposal_id, envelopes: [b64]}`, the
forwarded envelopes, sorted by their hash, each distinct envelope once.
Signature: `Sign(mix receipt key, "vettid/vote/1/mix-list", proposal_hash ‖ H(bytes))`.

**`record_proof`:** `{index: int, tree_size: int, path: [hash]}`, where
`index` is the tag's position among the sorted tags and `path` the audit
path, from the leaf up.

**Deposit body:**
`{v: 1, proposal_id, vk: b64, cert_prefix: b64, cert_sig: b64, seq: int, choice_id: string, ballot_sig: sig}`,
compact JSON, parsed strictly.

**Results:**

| Field | Type |
|---|---|
| `v` | `1` |
| `proposal_id` | string |
| `proposal`, `roster`, `closing` | `{doc: b64, sig: sig}`; `roster` binding only |
| `extensions` | array of `{doc: b64, sig: sig}`, by `n` |
| `record_tags` | non-binding only: array of `{tag: hash, issued: boolean}`, sorted by `tag` |
| `issuances` | binding only: array of `{record_key: b64, request_hash: hash, certify_sig: sig}`, by `record_key` |
| `mix_list` | binding only: `hash` of the mix list |
| `declines` | non-binding only: array of `{vk, cert_prefix, cert_sig, decline_sig}`, by `vk` |
| `record_root`, `ballot_root` | `hash` |
| `ballots` | array of `{vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`, by `vk` |
| `conflicts` | array, by `vk`, of `{vk, ballots: [ballot], declines: [decline]}` |
| `tally` | object: every choice `id` → `int` |
| `counts` | `{members_of_record, issued, declined, ballots, conflicts, copies, superseded, unaccounted, removed}`, all `int` |
| `dropped` | object: reason → `int`, for every reason of `format`, `proposal`, `late`, `delivery`, `certificate`, `ballot`, `choice` |
| `restored` | boolean |

Signature: §8.1.

**Service list:** `{v: 1, version: int, previous: hash, site_anchor_key: b64, services: [{service_id, name, iks: [b64], anchor_keys: [{key: b64 (SPKI DER), anchor_cert: sig, ik: b64}]}], mixes: [{name, receipt_key: b64, anchor_key: b64}]}`,
with `service_id` the lower-case hex of `H(first ik)[0:16]` and
`previous` the hash of the previous version (all-zero for the first).
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

- **It learns:** who the members of record are; when each vault
  certified (binding: when each member first cast); which members
  declined and their `vk` (non-binding); the ballots and the tally, at
  the closing.
- **It does not learn,** from the ballot, certificate or token: whose a
  ballot is.
- **Non-binding votes:** ballots arrive the moment they are cast
  (§6.4), so an arrival time is a link for a service that also knows
  when the member was active:
  - a site visit or sign-in just before;
  - a certification just before, from a vault that was locked at
    opening (§5.2);
  - other traffic on the connection.

  A dishonest box could also open deposits before the closing and see a
  running tally (§7.1). Each non-binding proposal's `statement` says so.
- **Binding votes:** the box receives one envelope per voter, at the
  closing, shuffled and with no times, so arrival says nothing to it.

### 9.2 Operator metadata (D5)

VettID runs the relay, the member-vault hosts and the service vault.

**The link:** the host's forwarder can see which vault process opened a
connection at time t, and the relay records a deposit arriving at t. An
operator who instruments both can join them. Together with the ballot
box's decryption, that links a ballot to a member.

| Option | What it closes | Cost |
|---|---|---|
| A. State it | Nothing. Each proposal says so. | None. Non-binding votes only. |
| B. An independent mix | Deposits go to a relay run by an independent party, which forwards each voter's last envelope at the closing, shuffled and with no times (§3.3). | An operating agreement, and the relay revision. The mix sees host addresses, not vaults. |
| C. Casting from the phone through an oblivious relay (RFC 9458) | The host sees no ballot traffic. | An OHTTP gateway, app work on both platforms, a third-party OHTTP relay. Phone hand-off times correlate with deposits. |
| D. The ballot box in an enclave (Phase 7) | The operator's access to decrypted ballots, but not the network link. | As planned. |

**Decided (owner, 2026-10-28): B for binding votes, A until then.**

**What VettID's operator still learns in a binding vote:** which vaults
deposited to the mix, and when: whether, and from when, a member voted.
Nothing joins a deposit to a ballot: every voter makes `max_casts`
deposits (§6.4), each the same size (§6.3); the ballot carries no time
and a random `seq` (§6.1); the box sees only each voter's last envelope,
forwarded with the others at the closing in random order.

**What the mix could do, colluding:** it sees each `chain_tag`'s
deposits, their times and the host they came from. With the operator,
it links a host to a `chain_tag`; with the service, which sees
certification times (§5.2), it links a voter's first deposit by time.
Either, with the box's decryption, links the ballot. The mix and its
operator are chosen before the first binding vote.

### 9.3 Residual trust

- **Phantom members of record:** connections the service controls,
  added before `record_at`, or (binding) keys added to the roster. Only
  the count and outside knowledge of the membership show them. A binding
  vote publishes the roster before `opens_at` and invites an independent
  count.
- **Stuffing:** to add a ballot, the service needs a certificate, which
  it can mint for a `vk` of its own, and an issuance to cover it.
  - **Binding:** issuance is the member's signature under their
    registered key (§5.3), and members who don't vote never certify. The
    room left is phantom roster keys.
  - **Non-binding:** marking issued a member who certified, cast or
    declined is caught by observers or by that member (§8.3 check 3); a
    dropped decline is caught by its member. The room left is
    `unaccounted` (certified members whose vault neither cast nor
    declined), the removed count, and members whose vault never checks.
    Each non-binding proposal's `statement` says so.
- **Withholding:** dropping a real ballot or decline is caught by that
  member (§8.3). In a binding vote the mix's receipts and list tell
  whether the mix or the box dropped it, and the escrow (§7.4) lets the
  count go ahead without the service.
- **Forks:** every document is anchored under a listed anchor key, which
  the site, the mirrors and anyone else can watch (§3.4).
- **The site:** votes.vettid.org can withhold or delay, not alter. In a
  binding vote the mirror covers withholding.
- **The certification key:** the vault checks its size and exponent
  only. A service that made a malformed modulus might weaken blinding;
  no proof of well-formedness is required.
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
| Certification refused or ignored | The vault retries until `closes_at`. A signed refusal is evidence (§8.3). An outage is covered by §10.2. |
| Proposal not sent | The vault learns of it on votes.vettid.org or a mirror and asks (§4.1). A refusal is evidence. |
| Registration refused (binding) | A signed refusal is evidence; the roster shows the key missing (§3.5). |
| Ask gate (VAULT-MESSAGING §10.4.1) | Registering, certifying, depositing and declining are not asks. |
| Site sign-in blocked | Voting needs no site sign-in. |
| votes.vettid.org down, or refusing a reader | The vault deposits on the bundles it holds, and defers the site checks (§6.4). |
| Rekor or its timestamp authority down | The service can't anchor, so it can't open, extend or close a vote; §10.2 covers it. |
| Deposits flooded with junk | Every deposit needs an admission token, and each member holds only their own (§3.3). |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits retry. |
| Service vault, relay, mix or host outage | Deposits wait in the ballot mailbox (14 days) or at the mix. Requests wait on the connection. Beyond the §10.2 bound, the vote is extended. |
| The member's vault locked, or its host restarted | Casting needs the app and so an unlocked vault. The app reminds the member before close. Binding registration needs the vault unlocked once in its window. |
| Clock skew | The app stops casting two minutes before close; the vault and the box use the receiver's clock (§6.4, §7.1); `not_open` is retried (§5.2). |
| Removal during the vote | The member's certificate stays valid and their ballot counts. A non-binding member removed after certifying can't decline; the results count removals (§8.1). |
| The service after close (binding) | The escrow lets anyone count (§7.4). |

### 10.2 The outage rule and evidence (fixed before opening)

- **What counts:** an outage, shown by the service vault's own health
  checks or the status page of the relay, the mix, votes.vettid.org,
  Rekor or its timestamp authority, longer than 1 hour within the
  registration window (binding) or the voting window.
- **Extension:** the service extends `register_until` (with `opens_at`,
  `closes_at` and `count_until` moving with it), or `closes_at` and
  `count_until`, by the outage, rounded up to the hour, by extensions
  totalling at most 24 h. Each extension is anchored and published
  **before the closing** (§7.1), then sent as `vote.extended`; the relay
  and the mix learn the new close from the site. The box has opened
  nothing, so the decision is made without a tally.
- **An outage at close:** if the service can't publish an extension or
  the closing within 24 h of `closes_at` (Rekor or the site being down),
  the vote is void and held again. The mix forwards nothing until the
  closing is published.
- **Evidence and reports:** a vault's evidence (§8.3) is shown to the
  member, who can post a report to votes.vettid.org after `count_until`,
  with no session. A report carries flags only: an outage of 30 minutes
  or more, certification refused or withheld, decline refused, proposal
  refused, the site or a mirror unreachable, and which §8.3 check
  failed. It spends the member's report token (§3.3), so there is at
  most one per certified member and it names no `vk`. The site publishes
  the counts per flag, as information.
- **Holding a vote again** (non-binding, before its closing) needs
  evidence that anyone can check: an anchored fork, or a signed refusal
  of a member of record. After the closing, nothing re-runs a binding
  vote (§7.4).
- **(chosen; not in the spec.)**

## 11. Test vectors

Produced by the reference implementation (items 5.3 and 5.4) and copied
by vettid-vault; a copied vector that stops matching is a
stop-and-report item.
1. **Derivations:** every §5.1 value from a fixed `proposal_seed` and
   `proposal_hash`, including `r`, the tokens and `chain_tag`.
2. **RFC 9474:** the RFC's RSABSSA-SHA384-PSS-Randomized vectors, one
   over a real `cert_msg` and one over a `token_msg` with fixed keys and
   the derived values, and the exact SPKI DER of a fixed key.
3. **Signatures:** `ballot_msg` and `ballot_sig`, a decline, a
   registration, a certify signature, a refusal and a mix receipt.
4. **The deposit:** a body, its padding, and its sealed envelope with
   fixed keys and randomness; an escrow envelope.
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
in 0.4.0. Items 14–20 were decided on 2026-10-29; item 21 is open.
Items 5, 6, 7 and 9 changed later (marked).

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
   replaces the single vote root. In 0.7.0 it is also kept out of
   backups, and the vote state is erased after the check (§5.1).
7. **Changed in 0.6.0:** blinding values are derived from the proposal
   seed (§5.1).
8. **The member may cast again until `closes_at`,** up to `max_casts`
   times; the highest `seq` counts (§6.1, §6.2).
9. **Changed in 0.5.0:** the seal is the VMS sealed envelope with the
   deposit body as its inner plaintext (§6.3).
10. **Publication** waits for the mailbox to drain (§7.1).
11. **Documents are anchored** in Rekor under a listed anchor key per
    service, with a timestamp (§3.4).
12. **The outage rule** covers the relay, mix, site, Rekor and
    registration, with a 24-hour cap; reports are information (§10.2).
13. **JCS documents** are verified as exact canonical bytes, with
    detached signatures (§2).

**Decided 2026-10-29:**

14. **votes.vettid.org** publishes every proposal and its documents, and
    members learn of proposals there (§3.4).
15. **No automatic abstain.** In a non-binding vote, a vault that didn't
    vote declines after the closing (§6.5); in a binding vote, a member
    who doesn't vote never certifies (§5.2).
16. **Results only at close** (§7.1).
17. **Binding votes:** registration before opening (§3.5), certification
    at the first cast (§5.2), and exactly `max_casts` deposits per voter
    (§6.4).
18. **Binding votes need an independent mirror** of votes.vettid.org
    (§3.4).
19. **Admission tokens for every vote** (§3.3).
20. **The ballot key is escrowed with the mirror** for binding votes
    (§7.4).

**Open:**

21. **Who runs the mirror** (§3.4), and who runs the mix (§9.2).

**Decided (owner, 2026-10-28):**
- **D5:** an independent mix for binding votes; non-binding votes state
  the boundary (§9.2).
- **D6 and D7:** relay admission tokens (§3.3), a RELAY-PROTOCOL
  revision; since 0.7.0, for every vote.
- **D8:** Sigstore Rekor as the anchor, plus OpenTimestamps for binding
  votes (§3.4).

## Changes

- **0.7.0 (2026-10-29):**
  - Admission tokens for every vote; the shared pool, its distribution,
    re-issue and the 500-member cap are gone (§3.3).
  - The mix forwards only each voter's last envelope, by a per-voter
    chain tag, and publishes the envelopes; the box sees one envelope per
    voter (§3.3).
  - The ballot key is escrowed with the mirror, so nothing re-runs a
    binding vote after the closing (§7.4).
  - The issued set is a marked subset of the record tags (§3.2).
  - The service list is anchored and append-only, and vaults accept only
    listed anchor keys; mirrors raise alarms and accept uploads from
    anyone; pending alarms and forks are told apart (§3.4).
  - Refusals are signed (§4); bundles carry an RFC 3161 timestamp, and
    logs are pinned (§8.5).
  - The closing is an hour after `closes_at`, so an outage in the last
    hour can be covered; extensions may be published until the closing
    and cover registration (§7.1, §10.2).
  - Report tokens instead of unauthenticated reports (§10.2).
  - The seed and vote state are kept out of backups and erased after
    the check; a restore marks proposals `seed_lost` (§5.1, §6.6).
  - "Asked" is recorded before sending; `not_open` is retried; declines
    wait for the closing (§5.2, §6.5).
  - Scheduled binding deposits, retries with the same bytes, the site
    wait bounded by the close (§6.4).
  - HKDF `info` bytes written out; Ed25519 checks by every verifier;
    header checks at the box; observer checks of times, the roster and
    copies; schemas updated (§2, §7.2, §8.4, §8.5).

- **0.6.0 (2026-10-29):**
  - Binding votes: registration and a roster; certification at the first
    cast; exactly `max_casts` deposits per voter; mix receipts; an
    independent mirror.
  - One registered anchor key per service; bundles in the messages; a
    Rekor profile.
  - Signed declines with the voting key; three-state issuance checks.
  - A closing document; a per-proposal seed; exact Ed25519 checks.

- **0.5.0 (2026-10-29):**
  - Proposals, pools, extensions and results published on
    votes.vettid.org and anchored in Rekor.
  - The automatic abstain replaced by a decline after close.
  - The box opens deposits only at close.
  - `seq` random and in the deposit body; the `day` gone.
  - The seal pinned to the VMS sealed envelope with no time inside.

- **0.4.1 (2026-10-28):** found while writing the reference
  implementation. The PSS salt is derived too (`pss_salt`), so a retry
  is identical. The derivation of `r` is fixed exactly.

- **0.4.0 (2026-10-28):** owner decision on item 3.
  - Ballots are sent the moment they are cast; the deposit phase and
    `decide_by` are gone.
  - A cast-again ballot carries `seq`, and the highest counts.
  - The vault sends an abstain an hour before close for a member who
    hasn't cast.
  - For non-binding votes, arrival time is a stated link; the mix
    removes it for binding votes.

- **0.3.0 (2026-10-28):** owner decisions D5–D8.
- **0.2.0 (2026-10-28):** the deposit phase with abstain by default;
  proposal and pool hashes in the certificate and the ballot; token
  quotas; drained publication and an anchor; derived blinding values and
  a conditional certification write; JCS exact bytes; an anonymous
  sealed sender; the outage rule.
- **0.1.0:** first full draft.
