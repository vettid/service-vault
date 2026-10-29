# Ballot Protocol

**Status:** 0.6.0 (2026-10-29), for review before more ballot code
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
wire vectors; this document is its source.

**Two kinds of vote.** A proposal is binding or not (§3.1), and the two
run differently:

| | Non-binding | Binding |
|---|---|---|
| Members of record | The roster at `record_at` (§3.2) | Vaults that registered a record key before `register_until` (§3.6) |
| Certification | At opening, automatically (§5.2) | At the member's first cast (§5.2) |
| Deposit tokens | A shared pool (§3.3) | Admission tokens, checked by the mix (§3.4) |
| Arrival at the box | At once | Held by the mix until close, shuffled (§3.4) |
| A member who doesn't vote | Their vault declines after close (§6.5) | Nothing: they never certify |
| Deposits per voter | One per cast | Exactly `max_casts` (§6.4) |

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only a member of record obtains a certificate, one per proposal. |
| One vote | At most one counted ballot per certificate: the valid ballot with the highest `seq` for a voting key counts (§7.2). A member can change their vote until close by casting again, up to `max_casts` times. |
| Secrecy of the choice | **Binding votes:** no one can tell how a member voted, not the service vault (which is also the ballot box), the relay, the mix or the vault hosts, unless the mix colludes with them (§9.2). **Non-binding votes:** the same against the service from the ballot alone, but a ballot's arrival time is a link for whoever knows when the member was active, and VettID's operator can join host and relay records (§9.1, §9.2). Each proposal's `statement` says which applies. **Not secret in either:** *whether* a member voted (§9). |
| Results only at close | No one sees a tally before the vote's final close. The box stores deposits sealed until the closing document is published (§7.1). A dishonest box could open them early in a non-binding vote; the mix prevents it in a binding one. |
| Verifiability | A member confirms that their ballot is counted as cast, or their decline recorded, and that everyone sees the same documents (§8.3). An observer confirms that every counted ballot has a valid certificate, that no voting key counts twice, the counts of §8.4, and the tally. |
| Publicity | Every proposal and its documents are published on votes.vettid.org and anchored in Rekor under the service's registered anchor key (§3.5), so a member learns of a proposal without the service, and a forked document is visible to anyone watching that key. |
| Availability | No one but the member can stop an eligible member from casting a counted ballot. Against the service itself the protocol gives detection, not prevention (§10). |
| Receipt-freeness | Out of scope (owner decision). The vault's post-vote check (§8.3) shows the member their counted choice, and so works as a receipt. Casting again gives no protection against a coercer who checks the outcome. |

## 2. Notation and primitives

- `‖` is concatenation. `u16`, `u32` and `u64` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- **Labels** follow the VMS convention (VAULT-MESSAGING §4.1): ASCII
  strings embedding the version, `vettid/vote/1/...`. Where a label
  starts a hashed or signed string, a `0x00` follows it as a separator.
  Every signature the service identity key makes, in VMS and here, is
  over a label-prefixed string, so the two can't be confused.
  **(chosen; differs from the plan:** the plan's `"vettid-vote-v1"`
  follows vettid-dev.)
- **Signatures:** `Sign(sk, label, m)` is `suite.Sign` from vettid-vault
  `vms/suite`, Ed25519 over `label ‖ 0x00 ‖ m`. (Every use below writes
  the `0x00` out.)
- **Ed25519 verification** is exactly:
  1. `A` (the public key) and `R` are 32 bytes whose `y` is below p, and
     not `x = 0` with the sign bit set;
  2. `[8]A` is not the identity (no small-order key);
  3. `S < L`;
  4. `[S]B = R + [k]A`, cofactorless, with `k = SHA-512(R ‖ A ‖ m) mod L`.

  Go's `ed25519.Verify` does steps 3 and 4. The service vault adds 1 and
  2. §11 item 8 has vectors for each rule.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
  Another form is refused.
- **Documents** (the proposal, a pool, the roster, an extension, the
  closing, the results; §8.5) are JCS (RFC 8785). A verifier parses
  strictly (VAULT-MESSAGING §5.3: no duplicate names), then
  re-serializes per RFC 8785 and refuses the document unless the bytes
  are identical. Each is signed with a detached signature over a string
  that contains `H(document bytes)` (§8.5 lists them). **(chosen; not in
  the spec.)**
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
  results are published.
- **Blind signatures** are RFC 9474 RSABSSA-SHA384-PSS-Randomized: RSA
  with a modulus of exactly 2048 bits, `e = 65537`, SHA-384, MGF1-SHA-384,
  salt length 48, and a 32-byte message prefix.
  - The key is an id-RSASSA-PSS SubjectPublicKeyInfo carrying exactly
    those parameters, the form RFC 9578 §6.5 specifies for Privacy Pass
    (RFC 9474 §6.2 requires the OID; RFC 4055 §3.1 defines the
    parameters). The SHA-384 AlgorithmIdentifiers omit their parameters
    (RFC 5754 §2), and the trailer field is the default. The exact DER
    prefix is a vector (§11 item 2). The member vault parses it by hand
    and refuses anything else; Go's `x509` does not parse it.
  - A key is used for one purpose of one proposal only (RFC 9474 §6.2):
    certificates or admission tokens.
  - The service vault uses `cloudflare/circl` `blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` in-repo with
    `math/big`. vettid-vault adds no third-party code to the enclave
    (vettid-vault README; V3-NOTES).
  - RSA-2048 is the plan's choice: the key lives for one vote and is
    destroyed at publication. Blinding hides the message whatever the
    signer's computing power (RFC 9474 security considerations).
- **Anchoring** uses ECDSA P-256 with SHA-256 (FIPS 186-5), under the
  service's anchor key (§3.5). It is what Rekor's `hashedrekord` and the
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
| `register_until` | Binding only: the end of registration (§3.6), at least 24 h after creation. |
| `opens_at` | Members can vote. For binding votes, at or after `register_until`. |
| `closes_at` | The last moment to cast: ballots deposited before it count. `closes_at − created_at ≤ 7 days − 1 h`. |
| `count_until` | `closes_at` + 2 h: the box collects until then (§7.1). |
| `created_at` | When the proposal was made: the pool's `iat` (§3.3). |
| `cert_key` | The RSA public key for certificates (§2). |
| `ballot_mailbox` | Relay URL and mailbox id: a relay keypair for this proposal only. |
| `ballot_kem` | The box's KEM public key for this proposal. |
| `max_casts` | How many times a member may cast: 1–8. |
| `pool` | Non-binding only: the first pool's `pool_hash` (§3.3). |
| `members_of_record` | Non-binding only: the count. Binding votes have it in the roster. |
| `record_root` | Non-binding only: the Merkle root of the record tags (§3.2). |
| `admission` | Binding only: the admission key and the mix (§3.4). |
| `mirrors` | Binding only: the independent mirrors' URLs (§3.5). |
| `outage_rule` | The rule of §10.2, as text. |
| `statement` | What the vote does not protect, in words for members: the links of §9 that apply to it. |

- **Timing:** the window's cap keeps the first pool's tokens, minted at
  creation with `iat` backdated 60 s and `exp = closes_at + 15 min`
  (§3.3), within the relay's open-token lifetime (RELAY-PROTOCOL §5.6;
  168 h deployed).
- **Signature:**
  `proposal_sig = Sign(service IK, "vettid/vote/1/proposal", H(proposal_bytes))`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds the certificate
  and the ballot to this one proposal (§5.1, §6.1).
- **Publicity:** the proposal is anchored and published before it is
  sent to anyone (§3.5). A vault certifies only under an anchored
  proposal, and deposits only under the published one (§5.2, §6.4).

### 3.2 Members of record and record tags (non-binding)

- **Members of record** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended, and with
  a vault that advertised the vote feature. One connection is one
  member. Two consequences, stated with the proposal:
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
- **Issuance tags:**
  `issued_tag = H("vettid/vote/1/issued" ‖ 0x00 ‖ proposal_id ‖ record_secret)`,
  for each member certified (§5.3).
- The service knows every `record_secret`, so it can publish an issuance
  tag for any member. What stops it is that each member's vault checks
  its own tag (§8.3). A member whose vault never checks is room the
  service can use; non-binding votes state this, and binding votes use
  registration (§3.6) instead.
- The service keeps the record secrets until the proposal leaves the
  site's index (§3.5), so a late vault can still ask for its proposal
  and check.

### 3.3 The token pool (non-binding)

- **What it is:** one-shot open deposit tokens for the ballot mailbox
  (RELAY-PROTOCOL §5.6: scope `deposit_open`, `sub` `*`, a fresh ULID
  `jti` each). They are minted locally, with no relay call.
  - `iat` is the mint time backdated by 60 s (§5.2 there).
  - `exp = closes_at + 15 min`.
  - Each carries `quota: {msgs: 1, bytes: 4096}` (RELAY-PROTOCOL §5.2;
    a deposit is 2,180 bytes, §6.3).
- **The pool** is a document (§8.5) with `pool_hash = H(pool_bytes)` and
  `pool_sig = Sign(service IK, "vettid/vote/1/pool", proposal_hash ‖ u32(pool_seq) ‖ pool_hash)`.
- **Pool 1** is minted when the proposal is made, and its hash is in the
  proposal. Later pools are re-issues (§7.3) or come with an extension
  (§10.2). There are at most four.
- **Publicity:** each later pool's hash, signature and anchor are
  published when it is minted (§3.5), but not its tokens.
- **Use:** a vault deposits only while it holds every published pool,
  and draws its token uniformly across all of them (§6.4). A pool sent to
  one member therefore marks no one: either it is published and everyone
  holds it, or the vault refuses to use it.
- **Size:** `2 × members_of_record + 64` tokens.
- **Distribution:** sent at `opens_at` over the connection, to every
  member of record, as identical bytes (§4.2). Its tokens are not
  published before `count_until`, so only members hold them.
  - A pool over one message (the 245,760-byte inner limit,
    VAULT-MESSAGING §5.5, at about 200 members; to be measured with
    real tokens) goes in parts (§4.2).
  - The bytes the service sends grow with N² (N pools of 2N tokens).
    Through the relay's per-key byte budget of 64 KiB/s per relay process
    (RELAY-PROTOCOL §7.2 limit 11), N = 300 takes minutes and N = 1,000
    hours. **Non-binding votes are limited to 500 members of record**
    until they too can use admission tokens.
- **What bearer tokens cannot do (§10.1):** a member, who holds the pool,
  can spend its tokens with junk, or by casting the maximum. Re-issue
  slows it; admission tokens stop it.

### 3.4 Admission tokens and the mix (binding)

The owner decided (D5–D7) that binding votes use tokens checked when a
deposit is accepted, issued per member at certification without the
issuer learning which token is whose, and an independent mix. Both are a
RELAY-PROTOCOL revision (vettid.org), to be specified there. What this
protocol needs from it:

- **In the proposal:** `admission = {key, tokens, mix}`.
  - `key` is an RFC 9474 key (§2) for admission tokens of this proposal
    only.
  - `tokens = max_casts + 2`; the 2 cover lost answers.
  - `mix` is the mix's relay URL, mailbox and receipt key (Ed25519).
- **Issuance:** with the certificate (§5.2), the box blind-signs
  `tokens` token values for the member, the same number for everyone.
  No token is issued later.
  - Token `i` (from 0) is `token_value_i`, 32 bytes, blind-signed as
    `token_msg_i = "vettid/vote/1/token" ‖ 0x00 ‖ proposal_hash ‖ token_value_i`,
    with its own prefix, salt and blinding factor (§5.1).
- **At the mix:** a deposit is `{token_value, token_prefix, token_sig,
  envelope}`.
  - The mix verifies the token under `key`, refuses it if spent, and
    otherwise spends it and answers with a receipt:
    `mix_receipt = Sign(mix key, "vettid/vote/1/mix-receipt", proposal_hash ‖ H(envelope))`.
  - The same token with the same envelope gets the same receipt again,
    so a retry after a lost answer costs nothing.
  - It refuses deposits at or after `closes_at` by its own clock, as
    extended by a published extension (§10.2).
  - **At close,** once the closing document is published (§7.1), it
    forwards every accepted envelope to the ballot mailbox in a random
    order, at once, with no times, pacing so that the mailbox's 10,000
    messages are never exceeded while the box collects. It publishes the
    sorted list of their hashes on votes.vettid.org, signed with its
    receipt key, as `mix.json`.
  - The relay accepts the mix's batch under the mix's own credential.
- **The ballot** names no pool (§6.1).
- **Effects:** a member can spend only their own tokens, so exhaustion
  is impossible; distribution is O(N); there is no pool.
- **Until it exists,** binding votes wait.

### 3.5 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public site run by VettID, separate from every
service vault (its design: vettid/votes, docs/VOTES-SITE.md).

- **The anchor key:** each service has one long-lived ECDSA P-256 anchor
  key, sealed in the service vault's keystore.
  - It is certified by the service identity key:
    `anchor_cert = Sign(service IK, "vettid/vote/1/anchor-key", H(anchor_key SPKI DER))`.
  - The site's service list (§8.5) names each registered service's
    identity key, anchor keys and certificates. VettID maintains it; a
    service is added by the owner.
  - Every document of every proposal of the service is anchored under
    it. The site publishes the set of anchor keys, and anyone can watch
    Rekor for them.
  - A new anchor key is certified the same way and added; old ones stay
    listed and watched.
- **The documents,** in order of upload:
  1. the proposal, with pool 1's hash (non-binding), before the
     proposal is sent to any member;
  2. the roster (binding), after `register_until` and before `opens_at`
     (§3.6);
  3. each later pool's hash and signature, when it is minted;
  4. any extension, before the current `closes_at` (§10.2);
  5. the closing, at the final close (§7.1);
  6. the mix's forward list (binding; §3.4);
  7. the results (§8.1), with every pool's bytes.
- **The anchor:** before uploading, the service vault anchors each
  document in Rekor: a `hashedrekord` entry with `H(document bytes)` and
  an ECDSA P-256 signature over the document bytes under its anchor key.
  The Sigstore bundle of Rekor's answer (§8.5 "Rekor profile") goes up
  with the document and with the message that carries it to vaults.
  - A pool is anchored over its full bytes, which Rekor and the site see
    only as a hash.
  - The mix's forward list is anchored by the site, under the site's own
    anchor key, also on the service list.
- **What the site checks** before it publishes an upload: the service is
  registered; the signatures; the exact JCS bytes; the anchor bundle
  under a registered anchor key; the order above; the document's fields
  against the proposal.
- **Write-once:** each document has one path. The site accepts the same
  bytes again, refuses different bytes, and never changes or removes a
  document.
- **Discovery:** the site keeps an index of proposals open or closed
  within the last 30 days. The app fetches the whole index, with no
  session, and hands the vault the entries of its services. It then
  fetches the pages of those proposals, which tells the site (as any web
  server) which proposals that address reads.
- **Monitor:** the site watches Rekor for entries under every registered
  anchor key. An entry that matches no published document within an
  hour of its log time is an alarm, published on the service's page. It
  means the service anchored a document it didn't publish: a fork.
- **Time anchor:** for binding votes the site stamps each document's
  hash with OpenTimestamps, upgrades the proof once Bitcoin confirms it,
  and publishes it. It shows when the site held the document; vaults
  don't wait for it.
- **What the site can and cannot do:**
  - It cannot alter a document or serve a fork that no one sees: a fork
    must be anchored under a watched key.
  - It could withhold a document, or refuse a reader. A vault checks
    anchors offline from the bundles its messages carry, so this delays
    the site checks rather than stopping a vote (§6.4).
  - It is independent of an organisation's service vault, not of VettID.
    For VettID's own member service the guarantee rests on VettID and on
    outside watchers of the anchor key, and each such proposal's
    `statement` says so.
- **An independent mirror (binding votes):** a binding vote needs at
  least one mirror run by a party other than VettID and other than the
  organisation, named in the proposal (`mirrors`) and on the service
  list. It runs the open-source watcher from vettid/votes: it reads
  Rekor for the registered anchor keys, fetches each document it finds
  from votes.vettid.org, verifies it, and republishes it, with its own
  index. It holds no keys and needs only to stay up; it can't alter
  anything either.
  - The app fetches the index from votes.vettid.org and from every
    mirror. A proposal of its service on one and missing from another
    is evidence, and the vault asks for it (§4.1).
  - So no single party, VettID included, can hide a vote from some
    members or run one that only some of them see.
  - The mirror's operator is chosen before the first binding vote, like
    the mix's.

### 3.6 Registration (binding)

**(Owner decision 2026-10-29.)**

- **Who may register:** the connections active at `record_at` whose
  vault advertised the vote feature.
- **How:** on a valid `vote.proposal`, the vault derives a record key
  `rk` for the proposal (§5.1) and sends
  `vote.register {proposal_id, record_key, register_sig}`, with
  `register_sig = Sign(rk, "vettid/vote/1/register", proposal_hash)`.
  It needs no member action, and retries until `register_until`.
- **The roster:** after `register_until` the service publishes the
  roster document: the sorted record keys, their signatures, their
  Merkle root and their count, `members_of_record` (§8.5). It is
  anchored and published before `opens_at`, and sent to every
  registered vault in `vote.roster`.
- **The vault checks** that its record key is in the roster. A missing
  key is evidence (§8.3).
- **Members of record** are exactly the roster's keys. A member whose
  vault was locked through the whole window can't vote in this vote;
  the app tells them.
- **What it closes:** the service cannot claim a registered member
  certified, since issuance is that member's own signature (§5.3).
  It can still add phantom keys to the roster, as it could add phantom
  members (§9.3), but only before `opens_at`, in a published count.

## 4. Messages from the service

Session-mode messages on the service connection, in the standard VMS
inner (VAULT-MESSAGING §5.3). Each is answered with a response that
names it (`re`), so the service knows it arrived. A vault without the
vote feature answers `unsupported_type`, which today's rules would
instead drop and audit. That needs the §6.4 change of item 5.1.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, bundle, anchor, record_secret?, record_proof?}`
- `proposal` is the §3.1 bytes, in base64; `bundle` its Sigstore bundle;
  `anchor` the service's anchor key with its `anchor_cert`.
- Non-binding: `record_secret` and `record_proof`
  `{index, tree_size, path}` (§8.5), the only per-member part.
- **The vault keeps** a proposal whose signature, anchor certificate and
  bundle verify (§8.5 "Rekor profile"). Under one `proposal_id`, it uses
  the one the site publishes (§6.4) and keeps any other as evidence
  (§8.3). It certifies only once one is chosen this way, or, with the
  site unreachable, under the only anchored one it holds.
- **Requested:** a vault that sees a proposal of its service on
  votes.vettid.org but holds none sends `vote.request {proposal_id}`
  (§5.4), and the service answers with `vote.proposal` or refuses.

### 4.2 `vote.pool` (non-binding)

`{proposal_id, pool_seq, part, parts, pool_part, pool_sig, bundle}`
- `pool_part` is a byte range of the pool document, in base64, of at
  most 196,608 bytes before encoding; parts are numbered from 1, in
  order. `pool_sig` and `bundle` are the same in every part.
- The vault assembles all `parts`, then checks `pool_hash` (against the
  proposal for pool 1), `pool_sig` and the bundle. Parts that disagree
  are dropped and asked for again with `vote.pool.request` (§5.4).
- A different pool under a `pool_seq` it already holds is kept as
  evidence and not used.

### 4.3 `vote.roster` (binding)

`{proposal_id, roster, roster_sig, bundle}`, sent after `register_until`
to every registered vault.

### 4.4 `vote.extended`

`{proposal_id, extension, extension_sig, bundle}` (§10.2). The vault
uses it once it is anchored, and checks it on the site before it next
deposits or declines.

### 4.5 `vote.closed`

`{proposal_id, results_hash}`. The vault doesn't depend on it: it runs
its check at `count_until` + 1 h anyway (§8.3).

## 5. Certification

### 5.1 The proposal seed and what is derived from it

- **The proposal seed** is 32 random bytes the vault draws when it first
  keeps a proposal (§4.1), and stores in its DEK-encrypted state as
  feature data (VAULT-MESSAGING §3.3) before using it. It is erased once
  the §8.3 check has passed, or 7 days after `count_until`. Because it is
  opened by the vault's unlock rather than by the password, the vault
  can register, certify and decline on its own.
  - The member's choice still needs the member's approval (§6.2).
  - Erasing it means a later compromise of the vault exposes no past
    vote.
  - **(chosen; not in the spec;** it replaces 0.5.0's single vote root.)
- **Derived values:** each is
  `HKDF-SHA256(ikm = proposal_seed, salt = proposal_hash, info = label, L)`:

  | Value | `info` | `L` |
  |---|---|---|
  | `seed`, whose Ed25519 key is `vk` | `vettid/vote/1/voting-key` | 32 |
  | `msg_prefix` | `vettid/vote/1/msg-prefix` | 32 |
  | `pss_salt` (the salt of RFC 9474's EMSA-PSS encoding) | `vettid/vote/1/pss-salt` | 48 |
  | `blind_seed` | `vettid/vote/1/blind` | 32 |
  | The record key `rk`'s seed (binding) | `vettid/vote/1/record-key` | 32 |
  | Token `i`'s value, prefix, salt and blind seed (binding) | `vettid/vote/1/token-value`, `vettid/vote/1/token-prefix`, `vettid/vote/1/token-salt`, `vettid/vote/1/token-blind`, each followed by `u32(i)` | 32, 32, 48, 32 |

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
  (RFC 9474 §4.2 with the salt and `r` fixed). Tokens likewise.
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_hash ‖ vk`.
- **A restore** (VMS restore event) that loses the seed loses the vote:
  the vault reports `seed_lost` and runs no tag check for the proposal
  (§8.3), since its earlier requests can't be recomputed.

### 5.2 Request and answer

- **When:**
  - **Non-binding:** at once on keeping a proposal (§4.1), at or after
    `opens_at`, with no member action. A vault unlocked at `opens_at`
    certifies then; a locked one when it is next unlocked, which may be
    just before its member casts (a link the `statement` names, §9.1).
  - **Binding:** at the member's first cast, just before the first
    deposit. The service learns when each member first cast, not how
    (the mix holds the ballot).
  - Either way it is a vault step, not an ask (VAULT-MESSAGING §10.4.1).
- **How:**
  1. The vault sends `vote.certify {proposal_id, blinded}`; for binding
     votes with `admission_blinded` (`tokens` entries) and
     `certify_sig = Sign(rk, "vettid/vote/1/issued", proposal_hash ‖ H(blinded ‖ admission_blinded_0 ‖ …))`.
     It records "asked".
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
     - It answers `vote.certified {proposal_id, blind_sig, admission_sigs?}`.
     - A repeated request gets the stored answer.
     - Refusals are the response with `status: error` and `error.code`
       one of `already_certified`, `not_open`, `closed`,
       `not_of_record` or `not_active`.
  3. **The vault** computes `cert_sig = Finalize(cert_key, msg_prefix ‖ cert_msg, blind_sig, r)`,
     which includes verifying it, and the tokens likewise. It keeps
     `(cert_prefix = msg_prefix, cert_sig)` and records "certified".
     - If `Finalize` fails, it keeps `blinded` and `blind_sig` as
       evidence, retries once, and then reports
       `certification_failed` (§8.3).
     - With no answer, it retries the same request with backoff until
       `closes_at`.

The service sees `blinded` and `blind_sig`, which tell it nothing about
`vk` or `cert_sig` without `r`.

### 5.3 The issuance list

The service vault records `connection, proposal_id, request, answer`
(the conditional write above). At publication (§8.1) it publishes:
- **non-binding:** the issuance tags of certified members;
- **binding:** each issuance as `{record_key, request_hash, certify_sig}`,
  where `request_hash = H(blinded ‖ admission_blinded_0 ‖ …)`, which
  observers verify against the roster.

Then it deletes the records.

### 5.4 Messages from the member's vault

| Type | Body | Answer |
|---|---|---|
| `vote.register` | `{proposal_id, record_key, register_sig}` (binding) | `ok`, or an error `not_of_record`, `closed` |
| `vote.certify` | `{proposal_id, blinded, admission_blinded?, certify_sig?}` | `vote.certified {proposal_id, blind_sig, admission_sigs?}`, or an error (§5.2) |
| `vote.decline` | `{proposal_id, vk, cert_prefix, cert_sig, decline_sig}` (non-binding; §6.5) | `ok`, or an error `not_certified`, `too_late` |
| `vote.request` | `{proposal_id}` | `vote.proposal` (§4.1) as the response, or an error `not_of_record`, `unknown_proposal` |
| `vote.pool.request` | `{proposal_id, pool_seq}` (non-binding) | `vote.pool` parts, or an error `unknown_pool` |

## 6. Casting

### 6.1 The ballot

- `ballot_msg = proposal_hash ‖ u32(seq) ‖ lp(choice_id)`
- `ballot_sig = Sign(vk, "vettid/vote/1/ballot", ballot_msg)`
- **`seq`** orders a member's casts without counting them:
  - the first cast draws `seq` uniformly from [1, 2^30);
  - each further cast adds a step drawn uniformly from [1, 2^16];
  - the vault stores the new `seq` before signing with it.

  The highest counts, so the order holds however deposits arrive, even
  shuffled by the mix, and the published `seq` says nothing about how
  often the member cast.
- **No pool and no timestamp.** The pool a deposit used is checked at
  deposit (§7.2) but not signed, so a retry through another pool is the
  same ballot. **(chosen; differs from the plan:** a signed time would be
  published with the ballot.)

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
  non-binding vote their vault declines after close (§6.5); in a binding
  one it never certifies. **(Owner decisions 2026-10-29;** the earlier
  automatic abstain is gone.)
- **Reminders:** the app reminds the member a day before `closes_at`.

### 6.3 The deposit

- **The seal** is a VMS v2 envelope in sealed mode (VAULT-MESSAGING §5.2,
  §4.3), to `ballot_kem`:
  - `sender_kid` all-zero (anonymous), `recipient_kid` the kid of
    `ballot_kem` (§4.4 there);
  - the HPKE `info` is VAULT-MESSAGING's `vettid/vms/2/sealed`, and the
    AAD is the header, as for every sealed envelope;
  - the inner plaintext is **the deposit body, not the §5.3 inner
    object**: it has no `id`, `type` or `ts`, so nothing in it carries
    the time. `ballot_kem` receives nothing else, so the recipient knows
    the format. Item 5.1 registers this exception to VAULT-MESSAGING
    §5.3.
- **`body`** is the JSON
  `{v: 1, proposal_id, vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig, pool_seq?}`
  (§8.5; `pool_seq` for non-binding votes only), padded to exactly 1,024
  bytes: `json ‖ 0x80 ‖ 0x00*` (VAULT-MESSAGING §5.4's bucket, which
  every honest body of 512–1,023 bytes reaches). Every deposit is
  therefore a 2,180-byte envelope.
- Nothing in the deposit identifies the vault. A member's own kid or
  key there would link the ballot.

### 6.4 Sending it

1. **Checks before depositing.** Before each deposit the app fetches the
   proposal's page on votes.vettid.org (§3.5), and the vault checks:
   - the proposal it holds is the published one;
   - non-binding: it holds every published pool, asking for any it
     lacks (`vote.pool.request`);
   - any extension on the site is one it holds, and it uses the latest
     `closes_at`.

   If the site doesn't answer within 10 minutes, the vault deposits on
   the strength of the Rekor bundles its messages carried, and records
   the site checks as deferred, to be made in §8.3. Any other failure is
   evidence (§8.3), and it doesn't deposit.
2. **Time.** At once, when the member casts (owner decision 2026-10-28).
   - **Binding:** every voter makes exactly `max_casts` deposits to the
     mix. The first goes when the member first casts. The rest are
     scheduled at times drawn uniformly between then and
     `closes_at − 5 min`, each a fresh seal of the latest ballot. A
     cast again is sent at once, using the next scheduled deposit, and
     the remaining ones are drawn again. The host and the mix therefore
     see the same number of deposits from every voter.
   - The ballot, the certificate and the schedule are in the vault's
     encrypted state, and survive a restart.
3. **Token.** Non-binding: a token drawn uniformly at random across all
   published pools the vault holds, among those it hasn't tried.
   Binding: the next unspent admission token.
4. **Key.** For the relay (non-binding), a fresh Ed25519 key for this
   deposit signs the request (RELAY-PROTOCOL §4.1). An open token needs
   no registered sender (§5.6). Every attempt is signed anew, with a
   fresh timestamp. A byte-identical request within 90 s is refused as
   a replay.
5. **Outcomes** (non-binding, at the relay; the mix's answers are in the
   relay revision, with the same meanings):

   | Answer | What the vault does |
   |---|---|
   | `2xx` | Reads the time of the `msg_id` ULID in the answer (RELAY-PROTOCOL §6.2). Before `closes_at` (to the millisecond, `closes_at` being a whole second): records "cast", and keeps `vk`, the certificate, `ballot_sig`, `seq` and every `pool_seq` it used. At or after it: records "late". |
   | `409 token_used` (spent by someone else, or by a first attempt whose answer was lost) | Deposits again with another token and a fresh key. A second copy is harmless: it is the same ballot (§7.2). **(chosen; differs from the plan,** which stopped at "probably cast".) |
   | `token_expired`, `token_revoked`, `token_invalid`, `quota_exceeded` with `quota: "token"` | Drops that token. With none left, waits for the next pool. |
   | `429 rate_limited` | Waits `retry_after`, then retries. |
   | Mailbox `quota_exceeded`, 5xx, network errors | Retries the same token, with a backoff of up to 5 min. |
   | `replay_detected`, `timestamp_stale`, `signature_invalid` | Re-signs and retries, once for `signature_invalid`, then reports `deposit_failed`. |
   | `400`, `payload_too_large`, `mailbox_unknown` | Reports `deposit_failed` (§8.3). |

   Retries continue until `closes_at`.

### 6.5 Declining (non-binding)

- **Who:** a vault that is certified, has never signed a ballot for the
  proposal, and whose cast state is not "unknown" (§6.6). Once it has
  declined it never casts.
- **When:** after the final `closes_at` (it checks the site for an
  extension first), at a time drawn uniformly from then to 90 minutes
  later. A vault locked then declines when it is unlocked, until
  `count_until`.
- **How:** `vote.decline {proposal_id, vk, cert_prefix, cert_sig, decline_sig}`
  on the service connection (§5.4), with
  `decline_sig = Sign(vk, "vettid/vote/1/declined", proposal_hash)`,
  retried until `count_until`. The service refuses a decline whose
  certificate or signature fails, from a connection it never certified
  (`not_certified`), or after `count_until` (`too_late`).
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

A vault restored from backup (the VMS restore event) marks every open
proposal it holds with cast state "unknown":
- it doesn't decline;
- its next cast uses `seq ≥ 2^30 + 2^24`, above any `seq` it could have
  signed before (a `seq` in that range shows a restore happened, nothing
  more);
- its §8.3 check accepts any ballot under its `vk`, and shows its
  choice.

## 7. The ballot box

### 7.1 Collecting and closing

- **When:** the ballot box (the service vault) collects from `opens_at`
  to `count_until`, acknowledging each message once its write is
  durable. For binding votes it collects the mix's batch (§3.4).
- **Sealed until close:** the box stores each deposit as received, with
  its `deposited_at` and token `jti`, and opens none until the closing
  document is published.
- **The closing:** at `closes_at`, if no extension was published before
  it, the service publishes the closing document (§8.5), anchored. It
  is the final close: from then on no extension is possible, the mix
  forwards, and the box opens what it holds and runs §7.2.
- **The arrival cutoff** is `closes_at`, by the time of the deposit's
  relay `msg_id` ULID, the same clock the vault reads (§6.4). For
  binding votes the mix enforces it, and the box takes every envelope
  in the mix's forward list.
- **Publication** waits until the mailbox is empty at `count_until`, and
  then until collects have come back empty for 10 minutes.
  **(chosen; not in the spec.)**
- **A restore of the service vault's table** while a proposal is open or
  unpublished loses acknowledged deposits. The service records it, the
  results say so (`restored: true`), and the vote is held again.

### 7.2 Checks, in order

1. **Format:** the envelope is 2,180 bytes, unseals, has exactly the
   1,024-byte padding, and `body` parses strictly.
2. **Proposal and time:** `proposal_id` is this proposal's, and
   (non-binding) the deposit's `msg_id` time is before `closes_at`.
3. **Token:** non-binding: the deposit's token is from a published pool
   of this proposal, and `pool_seq` is that pool's. Binding: the
   envelope is in the mix's forward list.
4. **Certificate:** `cert_prefix` is 32 bytes, and `cert_sig` verifies
   under `cert_key` for `cert_prefix ‖ cert_msg(proposal_hash, vk)`.
5. **Ballot:** `seq ≥ 1`, `vk` passes §2's checks, `ballot_sig` verifies
   under `vk` for `ballot_msg`, and `choice_id` is one of the
   proposal's.
6. **Repeats,** for each `vk`, over every ballot that passed 1–5 and
   every decline:
   - copies of one `(seq, choice_id)` are one ballot; if their
     `ballot_sig`s differ (only the holder of `vk` can make that), the
     lowest bytewise is kept;
   - if the highest `seq` has two different choices, or the `vk` also
     declined, the `vk` is a **conflict**: neither its ballots nor its
     decline count, and all of them are published (§8.1). Only the
     holder of `vk` can make one, and an honest vault never does
     (§6.1, §6.5, §6.6);
   - otherwise the ballot with the highest `seq` counts, and lower ones
     are superseded.

- **What is kept:** a counted ballot as
  `{vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`.
- **What is not kept:** `msg_id`, `jti`, `sender`, `deposited_at`,
  `pool_seq` and how many copies arrived are used for checks 2, 3 and 6,
  then discarded. No log line carries them.
- **Failures** are counted by reason (§8.5) and dropped.
- **Spent tokens:** the box keeps a count of spent `jti`s per pool,
  with no link to the ballots (§7.3).

### 7.3 Pool and quota watch (non-binding)

- **Re-issue:** when fewer than `members_of_record / 4` of the pools'
  tokens are unspent, and the vote has more than 15 minutes left, the
  box mints the next pool, publishes it (§3.5) and sends it. At most two
  re-issues.
- **Alarms:**
  - mailbox use above 20% of its quota (10,000 messages, 32 MiB;
    RELAY-PROTOCOL §7.2);
  - after close, more than 10% of deposits failing checks 1–4;
  - any conflict.

## 8. Publication and verification

### 8.1 Results

- **`results.json`** is a document (§8.5) with:
  - the proposal, every pool, the roster, any extensions and the
    closing, each with its signature;
  - non-binding: `members_of_record`, the record tags, `record_root`,
    the issuance tags and the declines; binding: the issuances (§5.3);
  - the counted ballots, sorted by `vk`, and `ballot_root`;
  - the conflicts, with all their ballots and declines;
  - the tally per choice, the counts, the failures by reason, and the
    count of members removed or suspended during the vote.
- **Signature:** detached,
  `results_sig = Sign(service IK, "vettid/vote/1/results", proposal_hash ‖ H(results_bytes))`.
- **Published and anchored** on votes.vettid.org (§3.5), with every
  pool's bytes.
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
- **Record leaf:** the 32-byte record tag (non-binding) or the 32-byte
  record key (binding), in sorted order.

### 8.3 What a member's vault checks

The check runs on `vote.closed`, and in any case at `count_until` + 1 h.
Without the results it retries with backoff for 7 days, and raises an
alarm after `count_until` + 24 h. The app runs pending checks whenever it
opens.

1. **Fetch:** the app fetches the proposal's documents from
   votes.vettid.org whole, over HTTPS, with no session and no query
   naming a voting key. The proof is computed in the vault (plan item
   5.7 adapts).
2. **The documents:**
   - each signature holds under the key that signed the proposal, and
     each anchor bundle verifies (§8.5 "Rekor profile");
   - the site shows no alarm for the service;
   - the proposal, pools, roster and extensions it received equal the
     published ones, and every published pool is one it holds;
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
   cast, no ballot under its `vk`. After a restore, §6.6.
   Binding: each of its mix receipts' hashes is in the mix's forward
   list; a missing one means the mix dropped it, a present one with no
   counted ballot means the box did.
5. **Proposals it never received:** for each proposal of its service on
   the site that it doesn't hold, it asks for it (§4.1). A refusal, when
   its connection was active at `record_at`, is evidence of exclusion.
6. **Outcome:** the vault shows the member the result. A failure names
   the check, and the vault keeps the evidence: the documents and
   bundles it received, the certificate, `blinded`/`blind_sig`,
   `ballot_sig`, the deposit outcomes and receipts, and any second
   proposal or pool.

### 8.4 What an observer checks

From the documents on votes.vettid.org:
1. **Signatures and anchors:** every signature holds, under the
   service's identity key on the service list; every document's anchor
   bundle verifies under a registered anchor key; the site shows no
   alarm for the service.
2. **Ballots:** every `cert_sig` holds under `cert_key` for
   `proposal_hash`; every `ballot_sig` under its `vk`; ballot,
   conflict and decline `vk`s are disjoint and each unique; every
   `choice_id` is one of the proposal's.
3. **Pools** (non-binding): one pool per `pool_seq`, at most four, pool 1
   the proposal's.
4. **Issuance:**
   - non-binding: record and issuance tags are each unique, and
     `issued ≤ members_of_record`;
   - binding: every issuance's `record_key` is in the roster, once, and
     its `certify_sig` verifies.
5. **Counts:** `ballots + conflicts + declined ≤ issued`. The rest,
   `unaccounted = issued − ballots − conflicts − declined`, is
   published: certified members with no counted ballot and no decline.
   Binding: `forwarded` (the mix's list) ≥ `ballots`.
6. **Tally and roots:** the tally and every root recompute.

### 8.5 Schemas

Every document is a JCS object (§2). A verifier refuses unknown fields,
missing fields, and fields of another type. `b64` is standard base64
with padding; `int` is a JSON integer (VAULT-MESSAGING §5.3); `time` is
an `int` of Unix seconds; `hash` is the `b64` of 32 bytes; `sig` the
`b64` of a 64-byte Ed25519 signature.

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
| `created_at`, `record_at`, `opens_at`, `closes_at`, `count_until` | `time` |
| `register_until` | `time`, binding only |
| `cert_key` | `b64` of the SPKI DER (§2) |
| `ballot_mailbox` | `{relay: string (https URL), mailbox: string}` |
| `ballot_kem` | `b64` of the MLKEM768X25519 public key |
| `max_casts` | `int` |
| `pool` | `hash`, non-binding only |
| `members_of_record` | `int`, non-binding only |
| `record_root` | `hash`, non-binding only |
| `admission` | binding only: `{key: b64 (SPKI DER, §2), tokens: int, mix: {relay: string, mailbox: string, receipt_key: b64}}` |
| `mirrors` | binding only: array of https URL strings, at least one |
| `outage_rule`, `statement` | string |

Signature: `Sign(IK, "vettid/vote/1/proposal", H(bytes))`.

**Pool:** `{v: 1, proposal_id, pool_seq: int (≥ 1), iat: time, exp: time, tokens: [string]}`.
Each token is the relay's token string as issued (RELAY-PROTOCOL §5.6),
not encoded again. Signature: §3.3.

**Roster** (binding): `{v: 1, proposal_id, members: [{record_key: b64, register_sig: sig}], members_of_record: int, record_root: hash}`,
`members` sorted by `record_key`. Signature:
`Sign(IK, "vettid/vote/1/roster", proposal_hash ‖ H(bytes))`.

**Extension:** `{v: 1, proposal_id, n: int (≥ 1), closes_at: time, count_until: time, outage: {from: time, to: time, source: string}, pool_seq?: int}`,
`pool_seq` naming its pool for non-binding votes. Signature:
`Sign(IK, "vettid/vote/1/extended", proposal_hash ‖ H(bytes))`.

**Closing:** `{v: 1, proposal_id, closes_at: time}`. Signature:
`Sign(IK, "vettid/vote/1/closing", proposal_hash ‖ H(bytes))`.

**Mix forward list** (binding): `{v: 1, proposal_id, envelopes: [hash]}`,
sorted. Signature: `Sign(mix receipt key, "vettid/vote/1/mix-list", proposal_hash ‖ H(bytes))`.

**`record_proof`:** `{index: int, tree_size: int, path: [hash]}`, where
`index` is the tag's position among the sorted tags and `path` the audit
path, from the leaf up.

**Deposit body:**
`{v: 1, proposal_id, vk: b64, cert_prefix: b64, cert_sig: b64, seq: int, choice_id: string, ballot_sig: sig, pool_seq?: int}`.
An ordinary JSON object (its bytes are not signed), parsed strictly.

**Results:**

| Field | Type |
|---|---|
| `v` | `1` |
| `proposal_id` | string |
| `proposal`, `roster`, `closing` | `{doc: b64, sig: sig}`; `roster` binding only |
| `pools`, `extensions` | arrays of `{doc: b64, sig: sig}`, by `pool_seq` and `n`; `pools` non-binding only |
| `record_tags`, `issued_tags` | arrays of `hash`, each sorted; non-binding only |
| `issuances` | binding only: array of `{record_key: b64, request_hash: hash, certify_sig: sig}`, by `record_key` |
| `declines` | non-binding only: array of `{vk, cert_prefix, cert_sig, decline_sig}`, by `vk` |
| `record_root`, `ballot_root` | `hash` |
| `ballots` | array of `{vk, cert_prefix, cert_sig, seq, choice_id, ballot_sig}`, by `vk` |
| `conflicts` | array, by `vk`, of `{vk, ballots: [ballot], declines: [decline]}` |
| `tally` | object: every choice `id` → `int` |
| `counts` | `{members_of_record, issued, declined, ballots, conflicts, unaccounted, removed, forwarded?}`, all `int` |
| `dropped` | object: reason → `int`, for every reason of `format`, `proposal`, `late`, `token`, `certificate`, `ballot`, `choice`, `superseded` |
| `restored` | boolean |

Signature: §8.1.

**Service list** (on votes.vettid.org, maintained by VettID):
`[{service_id, name, ik: b64, anchor_keys: [{key: b64 (SPKI DER), anchor_cert: sig}]}]`,
with `service_id` the lower-case hex of `H(ik)[0:16]`.

**Rekor profile.**
- **Entry:** `hashedrekord`, as the pinned Rekor version defines it; the
  digest is SHA-256 of the document bytes; the key is the anchor key as
  PKIX DER; the signature is ASN.1 DER ECDSA.
- **Bundle:** a Sigstore bundle (v0.3) with the transparency log entry,
  its inclusion proof and checkpoint.
- **A verifier checks:** that the entry's body names exactly
  `H(document)` and the anchor key, and that the anchor key is the
  proposal's service's (by its `anchor_cert`); the ECDSA signature; the
  inclusion proof against the checkpoint; and the checkpoint's signature
  under a log key in the Sigstore trusted root pinned in its release
  config.
- **Duplicates:** an anchor retried after a lost answer may make a
  second entry with the same digest. Entries with the same digest are
  one document, not a fork.
- **Time:** Rekor's v2 log gives no signed time; the OpenTimestamps
  proof (binding) does.
- The Rekor version and the trusted root are pinned in item 5.4, with a
  bundle vector for each document type (§11).

## 9. Trust boundaries

### 9.1 What the service vault learns

- **It learns:** who the members of record are; when each vault
  certified (binding: when each member first cast); which members
  declined and their `vk` (non-binding); the ballots and the tally, at
  close.
- **It does not learn,** from the ballot, certificate or token: whose a
  ballot is.
- **Non-binding votes:** ballots arrive the moment they are cast
  (§6.4), so an arrival time is a link for a service that also knows
  when the member was active:
  - a site visit or sign-in just before;
  - a certification just before, from a vault that was locked at
    opening (§5.2);
  - other traffic on the connection.

  A dishonest box could also open deposits before close and see a
  running tally (§7.1). Each non-binding proposal's `statement` says so.
- **Binding votes:** the box learns nothing from arrival: the mix
  forwards everything at close, shuffled and with no times, and every
  voter sent the same number of deposits.

### 9.2 Operator metadata (D5)

VettID runs the relay, the member-vault hosts and the service vault.

**The link:** the host's forwarder can see which vault process opened a
connection at time t, and the relay records a deposit arriving at t. An
operator who instruments both can join them. Together with the ballot
box's decryption, that links a ballot to a member.

| Option | What it closes | Cost |
|---|---|---|
| A. State it | Nothing. Each proposal says so. | None. Non-binding votes only. |
| B. An independent mix | Deposits go to a relay run by an independent party, which forwards them at close shuffled and with no times (§3.4). | An operating agreement, and the relay revision. The mix sees host addresses, not vaults. |
| C. Casting from the phone through an oblivious relay (RFC 9458) | The host sees no ballot traffic. | An OHTTP gateway, app work on both platforms, a third-party OHTTP relay. Phone hand-off times correlate with deposits. |
| D. The ballot box in an enclave (Phase 7) | The operator's access to decrypted ballots, but not the network link. | As planned. |

**Decided (owner, 2026-10-28): B for binding votes, A until then.**

**What VettID's operator still learns in a binding vote:** which vaults
deposited to the mix and when: whether, and from when, a member voted.
Nothing joins a deposit to a ballot: every voter makes `max_casts`
deposits (§6.4), each the same size (§6.3), the ballot carries no time
and a random `seq` (§6.1), and the mix forwards at once in random order
with no times. The mix alone, colluding with the operator, could join
them. The mix and its operator are chosen before the first binding vote.

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
    room left is phantom roster keys, and certified voters whose ballots
    went missing, whom §8.3 check 4 alerts.
  - **Non-binding:** the issuance tag of a member who certified, cast or
    declined is caught by observers or by that member (§8.3 check 3); a
    dropped decline is caught by its member. The room left is
    `unaccounted` (certified members whose vault neither cast nor
    declined), the removed count, and members whose vault never checks.
    Each non-binding proposal's `statement` says so.
- **Withholding:** dropping a real ballot or decline is caught by that
  member (§8.3). In a binding vote the mix's receipts and list tell
  whether the mix or the box dropped it.
- **Forks:** every document is anchored under the service's registered
  anchor key, which anyone can watch (§3.5).
- **The site:** votes.vettid.org can withhold or delay, not alter
  (§3.5).
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
| Certification refused or ignored | The vault retries until `closes_at`. A refusal is evidence (§8.3). An outage is covered by §10.2. |
| Proposal or pool not sent | The vault learns of it on votes.vettid.org and asks (§4.1, §4.2). A refusal is evidence. |
| Registration refused (binding) | Evidence; the roster shows the key missing (§3.6). |
| Ask gate (VAULT-MESSAGING §10.4.1) | Registering, certifying, depositing and declining are not asks. |
| Site sign-in blocked | Voting needs no site sign-in. |
| votes.vettid.org down, or refusing a reader | The vault deposits on the Rekor bundles after 10 minutes, and defers the site checks (§6.4). |
| Rekor down | The service can't anchor, so it can't open, extend or close a vote; §10.2 covers it. |
| Ballot mailbox flooded with junk | Pool tokens carry `quota: {msgs: 1, bytes: 4096}`, and the pool is held by members only. Junk is at most one 4 KiB message per token. The box collects continuously and alarms at 20% (§7.3). |
| Pool exhaustion by a member | **Met only with admission tokens** (§3.4). Re-issue and `max_casts` slow it in a non-binding vote. |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits retry. |
| Service vault, relay, mix or host outage | Deposits wait in the ballot mailbox (14 days) or at the mix. Requests wait on the connection. Beyond the §10.2 bound, the vote is extended. |
| The member's vault locked, or its host restarted | Casting needs the app and so an unlocked vault. The app reminds the member before close. Binding registration needs the vault unlocked once in its window. |
| Clock skew at close | The app stops casting two minutes before close; the vault and the box use the same clock (§6.4, §7.1). |
| Removal during the vote | The member's certificate stays valid and their ballot counts. A non-binding member removed after certifying can't decline; the results count removals (§8.1). |

### 10.2 The outage rule and evidence (fixed before opening)

- **What counts:** an outage, shown by the service vault's own health
  checks or the status page of the relay, the mix, votes.vettid.org or
  Rekor, longer than 1 hour within the voting window.
- **Extension:** the service extends `closes_at` and `count_until` by
  the outage, rounded up to the hour, by extensions totalling at most
  24 h. Each extension is published and anchored **before the current
  `closes_at`** (§3.5), then sent as `vote.extended`.
  - Non-binding: it comes with a new pool, minted against the new close
    within the relay's lifetime from its own `iat`.
  - Binding: no pool; the mix learns the new close from the site.
  - The box has opened nothing (§7.1), so the decision is made without a
    tally.
- **An outage at close:** if the service can't publish an extension or
  the closing within 24 h of `closes_at` (Rekor or the site being down),
  the vote is void and held again. The mix forwards nothing until the
  closing is published.
- **Evidence and reports:** a vault's evidence (§8.3) is shown to the
  member, who can post a report to votes.vettid.org after `count_until`,
  with no session. A report carries flags only, never a `vk`, a
  certificate or a time: an outage of 30 minutes or more, certification
  refused or withheld, decline refused, proposal refused, the site
  unreachable, and which §8.3 check failed. The site publishes the
  counts per flag, as information. A binding vote is held again only on
  evidence that can be checked: a mix receipt missing from the forward
  list, an anchored fork, or a refusal the service signed.
- **(chosen; not in the spec.)**

## 11. Test vectors

Produced by the reference implementation (items 5.3 and 5.4) and copied
by vettid-vault; a copied vector that stops matching is a
stop-and-report item.
1. **Derivations:** every §5.1 value from a fixed `proposal_seed` and
   `proposal_hash`, including `r` and the token values.
2. **RFC 9474:** the RFC's RSABSSA-SHA384-PSS-Randomized vectors, one
   over a real `cert_msg` with a fixed key and the derived values, and
   the exact SPKI DER of a fixed key.
3. **`ballot_msg` and `ballot_sig`**, a decline, a registration and a
   certify signature.
4. **The deposit:** a body, its padding, and its sealed envelope with
   fixed keys and randomness.
5. **Merkle:** trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion
   proof for every leaf of the 5-leaf tree.
6. **Documents:** each document type's bytes, signature and anchor
   bundle, plus refusals: non-canonical bytes and duplicate names.
7. **Ballot box:** one deposit each for a bad certificate, a bad ballot
   signature, an unknown choice, an unknown pool, a late deposit, and
   repeats (a copy; copies with different signatures; a lower `seq`; a
   conflict; a ballot and a decline).
8. **Ed25519:** every §2 rule: small-order keys, including their
   non-canonical encodings; `y ≥ p`; `x = 0` with the sign bit set; a
   non-canonical `S`; and valid signatures.

## 12. Decisions for the owner

Items 1–13 were approved by the owner on 2026-10-28, item 3 as amended
in 0.4.0. Items 14–17 were decided on 2026-10-29; item 18 is open. Items 6 and 7 change
in 0.6.0 (marked).

**Departures from the plan:**
1. **Labels:** `vettid/vote/1/...`, the VMS convention (§2).
2. **No timestamp in the ballot** (§6.1).
3. **Ballots are sent the moment they are cast** (owner decision
   2026-10-28). For non-binding votes, arrival time is a stated link
   (§9.1); the mix removes it for binding votes (§3.4, §9.2).
4. **A 409 deposits again with another token,** instead of stopping at
   "probably cast" (§6.4).
5. **The pool goes over the connection** to every member, identical,
   and its tokens are not published before the count (§3.3).

**Choices the plan and the specifications leave open:**

6. **Changed in 0.6.0:** a random **proposal seed** per proposal, in the
   vault's encrypted state and erased after the check, replaces the
   single vote root, so a later compromise exposes no past vote (§5.1).
7. **Changed in 0.6.0:** blinding values are derived from the proposal
   seed (§5.1).
8. **The member may cast again until `closes_at`,** up to `max_casts`
   times; the highest `seq` counts (§6.1, §6.2).
9. **The seal** is the VMS sealed envelope with the deposit body as its
   inner plaintext (§6.3).
10. **Publication** waits for the mailbox to drain (§7.1).
11. **Documents are anchored** in Rekor under a registered anchor key
    per service (§3.5).
12. **The outage rule** covers the relay, mix, site and Rekor, with a
    24-hour cap; reports are information, and only checkable evidence
    repeats a binding vote (§10.2).
13. **JCS documents** are verified as exact canonical bytes, with
    detached signatures (§2).

**Decided 2026-10-29:**

14. **votes.vettid.org** publishes every proposal and its documents, and
    members learn of proposals there (§3.5).
15. **No automatic abstain.** In a non-binding vote, a vault that didn't
    vote declines after close (§6.5); in a binding vote, a member who
    doesn't vote never certifies (§5.2).
16. **Results only at close** (§7.1).
17. **Binding votes:** registration before opening (§3.6), certification
    at the first cast (§5.2), and exactly `max_casts` deposits per voter
    (§6.4).
18. **Binding votes need an independent mirror** of votes.vettid.org
    (§3.5). **To decide:** who runs it.

**Decided (owner, 2026-10-28):**
- **D5:** an independent mix for binding votes; non-binding votes state
  the boundary (§9.2).
- **D6 and D7:** relay admission tokens (§3.4), a RELAY-PROTOCOL
  revision. The pool stays the interim mechanism, for non-binding votes
  only.
- **D8:** Sigstore Rekor as the anchor, plus OpenTimestamps for binding
  votes (§3.5).

## Changes

- **0.6.0 (2026-10-29):**
  - Binding votes: registration of a record key per vault before
    opening, with a published roster; certification at the first cast,
    signed by the record key; exactly `max_casts` deposits per voter;
    mix receipts and a published forward list (§3.4, §3.6, §5.2, §6.4);
    an independent mirror of votes.vettid.org (§3.5).
  - Anchoring under one registered, certified anchor key per service,
    which anyone can watch, instead of a key per proposal; bundles travel
    with the messages so vaults check offline; a Rekor profile (§3.5,
    §8.5).
  - Declines carry the voting key and its certificate; a refused decline
    is evidence; a key that declined and cast is a conflict; the `cast`
    refusal is gone (§6.5, §7.2).
  - Issuance is checked in three states (§8.3).
  - Pool 1 is in the proposal; a vault holds every published pool before
    depositing and draws across them (§3.3, §6.4).
  - The pool is no longer in the ballot (§6.1).
  - A closing document makes the final close; extensions are published
    before the current close, add up to 24 h, and cover the mix, the site
    and Rekor (§7.1, §10.2).
  - Reports carry no voting key, and only checkable evidence repeats a
    binding vote (§10.2).
  - A per-proposal seed replaces the vote root (§5.1); restore handling
    (§6.6); a table restore voids the vote (§7.1).
  - Exact Ed25519 checks (§2); `max_casts` for every vote; at least two
    real choices; quorum counting; the deposit cutoff on one clock; pool
    parts; schemas for the roster, extension, closing and mix list.

- **0.5.0 (2026-10-29):**
  - Proposals, pools, extensions and results published on
    votes.vettid.org and anchored in Rekor.
  - The automatic abstain replaced by a decline after close.
  - The box opens deposits only at close.
  - `seq` random and in the deposit body; the `day` gone.
  - The seal pinned to the VMS sealed envelope with no time inside.
  - Admission tokens, extensions, conflicts, clock skew, removal during
    a vote, Ed25519 verification and schemas specified.

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
  - Pool tokens are minted at opening, within the relay's lifetime.

- **0.3.0 (2026-10-28):** owner decisions.
  - D5: an independent mix for binding votes.
  - D6 and D7: relay admission tokens (§3.4) replace the pool for
    binding votes.
  - D8: Rekor, as a Sigstore bundle, plus OpenTimestamps for binding
    votes.

- **0.2.0 (2026-10-28):**
  - Every member deposits once, in a shared deposit phase, with abstain
    by default.
  - The proposal and pool hashes are in the certificate and the ballot.
  - Pool tokens carry a 1-message, 4 KiB quota, and the pool is not
    published during the vote.
  - Token lifetimes fit the relay's.
  - Publication waits for the mailbox to drain, and results are
    anchored outside the service.
  - Blinding values are derived, and the certification write is
    conditional.
  - The deposit answers are complete, with re-signing.
  - JCS is verified as exact bytes with detached signatures.
  - The seal pins an anonymous sender.
  - Eligibility edges are stated.
  - The outage rule is measured by the vaults.
  - D5 is re-examined (an independent mix recommended); D6–D8 added.
- **0.1.0:** first full draft.
