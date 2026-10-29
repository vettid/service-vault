# Ballot Protocol

**Status:** 0.5.0 (2026-10-29), for review before more ballot code
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

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only a member of record (§3.2) obtains a certificate, one per proposal. |
| One vote | At most one counted ballot per certificate: the valid ballot with the highest `seq` for a voting key counts (§7.2). A member can change their vote until close by casting again. |
| Secrecy of the choice | No one can tell how a member voted: not the service vault (which is also the ballot box), the relay, or the mix. The certificate is blind (§5) and the deposit names nothing of the member (§6.3). **What is not secret:** *whether* a member voted. The service learns it from declines (§6.5), and the operator of the vault hosts from deposit traffic (§9.2). For non-binding votes, a ballot's arrival time is also a link for a service that knows when the member was active (§9.1); for binding votes the mix (§9.2) removes it. |
| Results only at close | No one sees a tally before `closes_at`. The ballot box stores deposits sealed until close (§7.1). A dishonest box could open them early; non-binding votes state this, and the mix removes it for binding votes. |
| Verifiability | A member confirms that their ballot is counted as cast, or that their decline is recorded, and that everyone sees the same results (§8.3). An observer confirms that every counted ballot has a valid certificate, that no voting key counts twice, that `ballots + declined ≤ issued ≤ members_of_record`, and the tally (§8.4). |
| Publicity | Every proposal is published on votes.vettid.org and anchored in Rekor when it is created (§3.5), so a member learns of it without the service, and every member sees the same one. |
| Availability | No one but the member can stop an eligible member from casting a counted ballot. Against the service itself the protocol gives detection, not prevention: a service that refuses or drops is caught (§8.3, §10). Closing pool exhaustion by a member needs relay admission tokens (§3.4). |
| Receipt-freeness | Out of scope (owner decision). The vault's post-vote check (§8.3) shows the member their counted choice, and so works as a receipt. Casting again gives no protection against a coercer who checks the outcome. |

## 2. Notation and primitives

- `‖` is concatenation. `u16`, `u32` and `u64` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- **Labels** follow the VMS convention (VAULT-MESSAGING §4.1): ASCII
  strings embedding the version, `vettid/vote/1/...`. Where a label
  starts a hashed or signed string, a `0x00` follows it as a separator.
  **(chosen; differs from the plan:** the plan's `"vettid-vote-v1"`
  follows vettid-dev.)
- **Signatures:** `Sign(sk, label, m)` is `suite.Sign` from vettid-vault
  `vms/suite`, Ed25519 over `label ‖ m`.
  - **Verification** is RFC 8032 §5.1.7 cofactorless: `[S]B = R + [k]A`,
    with `S < L` and canonical encodings of `A` and `R`. A public key
    that is one of the eight small-order points is refused. This is Go's
    `ed25519.Verify` plus the small-order check; §11 item 8 has vectors,
    so that every library agrees.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
  Another form is refused.
- **JSON documents** (the proposal, a pool, an extension, the results;
  §8.5) are JCS (RFC 8785). They are signed over their exact bytes, with
  a detached signature. A verifier parses strictly (VAULT-MESSAGING §5.3:
  no duplicate names), then re-serializes per RFC 8785 and refuses the
  document unless the bytes are identical. **(chosen; not in the spec.)**
  - Times in them are Unix seconds, as JSON integers.
  - Binary values are standard base64 with padding (VAULT-MESSAGING
    §5.3).
  - **Message bodies** follow VAULT-MESSAGING §5.3; a document travels in
    a body as the base64 of its bytes.
- **Sorting** of tags, voting keys and other binary values is by their
  raw bytes, never by their base64.
- **The signing key:** the service identity key that signs a proposal
  signs every document and message of that proposal. A service vault
  starts no `identity.rotate` from a proposal's creation until its
  results are published.
- **Blind signatures** are RFC 9474 RSABSSA-SHA384-PSS-Randomized: RSA
  with a modulus of exactly 2048 bits, `e = 65537`, SHA-384, MGF1-SHA-384,
  salt length 48, and a 32-byte message prefix.
  - The key is an id-RSASSA-PSS SubjectPublicKeyInfo carrying exactly
    those parameters, as RFC 9578 §6.5 specifies for Privacy Pass (RFC
    9474 §6.2 requires the OID; RFC 4055 §3.1 defines the parameters).
    The SHA-384 AlgorithmIdentifiers omit their parameters (RFC 5754 §2),
    and the trailer field is the default. The member vault parses it by
    hand and refuses anything else; Go's `x509` does not parse it.
  - The key is used for this protocol and this variant only (RFC 9474
    §6.2).
  - The service vault uses `cloudflare/circl` `blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` in-repo with
    `math/big`. vettid-vault adds no third-party code to the enclave
    (vettid-vault README; V3-NOTES).
  - RSA-2048 is the plan's choice: the key lives for one vote and is
    destroyed at publication. Blinding hides the message whatever the
    signer's computing power (RFC 9474 security considerations).
- **Anchor signatures** are ECDSA P-256 with SHA-256 over a document's
  exact bytes (FIPS 186-5), under a key made for one proposal (§3.5). It
  is the algorithm Rekor and the standard Sigstore tools verify in a
  `hashedrekord` entry; Ed25519 there would have to be its pre-hashed
  variant.
- **The seal** is the VMS v2 envelope in sealed mode (§6.3).

## 3. Proposal

### 3.1 Contents

The proposal is a JCS document (§8.5 has the schema).

| Field | Meaning |
|---|---|
| `proposal_id` | A ULID. |
| `service` | The service identity key that signs it (§2). |
| `title`, `text` | UTF-8; `text` ≤ 16 KiB. |
| `choices` | 2–16 entries `{id, label}`, in display order, with `id` matching `[a-z0-9-]{1,32}` and unique. The id `abstain` is reserved and always present, for a member who wants to be counted without choosing. |
| `quorum` | The plan's quorum rule, as text, and the number of ballots it implies. |
| `binding` | Whether the vote is binding: it then needs the mix and admission tokens (§3.4, §9.2). |
| `record_at` | The roster snapshot, at or before the proposal's creation (§3.2). |
| `opens_at` | Certification opens; members can vote. |
| `closes_at` | The last moment to cast: ballots deposited before it count. `closes_at − opens_at ≤ 7 days − 1 h`. |
| `count_until` | `closes_at` + 2 h: the ballot box collects deposits and declines until then (§7.1). |
| `cert_key` | The RSA public key (§2). |
| `anchor_key` | The ECDSA P-256 public key that anchors this proposal's documents (§3.5). |
| `ballot_mailbox` | Relay URL and mailbox id: a relay keypair for this proposal only. |
| `ballot_kem` | The ballot box's KEM public key for this proposal. |
| `members_of_record` | The count. |
| `record_root` | The Merkle root of the record tags (§3.2). |
| `admission` | Binding votes only: the admission key, the number of tokens per member, and the mix (§3.4). |
| `outage_rule` | The rule of §10.2, as text. |
| `statement` | What the vote does not protect, in words for members: the links of §9.1 and §9.2 that apply to it. |

- **Timing:** the window's cap keeps the pool's tokens, minted at
  `opens_at` with `iat` backdated 60 s and `exp = closes_at + 15 min`
  (§3.3), within the relay's open-token lifetime (RELAY-PROTOCOL §5.6;
  168 h deployed).
- **Signature:**
  `proposal_sig = Sign(service IK, "vettid/vote/1/proposal" ‖ 0x00, proposal_bytes)`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds the certificate
  and the ballot to this one proposal (§5.1, §6.1).
- **Publicity:** the proposal is published and anchored before it is
  sent to anyone (§3.5). A vault deposits a ballot only under the
  public proposal (§6.4), so a proposal of a member's own gains the
  service nothing.

### 3.2 Members of record and record tags

- **Members of record** are the connections active on the service vault's
  roster at `record_at`: connected, not removed, not suspended. One
  connection is one member. Two consequences, stated with the proposal:
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
  `record_secret` and an inclusion proof of their tag. The vault checks
  it at once, against the root in the signed proposal.
- **Issuance tags:**
  `issued_tag = H("vettid/vote/1/issued" ‖ 0x00 ‖ proposal_id ‖ record_secret)`,
  for each member certified (§5.3).
- **Decline tags:**
  `declined_tag = H("vettid/vote/1/declined" ‖ 0x00 ‖ proposal_id ‖ record_secret)`,
  for each member whose vault declined (§6.5).
- The service knows every `record_secret`, so it can publish any tag.
  What stops it is that each member's vault checks its own tags both
  ways: present when it took the step, and absent when it didn't
  (§8.3).
- **Removal and suspension during the vote:** membership of record is
  fixed at `record_at`. A member removed or suspended later is refused
  certification if not yet certified (`not_active`, §5.2), and their
  issued certificate stays valid, since ballots are anonymous. Their
  vault keeps its vote state and runs its checks (§8.3) even after the
  connection is removed. A `vote.*` message arriving on a removed
  connection is dropped.

### 3.3 The token pool (non-binding votes)

- **What it is:** one-shot open deposit tokens for the ballot mailbox
  (RELAY-PROTOCOL §5.6: scope `deposit_open`, `sub` `*`, a fresh ULID
  `jti` each). They are minted locally, with no relay call, at
  `opens_at`.
  - `iat` is backdated by 60 s (§5.2 there).
  - `exp = closes_at + 15 min`.
  - Each carries `quota: {msgs: 1, bytes: 4096}` (RELAY-PROTOCOL §5.2;
    a deposit is 2,180 bytes, §6.3). A junk deposit on a pool token is
    therefore one small message.
- **The pool** is a JCS document (§8.5) with `pool_hash = H(pool_bytes)`
  and
  `pool_sig = Sign(service IK, "vettid/vote/1/pool" ‖ 0x00, proposal_hash ‖ u32(pool_seq) ‖ pool_hash)`.
  Every ballot names its pool's `pool_seq` and `pool_hash` (§6.1).
- **Publicity:** when a pool is minted, its `pool_hash`, `pool_sig` and
  anchor are published (§3.5), but not its tokens. A vault uses a pool
  only once its hash is public (§6.4), and checks that it holds every
  pool the results list (§8.3). So a pool shown to one member is
  caught.
- **Size:** `2 × members_of_record + 64` tokens.
- **Distribution:** sent at `opens_at` over the connection, to every
  member of record, as identical bytes (§4.2). Its tokens are **not
  published before `count_until`**, so only members hold them.
  - Over about 120 members of record, a pool exceeds one message: the
    245,760-byte inner limit (VAULT-MESSAGING §5.5), with about 365-byte
    tokens. It then goes as identical numbered parts.
  - The bytes the service sends grow with N² (N pools of 2N tokens).
    Through the relay's per-key byte budget of 64 KiB/s per relay process
    (RELAY-PROTOCOL §7.2 limit 11):
    - N = 300: about 90 MB, minutes;
    - N = 1,000: about 1 GB, hours.
    - **Beyond about 500 members this needs admission tokens** (§3.4).
  - Re-issue is limited to two further pools per vote, besides the pool
    that comes with an extension (§10.2). Its trigger is §7.3.
- **What bearer tokens cannot do (§10.1):** a member, who holds the pool,
  can spend its tokens with junk. Only members of record hold it, and
  each junk deposit is one 4 KiB message, but the pool can still be
  exhausted. Binding votes therefore use admission tokens.

### 3.4 Relay admission tokens and the mix (binding votes)

The owner decided (D5–D7) that binding votes use tokens checked when a
deposit is accepted, issued per member at certification without the
issuer learning which token is whose, and an independent mix. Both are a
RELAY-PROTOCOL revision (vettid.org), to be specified there. What this
protocol needs from it:

- **The admission key** is an RFC 9474 key like `cert_key` (§2), made for
  this proposal, and named in the signed proposal with the token count
  `k` and the mix's relay URL and mailbox. A vault refuses tokens that
  don't verify under that key.
- **Issuance:** with the certificate (§5.2), the box blind-signs `k`
  token values for every member, the same `k` for all: `k = max_casts +
  2`, where `max_casts` (for example 6) is stated in the proposal and the
  2 cover retries. A member casts at most `max_casts` times; the app says
  so.
  - The token values and their blinding values are derived like `r`
    (§5.1), with index `i`, so a retried `vote.certify` is identical, and
    the conditional write (§5.2) covers them with the certificate.
  - No token is ever issued later, so issuance says nothing about how
    often a member casts.
- **Checking:** **the mix** verifies and spends each token when it
  accepts a deposit, and answers the vault at once, so a refused token
  can be retried before close. The relay accepts the mix's batch under
  the mix's own credential.
  - The mix refuses deposits at or after `closes_at` by its own clock.
    It learns a valid extension (§4.4) from votes.vettid.org (§3.5), and
    holds until the extended close.
  - At close it forwards every accepted deposit to the ballot mailbox,
    in a random order, at once, with no times.
- **The ballot** names the admission key instead of a pool:
  `pool_seq = 0` and `pool_hash = H(admission key SPKI bytes)` in
  `ballot_msg` and the leaf (§6.1, §8.2), so the encoding doesn't
  change.
- **Effects:**
  - A member can spend only their own `k` tokens, so pool exhaustion is
    no longer possible.
  - Distribution is O(N): one message per member, at certification.
  - There is no pool to re-issue, publish or equivocate.
- **Until it exists:** the pool (§3.3) is used for non-binding votes, and
  binding votes wait.

### 3.5 Publication on votes.vettid.org

**(chosen; differs from the plan,** which published results on
member.vettid.org only. Owner decision 2026-10-29.)

votes.vettid.org is a public site run by VettID, separate from every
service vault. Members learn of proposals there without the service, and
every document of a vote is there, the same for every reader.

- **What a service vault uploads,** in order:
  1. the proposal, before it is sent to any member;
  2. each pool's hash and signature, when it is minted (its tokens only
     with the results);
  3. an extension, if any (§10.2);
  4. the results (§8.1).
- **The anchor:** before uploading, the service vault anchors each
  document in Sigstore's public transparency log, Rekor: a `hashedrekord`
  entry with `H(document bytes)` and the document's anchor signature
  under `anchor_key` (§2). The Sigstore bundle of Rekor's answer (log
  index, inclusion proof and signed checkpoint) goes up with the
  document.
  - `anchor_key` is made for the proposal, named in the signed proposal,
    and destroyed once the results are anchored. Every entry under it is
    one of this proposal's documents, and no entry can be added later.
  - A pool is anchored over its full bytes, which Rekor sees only as a
    hash.
- **What the site checks** before it publishes an upload:
  - The service is registered: its identity key is on the site's
    service list, which VettID maintains.
  - The service's signature, the exact JCS bytes, and the anchor bundle,
    against Rekor's key and `anchor_key`.
  - The order above, and the document's fields against the proposal (its
    `proposal_id`, the times, `pool_seq` in order).
- **Write-once:** each document has one path. The site accepts the same
  bytes again, refuses different bytes, and never changes or removes a
  document.
- **Discovery:** the site keeps an index of proposals that are open or
  closed within the last 30 days, with each one's service, hash and
  times. The app fetches the whole index, with no session, so the site
  doesn't learn which services a member is connected to. The app hands
  the vault the entries of its services.
- **Monitor:** the site watches Rekor for entries under the `anchor_key`
  of every proposal it holds, from the proposal's anchoring until a day
  after the results. An entry that is not one of the published documents
  is an alarm, published with the proposal. It means the service
  anchored a document it didn't publish: a split view.
- **Time anchor:** for binding votes the site also stamps each document's
  hash with OpenTimestamps. It upgrades the proof once Bitcoin confirms
  it and publishes it. Vaults don't wait for it.
- **Reports** from members (§10.2) are posted to the site after the vote.
- **What the site can and cannot do:**
  - It cannot alter a document: the signatures and Rekor catch that.
  - It could withhold a document, or show readers different indexes.
    Rekor and the service's messages to the vault limit what that gains
    (§8.3).
  - It is independent of an organisation's service vault, not of VettID.
    For VettID's own member service the two are run by the same party,
    and each such proposal's `statement` says so.

## 4. Messages from the service

Session-mode messages on the service connection, in the standard VMS
inner (VAULT-MESSAGING §5.3). Each is answered with a response that
names it (`re`), so the service knows it arrived. A vault without the
vote feature answers `unsupported_type`, which today's rules would
instead drop and audit. That needs the §6.4 change of item 5.1.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, record_secret, record_proof}`
- `proposal` is the §3.1 bytes, in base64. `record_proof` is
  `{index, tree_size, path}` (§8.5).
- This is the only per-member message besides certification. Only
  `record_secret` and `record_proof` differ between members.
- **A second proposal:** the vault keeps the first valid proposal for a
  `proposal_id`. A different one later is kept as evidence and not used,
  and the vault reports it (§8.3).
- **Requested:** a vault that sees a proposal of its service on
  votes.vettid.org (§3.5) but holds none sends `vote.request
  {proposal_id}` (§5.4), and the service answers with `vote.proposal` or
  refuses.

### 4.2 `vote.pool`

`{proposal_id, pool_seq, part, parts, pool_part, pool_sig}`
- The vault assembles all `parts`, then checks `pool_hash` and
  `pool_sig`.
- A different pool under a `pool_seq` it already holds is kept as
  evidence and not used. The vault reports it in §8.3.

### 4.3 `vote.closed`

`{proposal_id, results_hash}`
- The vault doesn't depend on it: it runs its check at `count_until`
  + 1 h anyway (§8.3).

### 4.4 `vote.extended`

`{proposal_id, extension, extension_sig}`
- `extension` is the base64 of a JCS document `{v, proposal_id,
  closes_at, count_until, reason}` (§8.5).
- `extension_sig = Sign(service IK, "vettid/vote/1/extended" ‖ 0x00, proposal_hash ‖ H(extension_bytes))`.
- It is published and anchored (§3.5), and the vault uses it only once
  it is public. It comes with a new pool (§10.2).

## 5. Certification

### 5.1 The voting key and what is certified

- **The vote root** is 32 random bytes, created once per member vault and
  kept in the vault's DEK-encrypted state as feature data
  (VAULT-MESSAGING §3.3). It survives `credential.rotate`,
  `credential.reset`, and PIN and password changes. Because it is opened
  by the vault's unlock rather than by the password, the vault can
  certify and decline on its own (§5.2, §6.5).
  - The member's choice still needs the member's approval (§6.2).
  - **(chosen; not in the spec;** an alternative to keeping it in the
    credential, which would need the password for every step and be lost
    at `credential.reset`.)
- **The voting key:**
  `seed = HKDF-SHA256(ikm = vote_root, salt = proposal_hash, info = "vettid/vote/1/voting-key", L = 32)`,
  and `vk` is the Ed25519 key from `seed`. Deriving from `proposal_hash`
  rather than `proposal_id` keeps the values of two proposals under one
  id apart.
- **Blinding values are derived, not stored**, so a retry is identical
  even after a restore from backup:
  - `msg_prefix = HKDF-SHA256(vote_root, proposal_hash, "vettid/vote/1/msg-prefix", 32)`
  - `pss_salt = HKDF-SHA256(vote_root, proposal_hash, "vettid/vote/1/pss-salt", 48)`:
    the salt of RFC 9474's EMSA-PSS encoding, which is otherwise random.
  - `blind_seed = HKDF-SHA256(vote_root, proposal_hash, "vettid/vote/1/blind", 32)`
  - **The blinding factor `r`** comes from `blind_seed` by rejection
    sampling. For `ctr = 0, 1, 2, …`:
    1. `c = SHA-384(blind_seed ‖ u32(ctr) ‖ 0x00) ‖ … ‖ SHA-384(blind_seed ‖ u32(ctr) ‖ 0x05)`,
       which is 288 bytes, truncated to its first 256.
    2. `r = OS2IP(c)`, taken if `0 < r < n` and `gcd(r, n) = 1`.
    3. Otherwise the next `ctr`.

    The expected number of tries is under 2.
  - The blinded message is then `blinded = r^e · OS2IP(EMSA-PSS-ENCODE(msg_prefix ‖ cert_msg; pss_salt)) mod n`
    (RFC 9474 §4.2 with the salt and `r` fixed).
  - Admission tokens (§3.4) use the same derivations with the labels
    `vettid/vote/1/token-value`, `-token-prefix`, `-token-salt` and
    `-token-blind`, and with `u32(i)` appended to the `info`.
  - These values stay secret, since the vote root is, so blinding is
    unchanged.
  - **(chosen; not in the spec.)**
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_hash ‖ vk`.

### 5.2 Request and answer

- **When:** at once on receiving a valid `vote.proposal`, with no member
  action (a vault started by the member's own state, not an ask; the ask
  gate, VAULT-MESSAGING §10.4.1, never applies). A vault unlocked at
  `opens_at` certifies then. A locked vault certifies when it is next
  unlocked, which may be just before its member casts; non-binding
  proposals state this link (§9.1).
- **How:**
  1. The vault computes `blinded = Blind(cert_key, msg_prefix ‖ cert_msg; r)`
     and sends `vote.certify {proposal_id, blinded}` (with
     `admission_blinded`, a list of `k`, for binding votes).
  2. **The service vault** checks:
     - the proposal is open: `opens_at ≤ now < closes_at`;
     - the connection is a member of record and still active;
     - this connection has no certificate yet, or has one for the same
       request.

     It records the issuance with a conditional write that succeeds only
     if no issuance exists for the connection, or one exists for the same
     request. Only then does it sign: `blind_sig = BlindSign(cert_sk, blinded)`,
     and the admission tokens likewise.
     - It answers `vote.certified {proposal_id, blind_sig}` (with
       `admission_sigs`), as the response to the request (`re`).
     - A repeated request gets the stored answer.
     - Refusals are the response with `status: error` and `error.code`
       one of `already_certified`, `not_open`, `closed`, `not_of_record`
       or `not_active`.
  3. **The vault** computes `cert_sig = Finalize(cert_key, msg_prefix ‖ cert_msg, blind_sig, r)`,
     which includes verifying it. It keeps `(cert_prefix = msg_prefix, cert_sig)`
     and records "certified".
     - If `Finalize` fails, it keeps `blinded` and `blind_sig` as
       evidence, retries once, and then reports
       `certification_failed` (§8.3).
     - With no answer, it retries the same request with backoff until
       `closes_at`.

The service sees `blinded` and `blind_sig`, which tell it nothing about
`vk` or `cert_sig` without `r`.

### 5.3 The issuance list

The service vault records `connection, proposal_id, request, answer`
(the conditional write above). It publishes the issuance tags of
certified members at publication (§8.1), then deletes the records.

### 5.4 Messages from the member's vault

| Type | Body | Answer |
|---|---|---|
| `vote.certify` | `{proposal_id, blinded, admission_blinded?}` | `vote.certified {proposal_id, blind_sig, admission_sigs?}`, or an error (§5.2). |
| `vote.decline` | `{proposal_id}` | `{proposal_id}` with `status: ok`, or an error `not_certified`, `cast` or `too_late` (§6.5). |
| `vote.request` | `{proposal_id}` | `vote.proposal` (§4.1) as the response, or an error `not_of_record` or `unknown_proposal`. |

## 6. Casting

### 6.1 The ballot

- `ballot_msg = proposal_hash ‖ u32(seq) ‖ u32(pool_seq) ‖ pool_hash ‖ lp(choice_id)`
- `ballot_sig = Sign(vk, "vettid/vote/1/ballot" ‖ 0x00, ballot_msg)`
- **`seq`** orders a member's casts without counting them:
  - the first cast draws `seq` uniformly from [1, 2^31);
  - each further cast adds a step drawn uniformly from [1, 2^16];
  - a vault restored from backup adds 2^24 before its next cast, so
    that it never reuses a `seq` it signed before the restore;
  - the vault stores the new `seq` before signing with it, and refuses a
    cast that would pass 2^32 − 1.

  The highest counts, so the order holds however deposits arrive, even
  shuffled by the mix, and the published `seq` says nothing about how
  often the member cast.
- `pool_seq` and `pool_hash` are those of the pool whose token carries
  the deposit (for binding votes, §3.4).
- **No timestamp.** **(chosen; differs from the plan:** a signed time
  would be published with the ballot.) The box keeps no arrival time
  (§7.2).

### 6.2 Choosing

- **Casting:** the member casts in the app, at any time from `opens_at`
  to `closes_at`. The vault signs only with the member's approval inside
  the credential's unlock window (VAULT-MESSAGING §3.5.3), and sends the
  ballot at once (§6.4). It is not an ask.
  - The app refuses to cast in the last two minutes before `closes_at`,
    by the vault's clock, so that skew doesn't drop a ballot.
- **Changing:** the member may cast again until `closes_at`, up to
  `max_casts` times for binding votes. The new ballot has a higher
  `seq`, and the highest counts (§7.2).
  - **(chosen; not in the spec:** still one counted ballot per key.)
- **Not voting:** a member who never casts has no ballot. Their vault
  declines after close (§6.5). **(Owner decision 2026-10-29;** the
  earlier automatic abstain is gone.)
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
  `{v: 1, proposal_id, vk, cert_prefix, cert_sig, seq, pool_seq, pool_hash, choice_id, ballot_sig}`
  (§8.5), padded per VAULT-MESSAGING §5.4. Every honest body is under
  1,023 bytes and lands in the same 1,024-byte bucket, so every deposit
  is a 2,180-byte envelope.
- Nothing in the deposit identifies the vault. A member's own kid or
  key there would link the ballot.

### 6.4 Sending it

1. **Before the first deposit,** the app fetches the proposal's page on
   votes.vettid.org (§3.5) and the vault checks:
   - the proposal it holds is the published one (same hash), with a
     valid anchor;
   - the pool it will use is published and anchored (non-binding votes),
     or the admission key is the proposal's (binding votes);
   - any extension it holds is the published one.

   It doesn't deposit until these hold. A failure is evidence (§8.3).
2. **Time.** At once, when the member casts (owner decision 2026-10-28).
   For binding votes the deposit goes to the mix (§3.4), which holds it
   until close.
   - The ballot and the certificate are in the vault's encrypted state,
     and survive a restart.
3. **Token.** Non-binding: a token drawn uniformly at random from the
   newest complete published pool, among those it hasn't tried. Binding:
   the next unspent admission token.
4. **Key.** It makes a fresh Ed25519 key for this deposit and signs the
   request with it (RELAY-PROTOCOL §4.1). An open token needs no
   registered sender (§5.6).
   - Every attempt is signed anew, with a fresh timestamp. A
     byte-identical request within 90 s is refused as a replay.
5. **Outcomes:**

   | Answer | What the vault does |
   |---|---|
   | `2xx` | Reads the time of the `msg_id` ULID in the answer (RELAY-PROTOCOL §6.2). Before `closes_at`: records "cast", and keeps `vk`, the certificate, `ballot_sig`, `seq` and the pool hash for §8.3. At or after it: the deposit was late, and it records "late". |
   | `409 token_used` (spent by someone else, or by a first attempt whose answer was lost) | Deposits again with another token and a fresh key. A second copy is harmless: it has the same `seq` and choice (§7.2). **(chosen; differs from the plan,** which stopped at "probably cast".) |
   | `token_expired`, `token_revoked`, `token_invalid` | Drops that token. With none left, waits for the next pool. |
   | `quota_exceeded` with `quota: "token"` | Drops the token. |
   | Mailbox `quota_exceeded`, 5xx, network errors | Retries the same token, with a backoff of up to 5 min. |
   | `replay_detected`, `timestamp_stale` | Re-signs and retries. |
   | `payload_too_large`, `mailbox_unknown` | Reports `deposit_failed` (§8.3). |

   Retries continue until `closes_at`.

### 6.5 Declining

- **Who:** a vault that holds a certificate for the proposal and has
  never signed a ballot for it.
- **When:** at a time drawn uniformly from `closes_at` to `closes_at` +
  90 min. A vault locked then declines when it is unlocked, until
  `count_until`.
- **How:** `vote.decline {proposal_id}` on the service connection
  (§5.4), retried until `count_until`. The service records the
  connection's `declined_tag` (§3.2), and refuses a decline from a
  connection it never certified (`not_certified`) or after `count_until`
  (`too_late`).
- **What it does:** each certified member is then accounted for, by a
  ballot (anonymous) or a decline (not anonymous). The service has no
  unused certificate to vote with, except those of members who neither
  cast nor declined (§9.3).
- It goes over the connection, not to the ballot mailbox, so nothing is
  deposited at a fixed time. It tells the service who didn't vote;
  §1 says so.
- **(chosen; not in the spec;** owner decision 2026-10-29, replacing the
  automatic abstain.)

## 7. The ballot box

### 7.1 Collecting

- **When:** the ballot box (the service vault) collects from `opens_at`
  to `count_until`, acknowledging each message once it is stored. For
  binding votes it collects from the mix, which forwards everything at
  `closes_at` (§3.4).
- **Sealed until close:** before `closes_at` the box stores each
  deposit as received, with its `deposited_at`, and opens none. At
  `closes_at` it opens them and runs §7.2. Nothing that reveals a choice
  exists before close, including for a decision to extend (§10.2).
- **The arrival cutoff** is `closes_at`, by the relay's `deposited_at`.
  For binding votes, the mix enforces it (§3.4) and the box takes every
  deposit in the mix's close batch.
- **Publication** waits until the mailbox is empty at `count_until`, and
  then until collects have come back empty for 10 minutes.
  **(chosen; not in the spec.)**

### 7.2 Checks, in order

1. **Format:** the envelope is 2,180 bytes, unseals, has the right
   padding, and `body` parses strictly.
2. **Proposal and time:** `proposal_id` is this proposal's, and
   `deposited_at < closes_at` (non-binding).
3. **Pool:** `pool_seq` and `pool_hash` name a pool this proposal issued,
   or (binding) are `0` and the admission key's hash.
4. **Certificate:** `cert_prefix` is 32 bytes, and `cert_sig` verifies
   under `cert_key` for `cert_prefix ‖ cert_msg(proposal_hash, vk)`.
5. **Ballot:** `seq ≥ 1`, `vk` passes §2's key check, `ballot_sig`
   verifies under `vk` for `ballot_msg`, and `choice_id` is one of the
   proposal's.
6. **Repeats**, for each `vk`, over every ballot that passed 1–5:
   - copies with the same `seq` and `choice_id` are one ballot;
   - if the highest `seq` has two different choices, the `vk` is a
     **conflict**: no ballot of it counts, not even a lower `seq`, and
     both conflicting ballots are published (§8.1). Only the holder of
     `vk` can make one, and an honest vault never does (§6.1);
   - otherwise the ballot with the highest `seq` counts, and lower ones
     are superseded.

- **What is kept:** a counted ballot as
  `{vk, cert_prefix, cert_sig, seq, pool_seq, pool_hash, choice_id, ballot_sig}`.
- **What is not kept:** `msg_id`, `jti`, `sender` and `deposited_at` are
  used for checks 2 and 6, then discarded. No log line carries them.
- **Failures** are counted by reason (§8.5) and dropped.
- **Spent tokens:** the box keeps a set of spent `jti`s, with no link to
  the ballot rows, to count what is spent (§7.3).

### 7.3 Pool and quota watch

- **Re-issue:** when fewer than `members_of_record / 4` of the newest
  pool's tokens are unspent, and the vote has more than 15 minutes left,
  the box mints the next pool (`pool_seq + 1`), publishes it (§3.5) and
  sends it. There are at most two re-issues (§3.3).
- **Alarms:**
  - mailbox use above 20% of its quota (10,000 messages, 32 MiB;
    RELAY-PROTOCOL §7.2);
  - after close, more than 10% of deposits failing checks 1–4;
  - any conflict.

## 8. Publication and verification

### 8.1 Results

- **`results.json`** is a JCS document (§8.5) with:
  - the proposal, every pool and any extension, each with its signature;
  - `members_of_record`, the record tags and `record_root`;
  - the issuance tags and the decline tags;
  - the counted ballots, sorted by `vk`, and `ballot_root`;
  - the conflicts, with both ballots of each;
  - the tally per choice, the counts, and the failures by reason.
- **Signature:** detached,
  `results_sig = Sign(service IK, "vettid/vote/1/results" ‖ 0x00, H(results_bytes))`.
- **Published and anchored** on votes.vettid.org (§3.5), with the
  anchor bundle, and for binding votes the OpenTimestamps proof.
- **Then:** `vote.closed` to every member of record; the RSA private
  keys and `anchor_key` are destroyed, and the issuance records deleted.

### 8.2 Merkle trees

- RFC 6962 §2.1 with SHA-256:
  - leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`;
  - split at the largest power of two below n;
  - the empty tree is `H("")`;
  - inclusion proofs are RFC 6962 audit paths.
  - This replaces vettid-dev's hex-string tree, which had no leaf/node
    separation and duplicated odd nodes.
- **Ballot leaf:**
  `lp(vk) ‖ lp(cert_prefix) ‖ lp(cert_sig) ‖ u32(seq) ‖ u32(pool_seq) ‖ pool_hash ‖ lp(choice_id) ‖ lp(ballot_sig)`.
  The certificate is in the leaf (plan §8). The leaves are in the order
  of `ballots` in the results: by `vk`.
- **Record leaf:** the 32-byte tag, in sorted order.

### 8.3 What a member's vault checks

The check runs on `vote.closed`, and in any case at `count_until` + 1 h.
Without the results it retries with backoff for 7 days, and raises an
alarm after `count_until` + 24 h. The app runs pending checks whenever it
opens.

1. **Fetch:** the app fetches the proposal's documents from
   votes.vettid.org whole, over HTTPS, with no session and no query
   naming a voting key. The proof is computed in the vault (plan item
   5.7 adapts).
2. **The file:**
   - `results_sig` holds, under the key that signed the proposal.
   - The anchor bundle verifies: `anchor_key`'s signature, the
     inclusion proof and Rekor's checkpoint, against Rekor's key pinned
     in the vault's release config.
   - The proposal bytes equal the ones it received.
   - Every pool in the file is one the vault holds, and every pool it
     holds is in the file, under its `pool_seq`.
   - An extension the vault received equals the one in the file.
   - `H(file)` equals `vote.closed`'s, if one came.
3. **Its tags:**
   - its record tag is present;
   - its issuance tag is present **if and only if** it certified: a tag
     it never asked for means its certificate went to someone else;
   - its decline tag is present **if and only if** its decline was
     answered `ok`.
4. **Its ballot:** if it cast, exactly one ballot under its `vk`, with
   its latest `seq`, its stored `cert_sig` and `pool_hash`, and that
   cast's choice, and the inclusion proof reaches `ballot_root`. If it
   never cast, no ballot under its `vk`.
5. **Proposals it never received:** for each proposal of its service on
   the site that it doesn't hold, it asks for it (§4.1). A refusal, when
   its connection was active at `record_at`, is evidence of exclusion.
6. **Outcome:** the vault shows the member the result. A failure names
   the check, and the vault keeps the evidence: the proposal bytes, the
   pools, the certificate, `blinded`/`blind_sig`, `ballot_sig`, the
   deposit outcome and any second proposal or pool. The member can post
   it as a report (§10.2).

### 8.4 What an observer checks

From the documents on votes.vettid.org:
1. **Signatures and anchors:** every signature holds, under the
   service's identity key as listed on the site; every document's
   anchor verifies under `anchor_key`; the site shows no alarm for the
   proposal.
2. **Ballots:** every `cert_sig` holds under `cert_key` for
   `proposal_hash`; every `ballot_sig` holds under its `vk`; `vk`s are
   unique; every `choice_id` is one of the proposal's.
3. **Pools:** exactly one pool per `pool_seq`, every one published when
   it was minted, and every ballot's pool is one of them.
4. **Tags:** record, issuance and decline tags are each unique, and
   `declined ≤ issued ≤ members_of_record`. Tags can't be matched to
   one another without the `record_secret`s, so the members check that
   part (§8.3).
5. **Counts:** `ballots + conflicts + declined ≤ issued`. The rest,
   `unaccounted = issued − ballots − conflicts − declined`, is published:
   certified members who neither cast a counted ballot nor declined.
6. **Tally and roots:** the tally and both roots recompute.

### 8.5 Schemas

Every document is a JCS object (§2). A verifier refuses unknown fields,
missing fields, and fields of another type. `b64` is standard base64
with padding; `int` is a JSON integer (VAULT-MESSAGING §5.3); `time` is
an `int` of Unix seconds; `hash` is the `b64` of 32 bytes.

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
| `cert_key` | `b64` of the SPKI DER (§2) |
| `anchor_key` | `b64` of the SPKI DER of a P-256 key (id-ecPublicKey, prime256v1, uncompressed point) |
| `ballot_mailbox` | `{relay: string (https URL), mailbox: string}` |
| `ballot_kem` | `b64` of the MLKEM768X25519 public key |
| `members_of_record` | `int` |
| `record_root` | `hash` |
| `admission` | present if and only if `binding`: `{key: b64 (SPKI DER, §2), max_casts: int, tokens: int, mix: {relay: string, mailbox: string}}` |
| `outage_rule`, `statement` | string |

**Pool:** `{v: 1, proposal_id, pool_seq: int (≥ 1), iat: time, exp: time, tokens: [string]}`.
Each token is the relay's token string as issued (RELAY-PROTOCOL §5.6),
not encoded again.

**Extension:** `{v: 1, proposal_id, closes_at: time, count_until: time, reason: string}`.

**`record_proof`** (in `vote.proposal`): `{index: int, tree_size: int, path: [hash]}`,
where `index` is the tag's position among the sorted tags and `path` is
the RFC 6962 audit path, from the leaf up.

**Deposit body:**
`{v: 1, proposal_id, vk: b64, cert_prefix: b64, cert_sig: b64, seq: int, pool_seq: int, pool_hash: hash, choice_id: string, ballot_sig: b64}`.
It is an ordinary JSON object (its bytes are not signed), parsed
strictly.

**Results:**

| Field | Type |
|---|---|
| `v` | `1` |
| `proposal_id` | string |
| `proposal` | `{doc: b64, sig: b64}`: the proposal's bytes and `proposal_sig` |
| `pools` | array of `{doc: b64, sig: b64}`, by `pool_seq` |
| `extension` | `{doc: b64, sig: b64}`, present if there was one |
| `record_tags`, `issued_tags`, `declined_tags` | arrays of `hash`, each sorted |
| `record_root`, `ballot_root` | `hash` |
| `ballots` | array of ballots, sorted by `vk`; each `{vk, cert_prefix, cert_sig, seq, pool_seq, pool_hash, choice_id, ballot_sig}` as in the deposit body |
| `conflicts` | array, sorted by `vk`, of `{vk, ballots: [ballot, ballot]}` with the two ballots sorted by `ballot_sig` |
| `tally` | object: every choice `id` → `int` |
| `counts` | `{members_of_record, issued, declined, ballots, conflicts, unaccounted}`, all `int` |
| `dropped` | object: reason → `int`, for every reason of `format`, `proposal`, `late`, `pool`, `certificate`, `ballot`, `choice`, `duplicate`, `superseded` |

**On votes.vettid.org,** each proposal has a directory named by its
`proposal_id`, holding each document (`proposal.json`, `pool-<n>.json`,
`extension.json`, `results.json`), its signature (`.sig`), its anchor
bundle (`.sigstore.json`) and, for binding votes, its OpenTimestamps
proof (`.ots`). Before `count_until` a pool is represented by
`pool-<n>.hash` (its `pool_hash`) instead of its bytes. The site's own
document specifies the paths, the upload API and the index.

## 9. Trust boundaries

### 9.1 What the service vault learns

- **It learns:** who the members of record are, which vaults certified
  and when, which declined, the ballots and the tally (at close).
- **It does not learn,** from the ballot, certificate or token: whose a
  ballot is.
- **Non-binding votes:** ballots are sent the moment they are cast
  (§6.4), so an arrival time is a link for a service that also knows
  when the member was active:
  - a site visit or sign-in just before;
  - a certification just before, from a vault that was locked at
    opening (§5.2);
  - other traffic on the connection.

  Tokens from the shared pool add nothing. A dishonest box could also
  open deposits before close and see a running tally (§7.1). Each
  non-binding proposal's `statement` says so.
- **Binding votes:** the mix forwards everything at close, shuffled and
  with no times, so arrival says nothing to the box.

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

**What VettID's operator still learns with the mix:**
- which vaults deposited to the mix, how often and when: whether a
  member voted, and how many times, but not the choice;
- nothing that joins a deposit to a ballot: the ballot carries no time,
  its `seq` is random (§6.1), every deposit is the same size (§6.3), and
  the mix forwards at once in random order with no times.

The mix and its operator are chosen before the first binding vote.

### 9.3 Residual trust

- **Phantom members of record:** connections the service controls,
  added before `record_at`. Only the count and outside knowledge of the
  membership show them. A binding vote publishes `members_of_record` on
  votes.vettid.org before `opens_at` and invites an independent count.
- **Stuffing:** to add a ballot, the service needs a certificate, which
  it can mint for a `vk` of its own, and an issuance tag to cover it.
  - Taking the tag of a member who certified, cast or declined: caught
    by observers (`ballots + declined > issued`) or by that member's
    tags (§8.3 check 3).
  - Taking the tag of a member who never certified: caught by that
    member's vault, which sees an issuance tag it never asked for, if
    it runs the check (§8.3).
  - Not sending a member the proposal: the vault learns of it on
    votes.vettid.org (§8.3 check 5).
  - **The slack:** members who certified but neither cast nor declined,
    published as `unaccounted`. A binding vote states a maximum for it,
    and the minimum vault version needed to take part.
- **Withholding:** dropping a real ballot or decline is caught by that
  member (§8.3).
- **Split views:** every document is anchored under a key made for the
  proposal and destroyed after the results. A second document under it
  is an alarm on votes.vettid.org (§3.5). Members and observers check
  the same anchored documents.
- **The site:** votes.vettid.org can withhold, not alter (§3.5).
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
| Certification refused or ignored | Every vault certifies at opening and retries until `closes_at`. A refusal is evidence (§8.3). An outage is covered by §10.2. |
| Proposal not sent | The vault learns of it on votes.vettid.org and asks (§4.1). A refusal is evidence. |
| Ask gate (VAULT-MESSAGING §10.4.1) | Certification, choosing, depositing and declining are not asks. Nothing in the vote path is a service challenge. |
| Site sign-in blocked | Voting needs no site sign-in. |
| Ballot mailbox flooded with junk | Pool tokens carry `quota: {msgs: 1, bytes: 4096}`, and the pool is held by members only. Junk is at most one 4 KiB message per token, about 2 MiB for a pool of 600, well under the 32 MiB quota. The box collects continuously and alarms at 20% (§7.3). |
| **Pool exhaustion by a member** | **Met only with admission tokens** (§3.4). With the pool, re-issue (§7.3) and the flood guard slow it but don't stop a determined member. So binding votes use admission tokens. |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits retry. |
| Service vault, relay or host outage | Deposits wait in the ballot mailbox (14 days). Certification requests wait on the connection. Beyond the §10.2 bound, the vote is extended. |
| The member's vault locked, or its host restarted, when the member casts | Casting needs the app and so an unlocked vault. The app reminds the member before close. |
| Clock skew at close | The app stops casting two minutes before close; the vault reads the relay's time on each deposit (§6.4). |

### 10.2 The outage rule and reports (fixed before opening)

- **During the vote:** the service vault's own health checks and the
  relay's status page count. If they show an outage of the relay or the
  ballot mailbox longer than 1 hour, the service extends `closes_at` and
  `count_until` by the outage, rounded up to the hour, at most once, by
  up to 24 h. The extension states the outage it is for, with the
  relay's status entries.
  - It is published and anchored (§3.5) before `vote.extended` goes out.
  - **It comes with a new pool,** minted against the new close, so that
    tokens don't expire at the old one. Its `exp` is within the relay's
    lifetime from its own `iat`.
  - The box hasn't opened any deposit (§7.1), so the decision is made
    without a tally.
- **Reports, after the vote:** the app posts a member's report to
  votes.vettid.org, with no session, after `count_until`. It carries only
  flags: an outage of 30 minutes or more while trying to deposit or
  certify; certification refused; the proposal refused; and which §8.3
  check failed.
  - A report signed under the member's `vk` with its certificate counts
    as verified, one per `vk`. It doesn't link a ballot further than the
    flags do.
  - The site publishes the counts per flag with the proposal, verified
    and unverified apart.
  - A binding vote states the share of verified reports at which the
    vote is repeated.
- **(chosen; not in the spec.)**

## 11. Test vectors

Produced by the reference implementation (items 5.3 and 5.4) and copied
by vettid-vault; a copied vector that stops matching is a
stop-and-report item.
1. **Derivations:** `vk`, `msg_prefix`, `pss_salt`, `blind_seed` and
   `r` from a fixed `vote_root` and `proposal_hash`, and the admission
   token values.
2. **RFC 9474:** the RFC's RSABSSA-SHA384-PSS-Randomized vectors, plus
   one over a real `cert_msg` with a fixed key and the derived values.
3. **`ballot_msg` and `ballot_sig`.**
4. **The deposit:** a body, its padding, and its sealed envelope with
   fixed keys and randomness.
5. **Merkle:** trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion
   proof for every leaf of the 5-leaf tree.
6. **Documents:** proposal, pool, extension and results bytes with
   their signatures and anchor signatures, plus refusals: non-canonical
   bytes and duplicate names.
7. **Ballot box:** one deposit each for a bad certificate, a bad ballot
   signature, an unknown choice, an unknown pool, a late deposit, and
   repeats (a copy; a lower `seq`; a conflict).
8. **Ed25519:** the small-order public keys, a non-canonical `S`, and
   valid signatures.

## 12. Decisions for the owner

Items 1–13 were approved by the owner on 2026-10-28, item 3 as amended
in 0.4.0. Items 14–17 are new in 0.5.0.

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

6. **The vote root** lives in the vault's encrypted state, not the
   credential, so the vault can certify and decline without the
   password (§5.1).
7. **Blinding values are derived** from the vote root (§5.1).
8. **The member may cast again until `closes_at`;** the highest `seq`
   counts (§6.1, §6.2).
9. **The seal** is the VMS sealed envelope with the deposit body as its
   inner plaintext (§6.3).
10. **Publication** waits for the mailbox to drain (§7.1).
11. **Documents are anchored** in Rekor (§3.5).
12. **The outage rule** uses the service's checks and the relay's
    status, with a 24-hour cap; members report after the vote (§10.2).
13. **JCS documents** are verified as exact canonical bytes, with
    detached signatures (§2).

**New in 0.5.0:**

14. **votes.vettid.org** publishes every proposal and its documents,
    anchored, and members learn of proposals there (§3.5). (Owner
    decision 2026-10-29.)
15. **No automatic abstain; a vault that didn't vote declines after
    close** over its connection (§6.5). (Owner decision 2026-10-29.)
16. **Results only at close:** the box opens no deposit before
    `closes_at` (§7.1). (Owner decision 2026-10-29.)
17. **Random `seq`,** an anchor key per proposal, and a fixed number of
    admission tokens per member (§6.1, §3.5, §3.4).

**Decided (owner, 2026-10-28):**
- **D5:** an independent mix for binding votes; non-binding votes state
  the boundary (§9.2).
- **D6 and D7:** relay admission tokens (§3.4), a RELAY-PROTOCOL
  revision. The pool stays the interim mechanism, for non-binding votes
  only.
- **D8:** Sigstore Rekor as the anchor, plus OpenTimestamps for binding
  votes (§3.5).

## Changes

- **0.5.0 (2026-10-29):**
  - Proposals, pools, extensions and results are published on
    votes.vettid.org and anchored in Rekor under a per-proposal ECDSA
    P-256 key, which Rekor's `hashedrekord` verifies; the site monitors
    Rekor for a second document (§3.5). Members learn of proposals
    there, and ask for one they weren't sent (§4.1, §8.3).
  - The automatic abstain is replaced by a decline after close (§6.5),
    with decline tags; each certified member's vault checks its issuance
    and decline tags both ways (§8.3).
  - The box opens deposits only at close (§7.1).
  - `seq` is random with random steps, and is in the deposit body; the
    `day` is gone from the ballot and the leaf (§6.1, §6.3, §8.2).
  - The seal is pinned: the VMS sealed envelope, with the deposit body as
    inner plaintext and no time (§6.3).
  - Derivations use `proposal_hash` (§5.1). A second proposal is kept as
    evidence (§4.1).
  - Conflicts void the voting key and are published (§7.2).
  - Admission tokens: a fixed count per member, checked by the mix, the
    key in the proposal, derived values, and the ballot encoding (§3.4).
  - An extension comes with a new pool, and is published first (§10.2).
  - Clock skew at close, removal and suspension during the vote, the
    signing key across a vote, Ed25519 verification, schemas (§8.5), and
    the post-vote retry schedule.
  - The SPKI encoding cites RFC 9578 §6.5.

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
