# Ballot Protocol

**Status:** 0.4.1 (2026-10-28), for review before any ballot code
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
| One vote | One counted ballot per certificate: the valid ballot with the highest `seq` for a voting key counts (§7.2). A member can change their vote until close by casting again. |
| Secrecy against the service | The service vault, which is also the ballot box, cannot tell whose a ballot is from the certificate (blind, §5) or the token (a shared pool, §3.3, or admission tokens, §3.4). Every member of record certifies at opening, so certification times say nothing. A ballot is sent the moment the member casts it (§6.4, owner decision). **Its arrival time is a link** for whoever also knows when the member was active (for example a site visit just before). For binding votes the mix (§9.2, D5) holds and shuffles deposits until close, which removes it. Non-binding votes state it. |
| Verifiability | A member confirms their ballot is counted as cast, and that it is in the same results everyone sees (§8.3). An observer confirms every counted ballot has a valid certificate, no voting key counts twice, `ballots ≤ issued ≤ members_of_record` (equal when every vault deposited), and the tally (§8.4). |
| Decline-ability | A member who does nothing has their vault cast an abstain (§6.2). Declining and abstaining look the same. |
| Availability | No one but the member can stop an eligible member from casting a counted ballot (§10). Closing pool exhaustion by a member needs relay admission tokens, a RELAY-PROTOCOL revision (D7, decided: §3.4). |
| Receipt-freeness | Out of scope (owner decision). |

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
  - Verifiers use RFC 8032 verification with canonical `S`, and reject a
    small-order public key, so that every library agrees.
- **`proposal_id`** is a canonical upper-case ULID: 26 ASCII bytes.
  Another form is refused.
- **Times** inside signed data are Unix seconds (`u64`), as LEASH and
  ICE use (VAULT-MESSAGING §10.11). Message bodies use VMS timestamps
  (§5.3 there).
- **JCS documents** (the proposal, a pool, the results) are signed over
  their exact bytes, with a detached signature. A verifier parses
  strictly (VAULT-MESSAGING §5.3: no duplicate names), then
  re-serializes per RFC 8785 and refuses the document unless the bytes
  are identical. **(chosen; not in the spec.)**
- **Blind signatures** are RFC 9474 RSABSSA-SHA384-PSS-Randomized: RSA
  with a modulus of exactly 2048 bits, `e = 65537`, SHA-384, MGF1-SHA-384,
  salt length 48, and a 32-byte message prefix.
  - The key is an id-RSASSA-PSS SubjectPublicKeyInfo carrying exactly
    those parameters (RFC 9474's encoding section; RFC 4055). The member
    vault parses it by hand and refuses anything else; Go's `x509` does
    not parse it.
  - The service vault uses `cloudflare/circl` `blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` in-repo with
    `math/big`. vettid-vault adds no third-party code to the enclave
    (vettid-vault README; V3-NOTES).
  - RSA-2048 is the plan's choice: the key lives for one vote and is
    destroyed at publication. Blinding hides the message whatever the
    signer's computing power (RFC 9474 security considerations).
- **The seal** is single-shot public-key encryption with the VMS suite-2
  KEM and AEAD (§6.3).

## 3. Proposal

### 3.1 Contents

| Field | Meaning |
|---|---|
| `proposal_id` | A ULID. |
| `title`, `text` | UTF-8; `text` ≤ 16 KiB. |
| `choices` | 2–16 entries `{id, label}`, with `id` matching `[a-z0-9-]{1,32}` and unique. The id `abstain` is reserved and always present (§6.2). |
| `quorum` | The plan's quorum rule, as text, and the number it implies. |
| `binding` | `false` until D5 is decided (§9.2). |
| `record_at` | The roster snapshot, at or before the proposal's creation (§3.2). |
| `opens_at` | Certification opens; members can vote. |
| `closes_at` | The last moment to cast: ballots deposited before it count. An hour before it, the vault of a member who hasn't cast sends an abstain (§6.2). `closes_at − opens_at ≤ 7 days − 1 h`. |
| `count_until` | `closes_at` + 2 h: the ballot box collects until then (§7.1). |
| `cert_key` | The RSA public key (§2). |
| `ballot_mailbox` | Relay URL and mailbox id: a relay keypair for this proposal only. |
| `ballot_kem` | The ballot box's KEM public key for this proposal. |
| `members_of_record` | The count. |
| `record_root` | The Merkle root of the record tags (§3.2). |
| `outage_rule` | The rule of §10.2, as text. |

- **Timing:** the window's cap keeps the pool's tokens, minted at
  `opens_at` with `iat` backdated 60 s and `exp = closes_at + 15 min`
  (§3.3), within the relay's open-token lifetime (RELAY-PROTOCOL §5.6;
  168 h deployed).
- **Signature:** the proposal is a JCS document;
  `proposal_sig = Sign(service IK, "vettid/vote/1/proposal" ‖ 0x00, proposal_bytes)`.
- **Hash:** `proposal_hash = H(proposal_bytes)` binds the certificate
  and the ballot to this one proposal (§5.1, §6.1). So a proposal sent
  to one member only, for example with a key of its own, is visible in
  the results (§8.3, §8.4).

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

### 3.3 The token pool

- **What it is:** one-shot open deposit tokens for the ballot mailbox
  (RELAY-PROTOCOL §5.6: scope `deposit_open`, `sub` `*`, a fresh ULID
  `jti` each). They are minted locally, with no relay call, at
  `opens_at`.
  - `iat` is backdated by 60 s (§5.2 there).
  - `exp = closes_at + 15 min`.
  - Each carries `quota: {msgs: 1, bytes: 4096}` (RELAY-PROTOCOL §5.2;
    a deposit is about 1 KiB, §6.3). A junk deposit on a pool token is
    therefore one small message.
- **The pool** is a JCS document `{proposal_id, pool_seq, tokens}`, with
  `pool_hash = H(pool_bytes)` and
  `pool_sig = Sign(service IK, "vettid/vote/1/pool" ‖ 0x00, proposal_hash ‖ u32(pool_seq) ‖ pool_hash)`.
  Every ballot names its pool's `pool_seq` and `pool_hash` (§6.1). So
  two pools under one `pool_seq`, or one shown to a single member, are
  visible in the results.
- **Size:** `2 × members_of_record + 64` tokens.
- **Distribution:** sent at `opens_at` over the connection, to every
  member of record, as identical bytes (§4.2). It is **not published
  before `count_until`**, so only members hold it.
  - Over about 120 members of record, a pool exceeds one message: the
    245,760-byte inner limit (VAULT-MESSAGING §5.5), with about 365-byte
    tokens and base64. It then goes as identical numbered parts.
  - The bytes the service sends grow with N² (N pools of 2N tokens).
    Through the relay's per-key byte budget of 64 KiB/s per relay process
    (RELAY-PROTOCOL §7.2 limit 11):
    - N = 300: about 90 MB, minutes;
    - N = 1,000: about 1 GB, hours.
    - **Beyond about 500 members this needs a different channel**: the
      app fetching the pool (D6, §12).
  - Re-issue is limited to two further pools per vote. Its trigger is
    §7.3.
  - **The pool is the interim mechanism**, until relay admission tokens
    (§3.4) replace it, for scale (D6) as well as availability (D7).
- **What bearer tokens cannot do (§10.1):** a member, who holds the pool,
  can spend its tokens with junk. Only members of record hold it, and
  each junk deposit is one 4 KiB message, but the pool can still be
  exhausted.

### 3.4 Relay admission tokens (D6, D7: decided 2026-10-28)

The owner decided to replace the pool with tokens the relay itself
checks, issued per member at certification without the issuer learning
which token is whose. This is a RELAY-PROTOCOL revision (vettid.org,
VettID's relay), to be specified there. What this protocol needs from
it:

- **Issuance:** with the certificate (§5.2), the ballot box blind-signs
  `k` fresh random token values for the member (`k` small, for example
  4: retries and a second copy). It uses a per-proposal admission key,
  in the style of Privacy Pass's publicly verifiable tokens (RFC 9578,
  blind RSA per RFC 9474). Issuance is per connection and counted, so a
  member holds `k` tokens, not a shared pool.
- **Checking:** the relay accepts a deposit to the ballot mailbox only
  with an unspent token that verifies under the admission key named for
  that mailbox. It spends the token value once.
  - The relay learns nothing about the member.
  - The ballot box learns nothing from the token beyond its validity.
- **Effects:**
  - A member can spend only their own `k` tokens, so pool exhaustion is
    no longer possible.
  - Distribution is O(N): one message per member, at certification.
  - There is no pool to re-issue, publish or equivocate.
  - The ballot and its leaf name the admission key instead of
    `pool_seq` and `pool_hash`.
- **Until it exists:** the pool (§3.3) is used for non-binding votes.
  Binding votes wait for admission tokens.

## 4. Messages from the service

Session-mode messages on the service connection, in the standard VMS
inner (VAULT-MESSAGING §5.3). Each is answered with a response that
names it (`re`), so the service knows it arrived. A vault without the
vote feature answers `unsupported_type`, which today's rules would
instead drop and audit. That needs the §6.4 change of item 5.1.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, record_secret, record_proof}`
- `proposal` is the §3.1 bytes, in base64.
- This is the only per-member message besides certification. Only
  `record_secret` and `record_proof` differ between members.

### 4.2 `vote.pool`

`{proposal_id, pool_seq, part, parts, pool_part, pool_sig}`
- The vault assembles all `parts`, then checks `pool_hash` and
  `pool_sig`.
- A different pool under a `pool_seq` it already holds is kept as
  evidence and not used. The vault reports it in §8.3.

### 4.3 `vote.closed`

`{proposal_id, results_hash, anchor}`
- `anchor` names where the results hash is anchored outside the service
  (§8.1).
- The vault doesn't depend on it: it runs its check at `count_until`
  + 1 h anyway (§8.3).

### 4.4 `vote.extended`

`{proposal_id, closes_at, count_until, reason}`, signed like a pool:
`Sign(service IK, "vettid/vote/1/extended" ‖ 0x00, proposal_hash ‖ u64(closes_at) ‖ u64(count_until))`
(§10.2).

## 5. Certification

### 5.1 The voting key and what is certified

- **The vote root** is 32 random bytes, created once per member vault and
  kept in the vault's DEK-encrypted state as feature data
  (VAULT-MESSAGING §3.3). It survives `credential.rotate`,
  `credential.reset`, and PIN and password changes. Because it is opened
  by the vault's unlock rather than by the password, the vault can
  certify and abstain on its own (§5.2, §6.2).
  - The member's choice still needs the member's approval (§6.2).
  - **(chosen; not in the spec;** an alternative to keeping it in the
    credential, which would need the password for every step and be lost
    at `credential.reset`.)
- **The voting key:**
  `seed = HKDF-SHA256(ikm = vote_root, salt = H(proposal_id), info = "vettid/vote/1/voting-key", L = 32)`,
  and `vk` is the Ed25519 key from `seed`. The salt is vettid-dev's
  choice; the `ikm` is not (theirs was the identity key, which rotates).
- **Blinding values are derived, not stored**, so a retry is identical
  even after a restore from backup:
  - `msg_prefix = HKDF-SHA256(vote_root, H(proposal_id), "vettid/vote/1/msg-prefix", 32)`
  - `pss_salt = HKDF-SHA256(vote_root, H(proposal_id), "vettid/vote/1/pss-salt", 48)`:
    the salt of RFC 9474's EMSA-PSS encoding, which is otherwise random.
  - `blind_seed = HKDF-SHA256(vote_root, H(proposal_id), "vettid/vote/1/blind", 32)`
  - **The blinding factor `r`** comes from `blind_seed` by rejection
    sampling. For `ctr = 0, 1, 2, …`:
    1. `c = SHA-384(blind_seed ‖ u32(ctr) ‖ 0x00) ‖ … ‖ SHA-384(blind_seed ‖ u32(ctr) ‖ 0x05)`,
       which is 288 bytes, truncated to its first 256.
    2. `r = OS2IP(c)`, taken if `0 < r < n` and `gcd(r, n) = 1`.
    3. Otherwise the next `ctr`.

    The expected number of tries is under 2.
  - The blinded message is then `blinded = r^e · OS2IP(EMSA-PSS-ENCODE(msg_prefix ‖ cert_msg; pss_salt)) mod n`
    (RFC 9474 §4.2 with the salt and `r` fixed).
  - These values stay secret, since the vote root is, so blinding is
    unchanged.
  - **(chosen; not in the spec.)**
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_hash ‖ vk`.

### 5.2 Request and answer

- **When:** at once on receiving a valid `vote.proposal`, with no member
  action (a vault started by the member's own state, not an ask; the ask
  gate, VAULT-MESSAGING §10.4.1, never applies). Every member of record
  certifies at opening, so issuance timing says nothing.
- **How:**
  1. The vault computes `blinded = Blind(cert_key, msg_prefix ‖ cert_msg; r)`
     and sends `vote.certify {request_id, proposal_id, blinded}`.
  2. **The service vault** checks:
     - the proposal is open;
     - the connection is a member of record;
     - this connection has no certificate yet, or has one for the same
       `blinded`.

     It records the issuance with a conditional write that succeeds only
     if no issuance exists for the connection, or one exists for the same
     `blinded`. Only then does it sign: `blind_sig = BlindSign(cert_sk, blinded)`.
     - It answers `vote.certified {request_id, proposal_id, blind_sig}`.
     - A repeated `blinded` gets the stored `blind_sig`.
     - Refusals: `vote.refused {request_id, proposal_id, reason}`, with
       `reason` one of `already_certified`, `not_open`, `closed` or
       `not_of_record`.
  3. **The vault** computes `cert_sig = Finalize(cert_key, msg_prefix ‖ cert_msg, blind_sig, r)`,
     which includes verifying it. It keeps `(cert_prefix = msg_prefix, cert_sig)`
     and discards `r`.
     - If `Finalize` fails, it keeps `blinded` and `blind_sig` as
       evidence, retries once, and then reports
       `certification_failed` (§8.3).
     - With no answer, it retries the same request with backoff until
       `closes_at`.

The service sees `blinded` and `blind_sig`, which tell it nothing about
`vk` or `cert_sig` without `r`.

### 5.3 The issuance list

The service vault records `connection, proposal_id, blinded, blind_sig`
(the conditional write above). It publishes the issuance tags of
certified members at publication (§8.1), then deletes the records.

## 6. Casting

### 6.1 The ballot

- `ballot_msg = proposal_hash ‖ u32(seq) ‖ u32(pool_seq) ‖ pool_hash ‖ lp(choice_id)`
- `ballot_sig = Sign(vk, "vettid/vote/1/ballot" ‖ 0x00, ballot_msg)`
- `seq` starts at 1 and goes up by one each time the member casts again
  (§6.2). The highest counts, so the order holds however deposits
  arrive, even shuffled by the mix.
- `pool_seq` and `pool_hash` are those of the pool whose token carries
  the deposit.
- **No timestamp.** **(chosen; differs from the plan:** a signed time
  would be published with the ballot.) The box records nothing but
  the day (§7.2).

### 6.2 Choosing

- **Casting:** the member casts in the app, at any time from `opens_at`
  to `closes_at`. The vault signs only with the member's approval inside
  the credential's unlock window (VAULT-MESSAGING §3.5.3), and sends the
  ballot at once (§6.4). It is not an ask.
- **Changing:** the member may cast again until `closes_at`. The new
  ballot has the next `seq`, and the highest `seq` counts (§7.2).
  - **(chosen; not in the spec:** still one counted ballot per key.)
- **Abstain before close:** a member who hasn't cast by `closes_at − 1 h`
  has `abstain` sent for them by their vault, with `seq` 1. If they
  then cast after all, their ballot has a higher `seq` and replaces it.
  - Every member of record therefore has one counted ballot, which
    leaves no unused certificate for the service to vote with (§9.3).
  - An abstain sent then says only "had not cast an hour before close",
    which the tally's abstain count largely shows anyway.
  - **(differs from the plan; kept by owner decision 2026-10-28:** the
    plan's members who don't vote cast nothing.)
- **Reminders:** the app reminds the member a day before `closes_at`.

### 6.3 The deposit

- `deposit = Seal(ballot_kem, info = "vettid/vote/1/deposit", body)`.
- `body` is the JSON
  `{v: 1, proposal_id, vk, cert_prefix, cert_sig, pool_seq, pool_hash, choice_id, ballot_sig}`,
  padded per VAULT-MESSAGING §5.4. Every honest deposit lands in the same
  1024-byte bucket.
- **`Seal`** is either VMS sealed mode with an all-zero, anonymous
  `sender_kid` (VAULT-MESSAGING §4.4), or HPKE base mode (RFC 9180) with
  suite 2's KEM and AEAD. Item 5.1 picks one.
  - Either way, nothing in the deposit identifies the vault. A member's
    own kid or key there would link the ballot.

### 6.4 Sending it

1. **Time.** At once, when the member casts (owner decision 2026-10-28).
   For binding votes the deposit goes to the mix (§9.2), which holds it
   until close.
   - An abstain goes at `closes_at − 1 h`. If the vault is locked then,
     it goes as soon as the vault is unlocked, before `closes_at`.
   - The ballot and the certificate are in the vault's encrypted state,
     and survive a restart.
2. **Token.** It picks a token uniformly at random from the newest
   complete pool, among those it hasn't tried.
3. **Key.** It makes a fresh Ed25519 key for this deposit and signs the
   request with it (RELAY-PROTOCOL §4.1). An open token needs no
   registered sender (§5.6).
   - Every attempt is signed anew, with a fresh timestamp. A
     byte-identical request within 90 s is refused as a replay.
4. **Outcomes:**

   | Answer | What the vault does |
   |---|---|
   | `2xx` | Records "cast". Keeps `vk`, the certificate, `ballot_sig` and the pool hash for §8.3. |
   | `409 token_used` (spent by someone else, or by a first attempt whose answer was lost) | Deposits again with another token and a fresh key. A second copy is harmless: it has the same `seq` and choice (§7.2). **(chosen; differs from the plan,** which stopped at "probably cast".) |
   | `token_expired`, `token_revoked`, `token_invalid` | Drops that token. With none left, waits for the next pool. |
   | `quota_exceeded` with `quota: "token"` | Drops the token. |
   | Mailbox `quota_exceeded`, 5xx, network errors | Retries the same token, with a backoff of up to 5 min. |
   | `replay_detected`, `timestamp_stale` | Re-signs and retries. |
   | `payload_too_large`, `mailbox_unknown` | Reports `deposit_failed` (§8.3). |

   Retries continue until `closes_at`.

## 7. The ballot box

### 7.1 Collecting

- **When:** the ballot box (the service vault) collects from `opens_at`
  to `count_until`, acknowledging each message once it has been
  handled. For binding votes it collects from the mix, which forwards
  everything at `closes_at` (§9.2).
- **The arrival cutoff** is `closes_at`, by the relay's `deposited_at`
  (for binding votes, the mix's arrival time).
- **Publication** waits until the mailbox is empty at `count_until`, and
  for at least 10 minutes after the last collect that returned nothing.
  **(chosen; not in the spec.)**

### 7.2 Checks, in order

1. **Format:** the size is within bounds, `deposit` unseals, and `body`
   parses strictly.
2. **Proposal and time:** `proposal_id` is this proposal's, and
   `deposited_at < closes_at`.
3. **Pool:** `pool_seq` and `pool_hash` name a pool this proposal issued.
4. **Certificate:** `cert_sig` verifies under `cert_key` for
   `cert_prefix ‖ cert_msg(proposal_hash, vk)`.
5. **Ballot:** `ballot_sig` verifies under `vk` for `ballot_msg`, and
   `choice_id` is one of the proposal's.
6. **Repeats:** for each `vk` the ballot with the highest `seq` is kept,
   whatever the arrival order, and lower ones are dropped. A copy with
   the same `seq` and `choice_id` is a duplicate, and is dropped. Two
   valid ballots with the same `seq` but different choices are a
   `conflict`: both are dropped and the count is published. Only the
   holder of `vk` can make one.

- **What is kept:** a ballot that passes is stored as
  `{vk, cert_prefix, cert_sig, seq, pool_seq, pool_hash, choice_id, ballot_sig, day}`,
  where `day` is the UTC date of `deposited_at`.
- **What is not kept:** `msg_id`, `jti`, `sender` and `deposited_at` are
  used for checks 2 and 6, then discarded. No log line carries them.
- **Failures** are counted by reason and dropped.
- **Spent tokens:** the box keeps a set of spent `jti`s, with no link to
  the ballot rows, to count what is spent (§7.3).

### 7.3 Pool and quota watch

- **Re-issue:** when fewer than `members_of_record / 4` of the newest
  pool's tokens are unspent, and the vote has more than an hour left,
  the box mints the next pool (`pool_seq + 1`). There are at most
  two re-issues (§3.3).
- **Alarms:**
  - mailbox use above 20% of its quota (10,000 messages, 32 MiB;
    RELAY-PROTOCOL §7.2);
  - more than 10% of an hour's deposits failing checks 1–4;
  - any `conflict`.

## 8. Publication and verification

### 8.1 Results

- **`results.json`** is a JCS document with:
  - `proposal` (base64 bytes) and `proposal_sig`;
  - every pool (base64 bytes) with its `pool_sig`;
  - `members_of_record`, the record tags and `record_root`;
  - the issuance tags and `issued`;
  - the ballots, sorted by `vk`, and their count;
  - the tally per choice, and the counts of failures by reason;
  - any extension with its reason (§10.2);
  - `ballot_root` (§8.2).
- **Signature:** detached, `results_sig = Sign(service IK, "vettid/vote/1/results" ‖ 0x00, H(results_bytes))`.
- **Published** on member.vettid.org, as one file.
- **Anchored (D8, decided 2026-10-28):** the results hash goes into Sigstore's public
  transparency log, Rekor, outside VettID's control.
  - **The entry** is a `hashedrekord`: `H(results_bytes)`, `results_sig`
    and the service's identity key. No ballot data goes into the log.
  - **The anchor** is the Sigstore bundle Rekor's answer is packaged in:
    the log index, the inclusion proof and the signed checkpoint. It is
    published as `results.json.sigstore.json` and sent in `vote.closed`.
  - **Checking:** vaults verify the bundle offline, against Rekor's
    public key pinned in the vault's release config. Observers use
    standard Sigstore tools (for example `cosign verify-blob`).
  - **For binding votes**, the same hash also goes to Bitcoin through
    OpenTimestamps, as a second, permanent time anchor.
  - The bundle version and Rekor's key (v1, or the tiled v2) are pinned
    in items 5.3 and 5.4.
- **Then:** the RSA private key is destroyed, and the issuance records
  deleted.

### 8.2 Merkle trees

- RFC 6962 §2.1 with SHA-256:
  - leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`;
  - split at the largest power of two below n;
  - the empty tree is `H("")`;
  - inclusion proofs are RFC 6962 audit paths.
  - This replaces vettid-dev's hex-string tree, which had no leaf/node
    separation and duplicated odd nodes.
- **Ballot leaf:**
  `lp(vk) ‖ lp(cert_prefix) ‖ lp(cert_sig) ‖ u32(seq) ‖ u32(pool_seq) ‖ pool_hash ‖ lp(choice_id) ‖ lp(ballot_sig) ‖ lp(day)`,
  with `day` as `YYYY-MM-DD`. The certificate is in the leaf (plan §8).
- **Record leaf:** the 32-byte tag.

### 8.3 What a member's vault checks

The check runs on `vote.closed`, and in any case at `count_until` + 1 h.

1. **Fetch:** the vault asks the app to fetch `results.json` whole, over
   HTTPS, with no session and no query naming a voting key.
   - The member site never serves per-`vk` proofs. The proof is computed
     in the vault (plan item 5.7 adapts).
   - The app also fetches the anchor entry.
2. **The file:**
   - `results_sig` holds.
   - `H(file)` equals the anchored hash and `vote.closed`'s.
   - The proposal bytes equal the ones it received.
   - Every pool the vault holds is in the file, under its `pool_seq`.
3. **Its own entry:** its record tag is present, and its issuance tag is
   present.
4. **Its ballot:** exactly one ballot under its stored `vk`. It is its
   latest cast, with the highest `seq` it sent, its stored `cert_sig`
   and `pool_hash`, and that cast's choice. The inclusion proof reaches
   `ballot_root`.
5. **Outcome:** the vault shows the member the result. A failure names
   the check, and the vault keeps the evidence: the proposal bytes, the
   pools, the certificate, `blinded`/`blind_sig`, `ballot_sig` and the
   deposit outcome.

### 8.4 What an observer checks

From `results.json` and the anchor:
1. **Signatures and anchor:** every signature holds, under the service's
   identity key as published on vettid.org with the proposal, and the
   file hash matches the anchor.
2. **Ballots:** every `cert_sig` holds under `cert_key` for
   `proposal_hash`; every `ballot_sig` holds under its `vk`; `vk`s are
   unique; every `choice_id` is one of the proposal's.
3. **Pools:** exactly one pool per `pool_seq`, and every ballot's pool
   is one of them.
4. **Tags:** record tags and issuance tags are unique; their numbers
   are `members_of_record` and `issued`.
5. **Counts:** `ballots ≤ issued ≤ members_of_record`. Every vault
   deposits, so a shortfall of ballots below `issued` measures
   undelivered ballots, and is published.
6. **Tally and roots:** the tally and both roots recompute, and every
   `day` is within the voting window.

## 9. Trust boundaries

### 9.1 What the service vault learns

- **It learns:** who the members of record are, that their vaults
  certified (all of them, at opening), the ballots and the tally.
- **It does not learn,** from the ballot, certificate or token: whose a
  ballot is.
- **Its view of arrivals:** times, `msg_id` and `jti`.
  - **Non-binding votes:** ballots are sent the moment they are cast
    (§6.4), so an arrival time is a link for a service that also knows
    when the member was active: a site visit or sign-in just before,
    or other traffic on the connection. Each non-binding proposal says
    so. Tokens from the shared pool add nothing.
  - **Binding votes:** the mix forwards everything at close, shuffled,
    so arrival times say nothing.

### 9.2 Operator metadata (D5: decide before the first binding vote)

VettID runs the relay, the member-vault hosts and the service vault.

**The remaining link:** the host's forwarder can see which vault process
opened a connection at time t, and the relay records a deposit arriving
at t. An operator who instruments both can join them. Together with the
ballot box's decryption, that links a ballot to a member. The design
above closes the links the service vault has on its own; this one needs
the host too.

| Option | What it closes | Cost |
|---|---|---|
| A. State it | Nothing. Each proposal says so. | None. Non-binding votes only. |
| B. An independent mix | Deposits go to a relay run by an independent party. It holds them until `closes_at`, then forwards them to the ballot box shuffled and at once. VettID sees vault→mix connections, but its box receives ballots with no arrival order. That also removes the cast-time link of §9.1. | An operating agreement, and a small relay feature (hold, shuffle, forward). The mix sees host addresses, not vaults. |
| C. Casting from the phone through an oblivious relay (RFC 9458) | The host sees no ballot traffic. | An OHTTP gateway in front of VettID's relay (a relay change), app work on both platforms, and a third-party OHTTP relay. Phones can't reliably deposit at a drawn time, so the vault→app hand-off times correlate with deposits. It also gives up the every-vault-deposits property for members whose phones are idle. |
| D. The ballot box in an enclave (Phase 7) | The operator's access to decrypted ballots, but not the network link. | As planned. |

**Decided (owner, 2026-10-28): B for binding votes, A until then.** It
keeps every property above and needs no app change. The mix and its
operator are chosen before the first binding vote. Its hold, shuffle and
forward feature is specified with the relay revision of §3.4.

### 9.3 Residual trust

- **Phantom members of record:** connections the service controls,
  added before `record_at`. Only the count and outside knowledge of the
  membership show them. A binding vote publishes the count ahead of
  `record_at` and invites an independent count.
- **Stuffing:** to add a ballot, the service needs a certificate, which
  it can mint for a `vk` of its own.
  - Every member of record deposits, so a stuffed ballot either makes
    `ballots` exceed `issued`, which observers catch, or replaces a real
    ballot, which that member catches (§8.3 check 4).
  - The slack left is the undelivered ballots of §8.4 check 5, published
    as a count. A binding vote states a maximum for it.
- **Withholding:** dropping a real ballot is caught by that member,
  against the same anchored file everyone sees (§8.3).
- **Split views:** a file for members differing from the observers' is
  caught by the anchor.

## 10. Availability

### 10.1 Vectors

The requirement (owner decision 2026-10-26): no one other than the
member may prevent an eligible member from obtaining a certificate and
casting a counted ballot during the voting window.

| Vector | How it is met, or what remains |
|---|---|
| Certification refused or ignored | Every vault certifies at opening and retries until `closes_at`. A refusal is evidence (§8.3). An outage is covered by §10.2. |
| Ask gate (VAULT-MESSAGING §10.4.1) | Certification, choosing and depositing are not asks. Nothing in the vote path is a service challenge. |
| Site sign-in blocked | Voting needs no site sign-in. |
| Ballot mailbox flooded with junk | Pool tokens carry `quota: {msgs: 1, bytes: 4096}`, and the pool is held by members only. Junk is at most one 4 KiB message per token, about 2 MiB for a pool of 600, well under the 32 MiB quota. The box collects continuously and alarms at 20% (§7.3). |
| **Pool exhaustion by a member** (a member of record spends the pool's tokens with junk) | **Met only with relay admission tokens** (§3.4, decided). With the interim pool, re-issue (§7.3) and the flood guard slow it but don't stop a determined member. So binding votes wait for admission tokens. |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits spread over the window and retry. |
| Service vault, relay or host outage | Deposits wait in the ballot mailbox (14 days). Certification requests wait on the connection. Beyond the §10.2 bound, the vote is extended. |
| The member's vault locked, or its host restarted, when the member casts or at the abstain time | Casting needs the app and so an unlocked vault. A pending abstain goes when the vault is unlocked, before `closes_at`. The app reminds the member before close. A member whose vault stays locked to the end has no ballot counted, a published shortfall (§8.4 check 5). |

### 10.2 The outage rule (fixed before opening)

- **Measured by:** the member vaults, not the service.
  - A vault that, during the vote, had no `2xx` from the relay
    for more than 30 minutes while trying, or no answer to
    `vote.certify` for more than 1 hour, records that span.
  - It reports it after the vote with its check (§8.3).
- **During the vote:** the service vault's own health checks and the
  relay's status page also count. If they show an outage of the relay
  or the ballot mailbox longer than 1 hour, the service extends
  `closes_at` and `count_until` by the outage, rounded up to the
  hour, at most once, by up to 24 h, by `vote.extended` (§4.4).
- **In the results:** every reported span. A binding vote states the
  share of vaults reporting an outage at which the vote is repeated.
- **(chosen; not in the spec.)**

## 11. Test vectors

Produced by the reference implementation (items 5.3 and 5.4) and copied
by vettid-vault; a copied vector that stops matching is a
stop-and-report item.
1. **Derivations:** `vk`, `msg_prefix`, `blind_seed` and `r` from a
   fixed `vote_root` and `proposal_id`.
2. **RFC 9474:** the RFC's RSABSSA-SHA384-PSS-Randomized vectors, plus
   one over a real `cert_msg` with a fixed key and the derived values.
3. **`ballot_msg` and `ballot_sig`.**
4. **The seal:** `Seal`/`Open` of a deposit with fixed keys and
   randomness.
5. **Merkle:** trees of 0, 1, 2, 3, 5 and 8 leaves, and an inclusion
   proof for every leaf of the 5-leaf tree.
6. **JCS:** proposal, pool and results bytes with their signatures,
   plus refusals: non-canonical bytes and duplicate names.
7. **Ballot box rejections:** one deposit each for a bad certificate, a
   bad ballot signature, an unknown choice, an unknown pool, a repeated
   `vk` (same `seq` and choice; a lower `seq`; the same `seq` with another
   choice), and a deposit after `closes_at`.

## 12. Decisions for the owner

All items below were approved by the owner on 2026-10-28, item 3 as
amended in 0.4.0.

**Departures from the plan:**
1. **Labels:** `vettid/vote/1/...`, the VMS convention (§2).
2. **No timestamp in the ballot** (§6.1).
3. **Ballots are sent the moment they are cast** (owner decision
   2026-10-28). A member who hasn't cast an hour before close has an
   abstain sent by their vault (kept, owner decision 2026-10-28). For non-binding votes, arrival time is
   a stated link (§9.1); the mix removes it for binding votes (§6.4,
   §9.2).
4. **A 409 deposits again with another token,** instead of stopping at
   "probably cast" (§6.4).
5. **The pool goes over the connection** to every member, identical,
   and is not published before the count (§3.3).

**Choices the plan and the specifications leave open:**

6. **The vote root** lives in the vault's encrypted state, not the
   credential, so the vault can certify and abstain without the
   password (§5.1).
7. **Blinding values are derived** from the vote root (§5.1).
8. **The member may cast again until `closes_at`;** the highest `seq`
   counts (§6.1, §6.2).
9. **The seal construction** is left to item 5.1 (§6.3).
10. **Publication** waits for the mailbox to drain (§7.1).
11. **Results are anchored** in a public transparency log (D8: Rekor
    proposed) (§8.1).
12. **The outage rule** is measured by the vaults, with a 24-hour cap
    (§10.2).
13. **JCS documents** are verified as exact canonical bytes, with
    detached signatures (§2).

**Decided (owner, 2026-10-28):**
- **D5:** an independent mix for binding votes; non-binding votes state
  the boundary (§9.2).
- **D6 and D7:** relay admission tokens (§3.4), a RELAY-PROTOCOL
  revision. The pool stays the interim mechanism, for non-binding votes
  only.
- **D8:** Sigstore Rekor as the results anchor, as a Sigstore bundle,
  plus OpenTimestamps for binding votes (§8.1).

## Changes

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

- **0.2.0 (2026-10-28):** after review of 0.1.0.
  - Every member deposits once, in a shared deposit phase, with abstain
    by default: closes the ballot box's own timing link, and the
    stuffing slack.
  - The proposal and pool hashes are in the certificate and the ballot:
    closes equivocation per member.
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
