# Ballot Protocol

**Status:** draft 0.1.0 (2026-10-29), for review before any ballot code
(MEMBER-SERVICE-PLAN §10, item 5.0). The plan-level design is
MEMBER-SERVICE-PLAN §8; where this document departs from it, the
departure is marked **(chosen; differs from the plan)** and listed in
§12. Choices the plan and the specifications leave open are marked
**(chosen; not in the spec)**. The owner decides both before code.

The message types defined here (§4–§6) are not yet in VAULT-MESSAGING,
which today lets a service connection send only
`connection.authenticate.challenge` (VAULT-MESSAGING §6.4 "Service
connections", 0.69.0) and lists votes as planned, not specified (§1.1).
Registering them there, with wire vectors, is item 5.1; this document
is the source for that change.

## 1. Requirements

| Requirement | Meaning here |
|---|---|
| Eligibility | Only a member of record (§3.2) can obtain a certificate, one per member per proposal. |
| One vote | One counted ballot per certificate: the ballot box keeps the first valid ballot for a voting key and drops the rest (§7.2). |
| Secrecy against the service | The service vault learns who asked for a certificate, never which ballot is whose: the certificate is blind-signed (§5) and the ballot arrives from a fresh key on a token drawn from a public pool (§6). The operator-metadata boundary is §9.2. |
| Verifiability | A member confirms their ballot is counted as cast and that one certificate, not more, was issued in their name; an observer confirms that every counted ballot carries a valid certificate, that no voting key counts twice, that ballots ≤ certificates ≤ members of record, and the tally (§8). |
| Decline-ability | A member may simply not vote; nothing in the published data separates a member who declined from one who never asked for a certificate, beyond the issuance list (§8.1), which shows who asked. |
| Availability | No one but the member can stop an eligible member from obtaining a certificate and casting a counted ballot during the window (§10). |
| Receipt-freeness | Out of scope (owner decision): a member can prove their vote to someone else by showing their voting key. |

## 2. Notation and primitives

- `‖` is concatenation. `u8(x)` and `u16(x)` are big-endian unsigned
  integers. `lp(x) = u16(len(x)) ‖ x`, with `len(x) ≤ 65535`.
- `H` is SHA-256.
- Labels follow the VMS convention (VAULT-MESSAGING §4.1): ASCII, no
  terminator, embedding the version; here `vettid/vote/1/...`.
  **(chosen; differs from the plan:** the plan's `"vettid-vote-v1"`
  follows vettid-dev, not VMS.)
- `Sign(sk, label, m)` is `suite.Sign` (vettid-vault `vms/suite`):
  Ed25519 over `label ‖ m`. `Verify` is its counterpart.
- `proposal_id` is a ULID, 26 Crockford base32 characters, as its ASCII
  bytes wherever it is hashed or signed.
- Times inside signed data are Unix seconds, `u64`, as the LEASH and
  ICE signed structures use (VAULT-MESSAGING §10.11). Times in message
  bodies are VMS timestamps (§5.3).
- Blind signatures are RFC 9474 **RSABSSA-SHA384-PSS-Randomized**
  (RFC 9474 §5, §6): RSA-2048, SHA-384, MGF1-SHA-384, salt length 48,
  with the 32-byte random message prefix of the randomized variant.
  - The service vault uses `github.com/cloudflare/circl/blindsign/blindrsa`.
  - The member vault implements `Blind` and `Finalize` (RFC 9474 §4.2,
    §4.4) in-repo with `math/big`. vettid-vault adds no third-party
    dependency to the enclave (vettid-vault README "Dependencies";
    V3-NOTES). It needs no private-key operation.
  - RSA-2048 is the plan's choice: the key lives for one voting window
    (≤ 7 days) and is destroyed at close. Unlinkability does not rest on
    RSA, since blinding is information-theoretic (RFC 9474 §7.3).

## 3. Proposal

### 3.1 Contents

The service vault creates a proposal with:

| Field | Meaning |
|---|---|
| `proposal_id` | ULID. |
| `title`, `text` | UTF-8; `text` ≤ 16 KiB. |
| `choices` | 2–16 entries `{id, label}`. `id` matches `[a-z0-9-]{1,32}`, unique. |
| `binding` | `false` until the §9.2 mitigation is decided (D5). |
| `record_at` | Unix seconds: the roster snapshot that defines members of record (§3.2). |
| `opens_at`, `closes_at` | Unix seconds. `closes_at − opens_at ≤ 7 days` (the relay's open-token lifetime, RELAY-PROTOCOL §5.6; 168 h deployed). |
| `cert_key` | The proposal's RSA-2048 public key, as an RSASSA-PSS SubjectPublicKeyInfo in DER (RFC 9474 §6.1, RFC 4055). |
| `ballot_mailbox` | Relay URL and mailbox id of the proposal's ballot mailbox: a relay keypair made for this proposal only (§7). |
| `ballot_kem` | The ballot box's KEM public key for this proposal (§6.3). |
| `pool_hash` | `H` of the first pool's bytes (§3.3). |
| `members_of_record` | The count (§3.2). |
| `record_root` | The Merkle root of the record tags (§3.2, §8.1). |
| `outage_rule` | The extension rule of §10.2, as text, fixed before opening. |

The proposal is a JSON object in RFC 8785 (JCS) form, with fields
named as above and binary values in canonical base64. The service vault
signs the exact bytes: `proposal_sig = Sign(service IK,
"vettid/vote/1/proposal", proposal_bytes)`. A member's vault verifies
it against the service's identity key it holds for the connection.
Verifiers check the bytes they received and never re-serialize, as for
LEASH delegations (VAULT-MESSAGING §10.11). **(chosen; not in the
spec.)** vettid-dev's vault never checked its proposal signature; this
one does, before §5.

### 3.2 Members of record and record tags

- **Members of record** are the connections that are active on the
  service vault's roster at `record_at`: connected, not removed, not
  suspended. One connection is one member. A member who connects again
  after `record_at` (a new connection) is not a member of record for
  this proposal.
- For each one the service vault draws a 32-byte random `record_secret`
  and sends it to that member only, in the proposal message (§4.1). The
  member's **record tag** is
  `record_tag = H("vettid/vote/1/record" ‖ proposal_id ‖ record_secret)`.
- `record_root` is the Merkle root (§8.2) over the record tags, sorted
  bytewise. The tags are published at opening. A member finds their
  own; nobody else can tell whose a tag is.
- **What this catches:** a member of record left out of the list, and,
  with the issuance tags (§5.3), a certificate issued in someone's name.
  **What it doesn't:** phantom members of record, which only the count
  and outside knowledge of the membership can show (§9.3).

### 3.3 The token pool

- The ballot box mints `pool_size` one-shot open deposit tokens for the
  ballot mailbox (RELAY-PROTOCOL §5.6: scope `deposit_open`, `sub` `*`,
  `exp = closes_at + 15 minutes`, a fresh ULID `jti` each). Minting is
  local and needs no relay call.
  - `pool_size = 2 × members_of_record`, at least 64.
- **The pool** is a JSON object `{proposal_id, pool_seq, tokens: [...]}`
  in JCS form. `pool_seq` is 1 for the first.
- **Distribution (chosen; differs from the plan):** every member of
  record receives the same pool bytes over their connection (§4.2), and
  the same bytes are published on member.vettid.org for observers.
  - The plan named a static file only. A member's vault, however, has
    no general HTTPS egress to fetch it, while a message on the
    connection reaches it anyway.
  - Every member gets the identical set, so receiving it carries no
    link. The point the plan made still holds: tokens are never handed
    out per member.
  - A pool larger than one message (`max_payload_bytes`, 262,144;
    about 600 tokens, i.e. 300 members of record) is sent as numbered
    parts, identical for every member.
- **Re-issue:** when fewer than `members_of_record / 4` tokens remain
  unspent (§7.3 counts them), the ballot box mints a new pool
  (`pool_seq + 1`) and sends it the same way. A pool's hash is in the
  signed `vote.pool` message (§4.2), not the proposal.

## 4. Messages from the service

New types on a service connection (to be registered in VAULT-MESSAGING
§10 by item 5.1; bodies are JSON per §5.3 there). The service sends them
in session mode like any other connection message. A member's vault
that doesn't support votes drops them, as it drops any type it doesn't
know from a service.

### 4.1 `vote.proposal`

`{proposal, proposal_sig, record_secret}`
- `proposal` is the §3.1 bytes, in canonical base64.
- `record_secret` is this member's, 32 bytes. It is the only
  per-member field.
- Sent to each member of record once the proposal opens; resent, the
  same bytes, until acknowledged by the vault's ordinary dedupe (the
  inner `id`).

### 4.2 `vote.pool`

`{proposal_id, pool_seq, part, parts, pool_part, pool_sig}`
- `pool_part` is a slice of the pool's bytes.
- `pool_sig = Sign(service IK, "vettid/vote/1/pool", proposal_id ‖ u32(pool_seq) ‖ H(pool bytes))`,
  over the whole pool.
- The vault keeps the parts until it holds all `parts` of a `pool_seq`,
  checks the hash and signature, and then uses that pool. For the first
  pool, it also checks the hash against `pool_hash`.

### 4.3 `vote.closed`

`{proposal_id, results_url, results_hash}`, sent at publication (§8.1)
so the vault can run its own check (§8.3).

## 5. Certification

### 5.1 The voting key

- **The vote root** is 32 random bytes, created once per member vault
  and kept as an item of the member's credential (VAULT-MESSAGING
  §3.5.2 `items[]`). It survives `credential.rotate` and password and
  PIN changes. **(chosen; not in the spec:** VMS has no vote root.)
  - In the credential, deriving a voting key needs the password, through
    the credential's unlock window (§3.5.3), like casting does.
  - `credential.reset` replaces it. A member who resets during an open
    vote, after certification, can't use that certificate. They lose
    that vote, and the issuance list shows that one was issued.
- **The voting key:**
  `seed = HKDF-SHA256(ikm = vote_root, salt = H(proposal_id), info = "vettid/vote/1/voting-key", L = 32)`,
  and `vk` is the Ed25519 key from `seed`. The salt is the vettid-dev
  choice. The `ikm` is not vettid-dev's: there it was the identity key,
  which rotates.
- **The certified message:**
  `cert_msg = "vettid/vote/1/cert" ‖ 0x00 ‖ proposal_id ‖ 0x00 ‖ vk(32)`.

### 5.2 Request and answer

The member's vault starts it. It is not an ask, so the ask gate
(VAULT-MESSAGING §10.4.1) never applies. It happens when the member
opens the proposal in the app and approves, inside the credential's
unlock window.

1. The vault draws the RFC 9474 randomizer `msg_prefix` (32 bytes) and
   computes `(blinded, inv) = Blind(cert_key, msg_prefix ‖ cert_msg)`.
   It **stores `msg_prefix`, `blinded` and `inv` before sending**, so a
   retry after a crash sends the same `blinded`.
2. The vault sends `vote.certify {request_id, proposal_id, blinded}`
   (`request_id` is a ULID; events are correlated per VAULT-MESSAGING §10).
3. The service vault checks:
   - the proposal is open (`opens_at ≤ now < closes_at`, extended by §10.2);
   - the connection is a member of record;
   - no certificate has been issued to this connection for this
     proposal, or the one issued was for the same `blinded`.

   It then signs, `blind_sig = BlindSign(cert_sk, blinded)`, records the
   issuance (§5.3), and answers `vote.certified {request_id, proposal_id, blind_sig}`.
   - A repeated `blinded` gets the stored `blind_sig` again, with no
     second issuance.
   - A different `blinded` from a connection already certified gets
     `vote.refused {request_id, proposal_id, reason: "already_certified"}`.
   - Other refusals are `not_open`, `closed` and `not_of_record`.
4. The vault computes `cert_sig = Finalize(cert_key, msg_prefix ‖ cert_msg, blind_sig, inv)`,
   which verifies the signature, and keeps `cert = (msg_prefix, cert_sig)`.
   On a refusal it keeps the stored state and shows the reason.

The service vault sees `blinded` and `blind_sig`. Without `inv` they
are independent of `vk` and `cert_sig` (RFC 9474 §7.3).

### 5.3 The issuance list

For each certificate issued, the service vault records the connection,
`proposal_id`, `blinded`, `blind_sig` and the time, kept until
publication and then deleted. It publishes the **issuance tags**,
`H("vettid/vote/1/issued" ‖ proposal_id ‖ record_secret)` of the
members who were certified, sorted. A member checks that their tag is
there if and only if they asked: a tag present without their asking
means a certificate was issued in their name (§9.3).

## 6. Casting

### 6.1 The ballot

`ballot_msg = proposal_id ‖ 0x00 ‖ lp(choice_id)`, and
`ballot_sig = Sign(vk, "vettid/vote/1/ballot", ballot_msg)`.
**(chosen; differs from the plan:** the plan's ballot carries a
timestamp. A signed time is published with the ballot, and an exact one
would be a timing link to the relay's arrival records. The ballot box
records the day itself (§7.2), so the ballot carries none.)

### 6.2 Approval

Casting needs the member's approval in the app, inside the credential's
unlock window (VAULT-MESSAGING §3.5.3): the vault needs the vote root.
The app shows the proposal (whose signature the vault has checked) and
the choice, and the vault signs only after that approval. It is not an
ask, and the ask gate doesn't apply.

### 6.3 The deposit

`deposit = Seal(ballot_kem, "vettid/vote/1/deposit", body)`, with `body`
the JSON `{v: 1, proposal_id, vk, cert_prefix, cert_sig, choice_id, ballot_sig}`
(binary values in canonical base64), padded per VAULT-MESSAGING §5.4.

- `Seal` is single-shot public-key encryption to `ballot_kem` with the
  VMS suite-2 KEM and AEAD, and no sender key. The exact construction
  (the VMS sealed mode or HPKE base mode, RFC 9180) is fixed in item
  5.1. **(chosen; not in the spec.)**
- Sealing keeps the relay's stored copies from showing a running tally.
  The ballot box can read them either way.

### 6.4 Sending it

1. **Delay.** The vault picks a deposit time uniformly at random in
   `[now, min(now + 6 h, closes_at − 1 h)]`, or now if that range is
   empty. **(chosen; not in the spec; see §9.2.)** The ballot is
   stored before the wait and survives a restart.
2. **Token.** The vault picks a token uniformly at random from the
   newest complete pool it holds, among those it hasn't tried.
3. **Key.** It makes a fresh Ed25519 key, used for this one deposit and
   then destroyed. A deposit with an open token needs a signature by
   some key, not a registered one (RELAY-PROTOCOL §4.1, §5.6).
4. It deposits `deposit` to `ballot_mailbox` with that token, signed
   with that key.
5. **Outcomes:**
   - `2xx`: done. The vault records "cast".
   - `409 token_used` on a first attempt (the token was spent by someone
     else): go back to step 2 with another token, and a new key.
   - `409 token_used` after an automatic retry of the same request (a 5xx
     or network error, then a retry): the first attempt may have been
     stored. The vault records "probably cast" and does not spend another
     token. A second deposit would be harmless (§7.2) but uses up the
     pool. **(plan §8, kept.)**
   - `token_expired`, or all tokens in the pool tried: wait for a newer
     pool (§3.3) and go back to step 2, until `closes_at`.
   - `429 quota_exceeded` and other relay errors: retry with backoff
     until `closes_at`, the same token while it is unspent.
6. **Fallback.** With no answer at all near `closes_at`, the vault
   deposits without a delay.

## 7. The ballot box

### 7.1 Collecting

The ballot box is part of the service vault. It collects from the ballot
mailbox continuously during the window and for 14 days after (the
relay's `message_ttl_seconds`), acknowledging each message after it has
been handled.

### 7.2 Checks, in order

The checks are ordered cheapest first, so that junk costs little
(§10.1).

1. The size is within bounds, `deposit` unseals, and `body` parses
   strictly (VAULT-MESSAGING §5.3 rules).
2. `proposal_id` is this proposal's. The arrival is before `closes_at`
   (as extended, §10.2), by the relay's `deposited_at`.
3. `cert_sig` verifies under `cert_key` for
   `cert_prefix ‖ cert_msg(proposal_id, vk)` (RFC 9474 §4.5).
4. `ballot_sig` verifies under `vk` for `ballot_msg(proposal_id, choice_id)`,
   and `choice_id` is one of the proposal's.
5. `vk` has no ballot yet. The **first** valid ballot for a `vk` counts,
   and later ones are dropped. This makes a double deposit harmless, so
   it is mandatory (plan §8). A member cannot change their vote.
   **(chosen; not in the spec.)**

A ballot that passes is stored as `{vk, cert_prefix, cert_sig, choice_id, ballot_sig, day}`,
where `day` is the UTC date of arrival. The relay's `msg_id` (a ULID
with millisecond time), `jti`, `sender` and `deposited_at` are not
stored, and no log line carries them. A ballot that fails is counted by
reason and dropped, and the count is logged; its contents are not.

### 7.3 Watching the pool and the quota

- The ballot box counts deposits by `jti` as they arrive. That includes
  junk: anyone holding the pool can spend a token. It re-issues the pool
  at the §3.3 threshold.
- It alarms when the ballot mailbox holds more than 20% of its message
  or byte quota (10,000 messages, 32 MiB; RELAY-PROTOCOL §7.2), or when
  more than 10% of deposits in an hour fail check 3.

## 8. Publication and verification

### 8.1 Results

At `closes_at`, as extended (§10.2), the ballot box stops counting and
the service vault publishes `results.json` on member.vettid.org. It is a
JCS object with:
- `proposal`, `proposal_sig`
- `members_of_record`, the record tags and `record_root`
- the issuance tags and `issued` (their count)
- the ballots, sorted by `vk`
- the tally per choice
- `ballot_root` (§8.2)
- `results_sig = Sign(service IK, "vettid/vote/1/results", H(results without results_sig))`

It then sends `vote.closed` (§4.3) to each member of record. The RSA
private key is destroyed. The issuance records (§5.3) are deleted; the
published tags remain.

### 8.2 Merkle trees

RFC 6962 §2.1 Merkle trees with SHA-256:
- leaf hash `H(0x00 ‖ leaf)`, node hash `H(0x01 ‖ left ‖ right)`;
- split at the largest power of two below n;
- the empty tree is `H("")`;
- inclusion proofs are RFC 6962 §2.1.1 audit paths.

This replaces vettid-dev's hex-string tree, which had no leaf/node
separation and duplicated odd nodes.

- **Ballot leaf:**
  `lp(vk) ‖ lp(cert_prefix) ‖ lp(cert_sig) ‖ lp(choice_id) ‖ lp(ballot_sig) ‖ lp(day)`,
  with `day` as `YYYY-MM-DD`, in `vk` order. The certificate is in the
  leaf (plan §8).
- **Record leaf:** the 32-byte record tag, in tag order.

### 8.3 What a member's vault checks

On `vote.closed`, or when the member asks, the vault fetches
`results.json` through the app (the app has HTTPS) and checks:
1. `results_sig` and the proposal bytes.
2. Its record tag is in the record tags, and its issuance tag is
   present if and only if it asked for a certificate.
3. Its `vk` (re-derived, §5.1) has exactly one ballot, with its choice,
   and the inclusion proof reaches `ballot_root`.

It shows the member the outcome. A failure is shown with which check
failed, so the member can report it.

### 8.4 What an observer checks

From `results.json` alone:
1. All signatures: `results_sig` and `proposal_sig` under the service's
   published identity key, every `cert_sig` under `cert_key`, every
   `ballot_sig` under its `vk`.
2. `vk`s are unique, and every `choice_id` is one of the proposal's.
3. `ballots ≤ issued ≤ members_of_record`.
4. The tally matches the ballots.
5. `ballot_root` and `record_root` recompute.
6. Every ballot's `day` falls within the window.

## 9. Trust boundaries

### 9.1 What the service vault learns

- Who are members of record, and who asked for a certificate and when
  (the issuance list is published as tags).
- The set of ballots and the tally.
- **Not** which ballot is whose: the certificate is blind (§5.2), the
  ballot comes from a fresh key on a pool token (§6.4), and the box keeps
  only the day.

### 9.2 Operator metadata (D5: to decide before the first binding vote)

VettID runs the relay, the member-vault hosts and the service vault.
The ballot leaves the member's vault through the host's forwarder,
which can see which vault process connected and when. The relay records
arrival to the millisecond (`msg_id`). An operator who instruments both
can link a deposit to a vault, and so a ballot to a member. The delay
of §6.4 narrows this only against an operator who does not keep exact
egress logs. **For non-binding votes this boundary is stated with the
proposal; `binding` stays `false` until one of these is chosen:**

| Option | What it closes | Cost and limits |
|---|---|---|
| A. State the boundary | Nothing; the proposal says the operator could link ballots | None. Fine for non-binding votes only. |
| B. Synchronized batches | Vaults deposit only at fixed shared times (e.g. on the hour), so arrival times say nothing within a batch | The forwarder still sees which vault connected in a batch: it closes the relay-timing link, not the host link. |
| C. Casting from the phone through an oblivious relay | The vault gives the sealed deposit to the app, which deposits it through an OHTTP relay (RFC 9458) run by a third party. The relay sees the OHTTP relay's address, and the host sees no ballot traffic | The phone→vault message and the deposit can still be correlated by time unless the app also waits a random time. It needs a third-party OHTTP relay and app work on both platforms. |
| D. A ballot relay run by an independent party | VettID's relay never sees deposits | The independent relay still sees the host's address, and with B it learns little. An operations agreement. |
| E. The ballot box in an enclave (Phase 7) | Exposure of decrypted ballots to the operator, which is a different problem | Doesn't affect the network link. |

The recommendation for binding votes is **C, with B as the fallback when
the app can't reach an OHTTP relay**. That is the owner's decision.

### 9.3 Residual trust

- **Phantom members of record:** the service could add connections it
  controls before `record_at`, and give them certificates and ballots.
  The published count, the record tags and outside knowledge of the
  membership are the only checks. A binding vote warrants publishing the
  roster count ahead of `record_at` and an independent count.
- **A certificate issued in a member's name:** caught by that member
  (§8.3 check 2). The service can't vote for a member who did vote,
  because only the first ballot per `vk` counts and its `vk` differs.
- **Withholding:** the service could drop a valid ballot before counting.
  It is caught by the member's own check (§8.3 check 3), which every
  voting vault runs on `vote.closed`.

## 10. Availability

### 10.1 Vectors

The requirement (owner decision 2026-10-26): no one other than the
member may prevent an eligible member from obtaining a certificate and
casting a counted ballot during the voting window. For each step,
why an outsider (no connection, or a connection of their own) cannot
block it, and what an operator outage does:

| Vector | Requirement and how it is met |
|---|---|
| Token pool exhaustion: anyone holding the pool can spend its one-shot tokens with junk (per-sender limits are per `jti`, RELAY-PROTOCOL §5.6, §7.2) | The box counts spent tokens (§7.3) and re-issues the pool at a quarter left. Minting is local and unbounded. A vault waits for the next pool and retries until close (§6.4). |
| Ballot mailbox quota: junk fills the 10,000-message / 32 MiB quota | The box collects continuously and drops junk after check 3 (§7.2), so the backlog stays far below the quota. Quota use is alarmed at 20% (§7.3). The proposal can name more than one ballot mailbox (shards) if needed. |
| Ask gate (VAULT-MESSAGING §10.4.1): an outsider can cause declines and cooldowns by triggering sign-in prompts | Certification and casting are started by the member's vault and are not asks (§5.2, §6.2). Nothing in the vote path is a service challenge. |
| Site sign-in blocked (rate limits, cooldown, an email bound by someone else) | Voting needs no site sign-in: the proposal comes over the connection, and voting is in the app. |
| A connection of one's own (another member) | It gets its own certificate, one, and its own ballot. It can spend pool tokens (as above), but can't touch another member's state on the service vault. |
| Relay flood | The relay's per-network limits and WAF (RELAY-PROTOCOL §7.2). Deposits spread over the window and retry. |
| Service vault outage | Deposits wait in the ballot mailbox (14 days) and lose nothing. Certification requests wait on the connection and are retried by the vault. Beyond the §10.2 bound, the window is extended. |
| Relay outage | The vault retries until close. Beyond the §10.2 bound, the window is extended. |
| The member's own vault held or locked | Out of scope (the member's own state). The app reminds the member a day before close. |

### 10.2 The outage rule (fixed before opening, in `outage_rule`)

- **When it applies:** the service vault's certification is unavailable,
  or the relay refuses deposits to the ballot mailbox, for more than
  1 hour in total during the window (from the service vault's health
  and the relay's status, recorded by the service vault).
- **What it does:** `closes_at` moves by the total outage, rounded up to
  the hour, at most once by up to 48 hours.
- **How members learn of it:** a signed `vote.extended {proposal_id, closes_at}`
  to every member of record. The relay tokens' `exp` follows through a
  new pool.
- **Recorded in the results:** each outage and the extension.
- **(chosen; not in the spec:** the 1-hour threshold and the 48-hour cap.)

## 11. Test vectors

These are produced by the reference implementation (items 5.3 and 5.4).
vettid-vault copies them; a copied vector that stops matching is a
stop-and-report item (CLAUDE.md "Coordination rules").
1. **HKDF voting key:** `vote_root`, `proposal_id` → `seed`, `vk`.
2. **`cert_msg` and RFC 9474:** the RFC's own RSABSSA-SHA384-PSS-Randomized
   vectors (RFC 9474 Appendix A), plus one over a real `cert_msg` with a
   fixed key, `msg_prefix` and blinding factor.
3. **`ballot_msg` and `ballot_sig`:** a fixed `vk`.
4. **`Seal`/`Open` of `deposit`:** fixed keys and ephemeral randomness.
5. **Merkle:**
   - the empty tree, and trees of 1, 2, 3, 5 and 8 leaves;
   - an inclusion proof for every leaf of the 5-leaf tree;
   - the RFC 6962 leaf and node prefixes.
6. **Proposal and results:** JCS bytes and signatures.
7. **Ballot box rejections**, one deposit each: bad certificate, bad
   ballot signature, unknown choice, repeated `vk`, after close.

## 12. Decisions for the owner

Departures from the plan:
1. **Labels:** `vettid/vote/1/...`, the VMS convention, not `"vettid-vote-v1"` (§2).
2. **The ballot carries no timestamp.** The box records the day (§6.1).
3. **The pool goes to each member over the connection,** the same bytes
   for all, and is also published for observers. It is not only a static
   file (§3.3).

Choices the plan and specifications leave open:

4. **The vote root** is a credential item: it needs the password, and is
   lost at `credential.reset` (§5.1).
5. **Ballots are sealed** to a per-proposal ballot-box key (§6.3).
6. **The first ballot per voting key counts;** no vote changes (§7.2).
7. **Record tags and issuance tags** are published (§3.2, §5.3), so each
   member can check their own entry.
8. **The deposit delay:** uniform within up to 6 hours, ending an hour
   before close (§6.4).
9. **The outage rule:** 1-hour threshold, extensions up to 48 hours (§10.2).
10. **Proposal and results encoding:** JCS, signed as exact bytes (§3.1, §8.1).
11. **Kept from the plan:** RSA-2048, RFC 9474 RSABSSA-SHA384-PSS-Randomized (§2).
12. **D5:** which §9.2 option is required before a binding vote (recommended: C, with B as fallback).

## Changes

- 0.1.0 (2026-10-29): first full draft, from the stub's outline and
  MEMBER-SERVICE-PLAN §8.
