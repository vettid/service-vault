# Ballot Protocol

**Status:** stub. Written in full, and reviewed, before any ballot code
(MEMBER-SERVICE-PLAN §10, item 5.0). The plan-level design is
MEMBER-SERVICE-PLAN §8.

This document will specify:

1. Requirements: eligibility, one vote, secrecy against the service,
   verifiability, decline-ability, **availability** (below);
   receipt-freeness out of scope.
2. Proposal publication: signed proposal, per-proposal RSA certification
   key, ballot mailbox, public pool of one-shot open deposit tokens
   (RELAY-PROTOCOL §5.6) distributed as a static file; voting window
   ≤ 7 days.
3. Voting key: the vote root (stable across credential rotation),
   HKDF-SHA256 with `salt = SHA256(proposal_id)`, `info = "vettid-vote-v1"`.
4. Certification: RFC 9474 blind signature under the connection; one
   certificate per connection per proposal; issuance log.
5. Casting: labelled canonical ballot encoding, random pool token,
   ephemeral relay key, randomized delay; the rule for `409 token_used`.
6. Ballot box: certificate and signature checks, rejection of a repeated
   voting key, timestamps reduced to the day; `msg_id`, `jti` and exact
   arrival times discarded.
7. Publication and verification: Merkle tree with leaf and node domain
   separation, the certificate in the leaf; member and observer checks.
8. Trust boundaries: what the service can and cannot learn; operator
   metadata (relay arrival times, member-vault egress) and its
   mitigation for binding votes; phantom certificates and how they are
   caught.
9. Test vectors.

## Availability requirement (owner decision 2026-10-27)

No one other than the member may prevent an eligible member from
obtaining a certificate and casting a counted ballot during the voting
window. The full protocol must show, for each step, why an outsider (no
connection, or a connection of their own) cannot block it, and what an
operator outage does. At least these vectors are addressed:

| Vector | Requirement |
|---|---|
| Token pool exhaustion: anyone can spend public one-shot open tokens with junk deposits (RELAY-PROTOCOL §5.6; per-sender limits are per `jti`) | The service re-mints and republishes the pool when it runs low (minting is local and unbounded); a member's vault fetches a fresh pool and retries with another token until the window closes. |
| Ballot mailbox quota: junk deposits fill the mailbox (message and byte quota, RELAY-PROTOCOL §7.2) so real ballots are refused | The ballot box collects continuously and drops invalid deposits after a cheap check (certificate signature first), so the backlog stays far below the quota; quota use is monitored and alarmed; ballot mailboxes can be sharded. |
| Eligibility certification blocked by the ask gate (VAULT-MESSAGING §10.4.1: a deny starts a 7-day cooldown on every challenge from that connection; 5 asks per 24 h) — an outsider can cause denies by triggering sign-in prompts with a member's email | Certification and casting are started by the member's vault and are not asks, so the ask gate never applies to them; nothing in the vote path depends on a service-initiated challenge. |
| Sign-in to the site blocked (rate limits, ask-gate cooldown, email bound by someone else) | Voting never requires a site sign-in: proposals are delivered to the member's vault and voting happens in the app. |
| Service vault outage during the window | Ballots are deposited to the relay mailbox, which holds them until collected, so an outage loses no ballots; certification is retried by the member's vault; an outage of certification beyond a stated bound extends the window by the outage (rule fixed before the vote opens and published with the proposal). |
| Relay flood | Relay per-network limits and WAF (RELAY-PROTOCOL §7.2); casting spreads over the window with retries. |
| Member's own vault held or locked | Out of scope (the member's own state); the app reminds the member before close. |

