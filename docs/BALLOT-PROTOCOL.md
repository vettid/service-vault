# Ballot Protocol

**Status:** stub. Written in full, and reviewed, before any ballot code
(MEMBER-SERVICE-PLAN §10, item 5.0). The plan-level design is
MEMBER-SERVICE-PLAN §8.

This document will specify:

1. Requirements: eligibility, one vote, secrecy against the service,
   verifiability, decline-ability; receipt-freeness out of scope.
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
