# Relay-key rotation in the service vault

**Status:** 0.7.0, draft (2026-11-14). Against VAULT-MESSAGING 0.90.11
(§3.4, §3.4.1, §3.4.2). GC #9442.

VAULT-MESSAGING §3.4.2 RK0 asks a service vault to follow the relay-key
rotation rules "as a member vault does", and to advertise
`relay_follow` only once it implements §3.4.1 and §3.4.2 in full. The
rules are written for two vaults that may each rotate. This document
states how they read for this service, which both follows its members'
rotations (Q, sections 3 and 4) and rotates its own relay key (P,
section 5; owner decision b, GC #10505), says where the spec leaves a
choice to it, and splits the work. The code follows this text; none of
it is built yet.

Choices are marked **(chosen; not in the spec)**. Everything else is
the spec's own rule, restated for a service; where this text is shorter
than the spec, the spec governs. As in RELEASE-29.md, the service runs
as one task, and one lock (the peer's) covers every state change.

## 1. Scope: the service is both Q and P

- **The owner chose to build both sides (b, GC #10505).** The service
  follows its members' rotations as Q, and rotates its own relay key as
  P (section 5). It rotates its relay key alone: its `ik` never rotates
  (RELEASE-29 §1), so §3.4's identity-key part of a rotation, S5, S6's
  ending of invitations under an old `ik`, and S8 stay inert. A
  compromise of the service's whole state (its `ik` with it) still means
  new keys and new invitations for every member; a relay-key rotation
  answers what the relay key alone covers (section 5).
- **What it does as Q,** toward a member vault P that rotates:
  1. **§3.4.1's receiving side:** the relay-key states (current,
     earlier, foreign) and the cut-off in `acceptFrom`; Table A by relay
     key; rule C on relay links (seen, forks); rule U to follow
     `relay.address.update`, with binding L; rule T for the tokens.
  2. **§3.4.2:** RK2, RK5, RK6, RK7, RK8, RK10, RK12, and RK14's
     receiving side: the hold, the keep, the pin, the telling as
     received, and the re-deposits.
  3. **RK0:** advertise `relay_follow` once 1 and 2 are built, never
     before.
- **What it does as P,** rotating its own relay key toward its members
  (section 5): §3.4's order of a relay-key rotation, the resends, the
  old key's life; §3.4.1's rotating side (S1, S2, S3, S6's relay part,
  S7, S9, "The gate"); and §3.4.2's P-side rules (RK3, RK4, RK5 and RK8
  as the sender, RK9, RK10 while in its own S1, RK11, RK13, RK14's
  telling as the sender, and "When both sides' old mailboxes end").
- **Today:**
  - a `relay.address.update` is refused and audited
    `address_update_refused` (session.go, from vettid-vault #241);
  - `relay_follow` is not advertised (RELEASE-29 §6);
  - a deposit on the held standing token refused `mailbox_unknown` makes
    the connection `stale` (`peer_stale`) and drops **every** entry
    waiting for it, `undelivered_mailbox_unknown` (outbox.go).
- **The switch (chosen; not in the spec).** All of this is built behind
  one switch, a constant in the code, not an operator setting, off until
  PR 5, so `main` stays deployable for ballot and ops fixes while the PRs
  land (section 6). While it is off, today's three behaviours above stay
  exactly as they are. PR 5 turns it on together with advertising
  `relay_follow`; it is never on without it, and never advertised
  without it. **It is one-way:** once members have seen `relay_follow`,
  their gate (§3.4.1 "The gate", RK0) lets them rotate toward the
  service, so turning it off again would refuse their updates and strand
  them. Going back means a release that keeps it on. That holds on
  staging too: turning it on there is one-way for staging's members.
  Tests set it through a test hook, so every test also runs with it
  off. PR 5's switch also waits on the spec's answer to the restore
  question (section 4). The P side (section 5) has a second one-way
  switch of its own, turned on in PR 8, after this one.

## 2. What it depends on

- **The wire types belong in vettid-vault's `vms`, not here (chosen
  with the lead, GC #10442).** Member vaults need the same receiving-side
  code, and the two must agree byte for byte:
  - the relay link (`{v, suite, old, new, sig_old, sig_new}`, label
    `vettid/vms/2/relay-rotate`) with its form checks and verification;
  - the `relay.address.update` body (`relay`, `relay_links`, `rotations`,
    `token`, `reconnect_token`) and the `relay.mailbox.closed` body
    (`mailbox`, `last_msg_id`);
  - `relay_links` in a reconnect `hs.init` (announcing `from.relay`) and
    `hs.resp` (with `relay`), and rule U's precedence: a malformed body
    wins over `relay_unlinked`;
  - **shared test vectors** for all of these: valid links and chains,
    each chain refusal, and the precedence cases, run by both the vault
    and the service.

  The service pins the `vms` release that has them; that pin change is
  its own PR, with `docs/SOURCE.md` regenerated.
- **No member vault rotates a relay key yet** (§3.4.1 A5), and none
  advertises `relay_follow`. Tests run against `peertest` members that
  rotate. **Before the switch is turned on in production,** the service
  is run on staging against a real member vault release that rotates
  (chosen; not in the spec).

## 3. §3.4.1 for a service

- **Order of processing.** The service has one mailbox except while it
  rotates its own relay key; the multi-mailbox order and collected-to
  times are section 5's.
- **Relay-key states and the cut-off.** Each connection keeps P's
  current relay key, and every earlier key with its followed link and
  its cut-off. The cut-off is the position (`msg_id`, `deposited_at`)
  of the message that made the follow:
  - for rule U, the `relay.address.update`;
  - for RK8, the reconnect's verified `hs.fin` (an `hs.init`'s follow,
    which counts as before the cut-off) or the `hs.resp` itself.

  An earlier key leaves from the oldest end once no token the service
  issued to it can still deposit: a revoked reconnect token counts until
  its revocation has left the outbox, a denied standing token until its
  `exp`. **At most 32 earlier keys per member** (the spec's reading, to
  be confirmed): a follow that would keep more is refused `unexpected`.
- **Table A** runs at `acceptFrom` step 4 as written, with the three
  exceptions between vaults (RK7's `hs.confirm` and `hs.fin`, RK8's
  linked reconnect messages). Its notes apply as written, including a
  `relay.token.issued` after its cut-off: tokens by rule T only, with no
  `features`, no resend, no dedupe entry and no answer.
- **Rule C, relay links.** Every valid relay link that passes step 3 is
  kept as seen, at most 32 per member, counted apart from identity
  links. A second successor suspends the connection as a relay fork:
  - audit `connection.fork_suspected` with `ref` = `relay`; the
    application gets `connection.suspended` with the new reason
    `relay` (added to events.go's list), and the operator the alarm
    `fork_suspected` (RELEASE-29 §7);
  - the only exit is a new invitation, as the spec says.
- **Legacy moves.** A connection a `relay.address.update` moved before
  #152 (`LegacyPrevRelayPK`) stays suspended (`relay_moved_unlinked`);
  it never enters the earlier-key state, and nothing here revives it.
- **Rule U, the follow.** Rule U's checks as written: a chain of 1 to 32
  links, each link's form, the ends (the first `old` is the `sender`,
  the last `new` is `relay.pk`), the followed prefix, `relay_rollback`,
  the cap, and rule T on `token`, else `token_unusable`. Then, in one
  state write: the links, the cut-offs, `relay.pk` made current, the
  tokens kept (a `reconnect_token` that fails rule T is ignored, no
  reason to refuse). After it:
  - `relay.token.issued` for the new key (standing and reconnect),
    whenever the current epoch isn't demoted and no reconnect of the
    service's own is open (`tokens.go` returns without sending while one
    is). So the follow's write sets a durable **owed** mark on the
    connection record, cleared only in the write that queues that
    `relay.token.issued`; housekeeping sends it once nothing blocks it,
    so a restart can't lose it and the member's S1 still ends;
  - the reconnect tokens issued to the passed keys revoked (those that
    open answers and pending epochs carry included);
  - the reconnect token held for the passed mailbox replaced by the
    update's, if kept (without one, RK6's wait);
  - the member's cached `relay.token.refresh` answers are deleted
    (`kindResp`, kept 24 hours, `ResponseRetention`). They are found by
    paging that connection's `kindResp` records with the `Pager`, prefix
    `<connection id>|`, and keeping those whose cached inner is a
    `relay.token.refresh` answer. The request's `kindInner` mark stays,
    so a resent request is **not answered**: the follow's
    `relay.token.issued` carries the tokens, and no standing token for
    the passed key goes out (RK2).
  - **Crash safety of the follow.** The update's dedupe marks (its
    `msg_id` and inner `id`) are written no earlier than the connection
    record that records the follow, so a crash before it leaves the
    update unmarked and the relay delivers it again: the follow is then
    simply done again, its `relay.token.issued` (the owed mark) and its
    revocations included, which are idempotent. Outbox entries a crash
    left re-addressed to a mailbox the connection record doesn't name as
    current are moved back at load (and, if `relay_held` is set, queued
    held again, neither attempted nor marked tried); entries left at the
    passed mailbox after the connection record names the new one are
    re-addressed at load. Either way the load seals them again under the
    current epoch.
  - **A duplicate** (every link already followed) is answered with a
    fresh `relay.token.issued`, at most one an hour per member, **on the
    same clock as the answers to `relay.token.refresh`** (the spec's
    reading of §7.2's limits). Its `token` is not checked by rule T and
    none of its tokens is kept.
- **Binding L (RK5, RK10).**
  1. Rule U's checks that don't depend on the `ik` run first and change
     nothing; any failure refuses the update with none of its links
     followed, identity links included.
  2. An update from an earlier key after its cut-off has its identity
     links judged as Table A's row judges an `identity.rotate`: if any is
     not already followed, the update is refused `superseded_relay`.
  3. The identity links are judged as an `identity.rotate`'s (Table B).
     Where every one is already followed, R29-K9 is judged before the
     `ik` requirement (evidence first).
  4. RK5's `ik` requirement, against the `ik` those links would lead to.
     A failure refuses the update with Table B's reason for its `ik`:
     `ancestor_ik`, `rejected_ik`, or `unknown_ik` for any other.
  5. Only an update that is then followed (or a duplicate that passes)
     has its identity links applied, then its relay links, then its
     tokens, in one write. If applying the identity links suspends the
     member (R29-K9, a received flag, a conflict) or ends the epoch the
     update travels under, no relay link is followed, no token kept and
     no answer sent; the suspension stands.

  The service already follows identity links (rotation.go, R29-K9);
  this reuses it.
- **Rule T** as written. A `relay.token.issued` whose `iss` is a mailbox
  the service doesn't know for P is **deferred**:
  - at most two visibility timeouts of **60 seconds** (the relay's value
    is not read: the spec's fail-closed reading), counted from the
    first time it was seen, stored by `msg_id` in a record kind of its
    own, `defer` (listed in `peer.Kinds()`), so a restart doesn't reset
    it. `kindUnacked` is not used: it feeds the public
    `counts.unhandled` (chosen; not in the spec);
  - at most 8 deferred messages per member and reason, each kept at most
    16 days;
  - a deferred message takes no dedupe mark: session.go marks the inner
    `id` before dispatch today, so the deferral is decided before that
    mark;
  - while the service collects two mailboxes (its own rotation,
    section 5), also while the other mailbox has not been collected past
    the message's `deposited_at`;
  - past either bound it is processed, and its token ignored (not
    refused).

## 4. §3.4.2 for a service

- **RK1** is built (RELEASE-29 §14 item 4b), with one difference from
  RK1-b, which is not about rotation: the service discards a member's
  rekey `hs.init` during **any** open reconnect of its own (audited
  `rekey_while_reconnecting`, RELEASE-29 §3), where RK1-b names only a
  reconnect that names an epoch other than the current one. Narrowing it
  is a conformance fix of its own, a separate PR that also amends
  RELEASE-29 §3; it is not part of this work.
- **RK2.** Every token the service puts in a message to P names P's key
  as the service has it on record when the message is deposited (for a
  handshake message, when it is sealed). It never names a key a message
  only announces: the service's `hs.resp` to a member's RK8 `hs.init`
  carries tokens for the key on record, not for the announced one.
  - **At a follow,** queued deposits on the held standing token move to
    the new mailbox; a queued `relay.token.issued` is dropped (the
    follow's answer replaces it). A handshake's own deposits keep their
    mailbox.
  - **Entries that carry tokens (chosen; not in the spec).** The service
    seals an entry when it queues it, so a waiting entry may carry a
    token minted for the passed key. At a follow, a waiting answer to
    the member's `relay.token.refresh` (`{kind: "standing", token}`) is
    dropped, like a waiting `relay.token.issued`, and its cached copy
    deleted (section 3): the follow's `relay.token.issued` gives the
    member fresh tokens. `connection.approved` goes before activation on
    the request's own token and is not kept (below). No other message
    the service sends carries a token. (The lead takes this into the
    spec erratum: RK2 moves such entries without saying they are minted
    again.)
- **RK6.** At a follow (by rule U or RK8), the service's own open
  reconnects whose `hs.init` carried tokens naming the passed key and
  that have sent no `hs.fin` are abandoned, their tokens revoked, and
  started again with tokens for the new key, after any establishment in
  the same write.
  - **Not restarted:** the reconnect whose own message made the follow.
  - **The wait.** A restart, and every reconnect the service starts with
    P after a follow, for whatever reason (RELEASE-29 §3 lists them: `B`,
    no valid standing token, `token_revoked`, `quota_exceeded`, rule J,
    carried-token discards, H5, the demotion cases, a restore), goes only
    on a **held** reconnect token for P's current mailbox, never on the
    passed mailbox's or on a carried token not yet adopted. Without one,
    the service waits up to 60 days after the follow (or, while it is in
    its own S1 toward that member, until RK13's cap) and does not judge
    "no reconnect token" meanwhile. Past the
    wait without one, the connection becomes `stale` by the reconnect
    bound, except while "No reconnect while carried tokens wait" holds.
  - **An owed restart (a reading; not in the spec)** is not an open
    reconnect (it has no `hs.init`), but it blocks starting another one,
    as an open reconnect does under RK1-a, so that two tries don't spend
    the member's reconnect token's deposits; the follow's
    `relay.token.issued` still goes whenever the current epoch isn't
    demoted.
  - Any epoch established with P after the follow ends an owed restart,
    unless the current epoch is demoted.
- **RK7.** Past its cut-off, an earlier key's message still goes to
  Table B in two cases:
  - an **`hs.confirm`** under an epoch that a handshake signed by the
    service's current `ik` for P established;
  - an **`hs.fin` for an answer the service has open,** when its `sig_I`
    verifies under the `ik` the answer pinned and that `ik` is the
    service's current `ik` for P. An answer kept only as fork evidence
    passes too, whatever `ik` it pinned, and is judged as evidence (it
    suspends; it never establishes).

  Each pass closes per epoch once the service has accepted, under that
  epoch or a later one, a message from a later relay key of P's. "Later"
  is establishment order at the service (positions as in the cut-off; a
  tie is not later; pending and abandoned-while-pending epochs don't
  count, except the pass's own). For an `hs.fin`, its epoch is the one it
  would establish, at its own position. Each closure is recorded with
  the epoch when it happens and never undone; the records live as long
  as the earlier key does.
- **RK8.** A member's reconnect `hs.init` (announcing `from.relay`) and
  its `hs.resp` to the service's reconnect (announcing `relay`) may carry
  `relay_links` from the deposit key to the announced key.
  - **Accepted** from P's **current or an earlier** key, before or after
    an earlier key's cut-off, when the links connect `sender` to the
    announced key and pass rule C. The main case is a member with no
    epoch at its second write: its `sender` is still the service's
    current key for it, and its reconnect announces the new one.
  - **Refused:**
    - at parse, `relay_unlinked`: a fault in a link's form, a count
      outside 1 to 32, or a chain end that doesn't match (the first
      `old` is not the deposit key, or the last `new` is not the
      announced key; rule U's "Precedence");
    - rule U's checks or RK5's requirement fail: rule U's reason, and the
      handshake does not complete;
    - the service has already followed P away from the announced key:
      `superseded_relay`;
    - no links, from an earlier key after its cut-off: `superseded_relay`
      as before.
  - **Followed** under rule U's checks and RK5, in RK8's order (identity
    links, relay links, then the message's tokens by rule T against the
    announced key's mailbox): for an `hs.init`, in the write that
    establishes the reconnect at its verified `hs.fin`; for an `hs.resp`,
    in the write that processes it after `sig_R` verifies. If every link
    is already followed, the follow changes nothing and the handshake
    goes on.
  - **After an RK8 follow** the service does all of rule U's after-steps
    (section 3): its `relay.token.issued` for the new key, the
    revocations, the held reconnect token replaced, the cached refresh
    answers deleted. Only an `hs.confirm` goes on the
    `hs.init`'s carried token not yet adopted; the `relay.token.issued`
    goes on a held token for the new mailbox (the member's prompt
    `relay.token.issued`, kept by rule T). Without it the member's S1
    toward the service never ends.
- **RK10.** A definite refusal of the service's own reconnect `hs.init`
  tied to rotation: a `mailbox_unknown`; and, while the service is in
  its own S1 toward that member (section 5), any definite refusal, or a
  `token_revoked` on a reconnect token the member issued for an earlier
  relay key of the service's (RK9: not a failed try then). The latter
  two end the try at once, and the next starts at the try's expiry, or
  as soon as a new reconnect token from the member arrives. For
  `mailbox_unknown`:
  - With a newer mailbox of P's followed (by rule U or RK8): the try
    ends at once, counts as a failed try under "The reconnect bound", and
    the next starts at once.
  - With none followed: the refusal is not counted. The service doesn't
    retry; it waits for P's links up to 60 days after the first such
    refusal (or, while it is in its own S1, until RK13's cap), then the
    connection becomes `stale` with the alarm `reconnect_failed`. Except
    after a restore (below).
  - Every other refusal is as "The reconnect bound" says.
- **A restore across a member's follow (open; gates PR 5).** A table
  restore can bring back a connection from before the service followed a
  member's relay link: the earlier key current, no cut-offs, and the
  followed relay and identity links forgotten. The member's S1 toward
  the service ended when the service first followed, so the member sends
  no links again (RK8's links travel only during S1): its deposits from
  its new key are refused `foreign_sender`, and the restore's reconnect
  goes to the old mailbox, which is gone once the grace has passed.
  Nothing in the spec heals it yet. **The lead's decision (GC #10490):**
  the question goes into the spec erratum (for example, a P that
  receives a reconnect whose tokens name an earlier key of its own sends
  its links again), and PR 5's switch stays off until the spec answers
  it. Until then:
  - for a restore's reconnect, a `mailbox_unknown` with no newer mailbox
    followed ends the reconnect at once, `reconnect_failed`, the
    connection `stale`, with the alarm, rather than waiting 60 days
    (chosen; not in the spec): README "Restoring the table" already says
    such a member connects again;
  - while any restore reconnect is open, deposits the service can't
    attribute (an unknown relay key, so no connection, audited
    `unknown_kid` with an empty id; or an epoch it can't open) are
    counted, and the alarm `restore_relay_moved` fires once per restore
    with that count (chosen; not in the spec). It is service-wide: such a
    deposit can't be tied to a member, since its relay key is unknown
    and its epoch may be newer than the restored keyrings. It shows the
    operator that some members probably moved, not which. A restore
    reconnect that reaches its bound raises `reconnect_failed` for that
    connection, as today.
- **RK12.** While a connection is suspended, relay links that pass rule
  C are still kept as seen (step 1).
- **RK14, the hold.** With the switch on, replacing today's handling
  (section 1), a durable deposit to P's mailbox refused `mailbox_unknown`
  is **held**, without `stale`, while the connection exists and the
  service has not followed P to a newer mailbox:
  - a handshake message, `hs.confirm` included, is not held: it ends as
    a refusal of its carried token does (§6.3.1); best-effort notices
    (`connection.removed`) are not durable and are not held either;
  - neither `stale` nor an update the service refuses or doesn't follow
    ends a hold;
  - held entries are not attempted while held. A new durable entry
    queued for that member while `relay_held` is set is queued held and
    untried, without an attempt (chosen; not in the spec);
  - at a follow, held deposits are re-addressed to the new mailbox and
    sealed again under the current epoch (below for their `ts`), and
    `relay_held` ends (a later refusal starts a new episode). The
    re-address is **idempotent at load**: an entry whose mailbox isn't
    the member's current one (and isn't a handshake's own) is
    re-addressed again at the next start, so a crash partway through a
    large re-address loses nothing;
  - at the connection's end, they end as §8.3 says;
  - at 60 days after the episode's first refusal, every held entry for
    that member ends undelivered (`undelivered_mailbox_unknown`), the
    connection becomes `stale` if it isn't already, and `relay_held` is
    cleared, with `connection.released` (reason `limit`). Entries queued
    after that are attempted as usual; a `mailbox_unknown` past the limit,
    in the same episode, ends an entry at once, and an episode resets only
    at a follow.
- **Held entries and RELEASE-29 §13.** §13 marks every waiting entry
  tried at each start, and ends a tried entry past 16 days, which would
  end held entries long before the hold's 60 days; and a fresh `ts` at
  re-address could duplicate an entry an earlier attempt did deliver.
  So:
  - each entry records whether an attempt **before** its hold may have
    reached the relay (§13's "tried": a `201`, a `5xx`, no answer,
    `replay_detected`). The `mailbox_unknown` refusal itself proves its
    own attempt was not stored, so it doesn't make the entry tried;
  - §13's start rule (mark every waiting deposit tried) skips held
    entries: none is attempted while held, so no lost write can hide an
    accepted deposit of one;
  - at re-address, an entry no attempt can have delivered takes a fresh
    `ts` and a new `seq`; §13's case 2 does not apply to it until its
    first attempt after the re-address, from which §13 runs as for any
    entry. An entry an earlier attempt may have delivered keeps its `ts`
    (chosen; not in the spec, pending the lead's RK14 erratum), and §13
    applies as written (case 2 past 16 days), so the member's dedupe
    still covers any earlier copy. After a hold longer than 16 days such
    an entry ends by case 2 at its re-address; for a member message that
    is a rotation loss, told `message.delivery_unconfirmed` (below).

  RELEASE-29 §13 says so, marked not built yet. ("Held" here is RK14's
  hold for a newer mailbox; §13's held-after-demotion entries are a
  different state, and the code keeps them apart.)
- **The outbox bound (chosen; not in the spec).** Held entries count
  toward `MaxOutboxPerConn` (256). So that the hold can't block its own
  way out:
  - the follow's `relay.token.issued` is exempt from the bound, as
    `hs.confirm` is;
  - re-deposits from the keep are queued in batches as the bound allows,
    oldest first, each still bound by its cutoff; the rest wait in the
    keep, not in the outbox;
  - during a long hold, other new sends past the bound are refused at
    once (`outbox_full`; `SendMessage` returns `ErrBusy`). An answer to a
    member's request (`respond`, a `vote.*` reply) refused this way is
    cached for 24 hours but not queued, as today; the member's resend of
    the request within that time gets the cached answer again once there
    is room.
- **What the application sees (chosen; not in the spec).** The service
  has no member feed. The connection record carries `relay_held:
  {since}`, shown in the connection API. Its start and end are events to
  the application, `connection.held` and `connection.released`. For a
  "member message" (below):
  - `message.not_delivered`: the relay never stored it (the hold's
    60-day end, or a `mailbox_unknown` past it);
  - `message.delivery_unconfirmed`: it may or may not have been
    delivered (a pinned entry given up at a cutoff or with no telling,
    the dropped-entries record, and an entry tried before its hold that
    case 2 ends at its re-address);

  each with the request it came from.
  This reverses RELEASE-29 §13's "Told to whom" for these cases only:
  a message lost to a member's rotation has no missing answer the
  application could notice, unlike §13's cases. §13 is amended to say
  so.
- **RK14, the keep.**
  - **What is kept.** For 60 days after each `201` to a member's
    mailbox, the inner message of every durable session entry except
    those §3.4.2 step 3 lists as not kept. For what the service sends,
    that is:
    - the "member messages", told when lost: `vote.*` (its sends and its
      answers to members' requests), `connection.authenticate.challenge`
      and `.withdraw`;
    - `profile.update` and, once the service rotates (section 5),
      `relay.mailbox.closed`: upkeep, audited only.

    Not kept: handshakes, `hs.confirm`, `relay.token.issued` and
    `relay.token.refresh`, `relay.address.update` (its own resends,
    §3.4 (b), recover it), `connection.removed`, and `connection.approved`.
    The last is a choice against step 3's list (chosen; not in the spec;
    the lead takes it into the erratum): it is sent before activation on
    the request's token, it carries tokens (RK2), and it is never sent
    again once the member has activated the connection.
  - **When an entry leaves the keep:** an unpinned entry not covered by a
    telling, at its 60 days (a pinned one stays as its pin governs, a
    covered one until it is queued or its cutoff passes); when its `exp`
    passes (a pinned one is audited `drop.held_expired`, an unpinned one
    ends silently; the service's challenges carry `exp`); at the
    connection's removal, which deletes all its kept and pinned entries.
  - **The cap:** 2,000 entries and 8 MiB of kept inners per member, the
    oldest dropped first, with the record of dropped member messages
    (count, highest `msg_id`, first inner `id`) the spec describes.
  - **Storage (chosen; not in the spec).** A record kind of its own,
    `keep` (listed in `peer.Kinds()`), one record per kept entry, id
    `<connection id>/<msg_id>`; connection ids hold no `/`, so the `/`
    ends the prefix. The store's ordered `Page` (the `Pager` interface,
    which the sealed store and the table implement; `peer.Store` itself
    has no paging) reads one member's entries in `msg_id` order, oldest
    first, from the prefix: no new query, and the cap finds the oldest
    without reading the rest. Each record carries the mailbox its `201`
    came from, its first `201` time and, once covered by a telling, that
    telling's cutoff. It is written in the same write that records its
    `201`, and in that write's order before the outbox entry's deletion
    (below). The connection record carries the member's kept count and
    bytes, kept in the same writes, so the cap is checked at each `201`
    without reading the records; housekeeping recomputes them from the
    records now and then, since a partial write can make them drift.
    Keep records are not loaded at start; they are read per member at a
    follow or a telling, and pruned in batches at housekeeping. They are
    sealed like every record, and stay in the table's backups for as
    long as the backups are kept, with the content of up to 60 days of
    the service's sends.
  - **Size:** a ballot sends a member a few messages of a few KiB each,
    so a member's keep is tens of KiB in practice; with 15,000 members,
    a few hundred MiB. The 8 MiB cap per member bounds a misbehaving
    case, not the expected one.
- **RK14, the pin and the telling as received.**
  - **At a follow** the entries kept for the passed mailbox are pinned
    until P's `relay.mailbox.closed` for it, or 60 days after the follow.
    A deposit in flight at the follow whose `201` lands after it is kept
    and pinned with the others for that mailbox. The pins are a list on
    the connection record, one per passed mailbox (two rotations within
    60 days give two): `{mailbox, since, telling, cursor}`, where
    `telling` is unset until one arrives. Entries are matched to a pin
    by the mailbox each keep record carries. A pin outlives its 60 days
    while a telling's batches are still being queued, until they are
    done or its cutoff passes.
  - **The telling** is accepted only for such a pinned mailbox, never for
    P's current one (acked and ignored otherwise). The write that
    accepts it stores in the pin, before any re-deposit: its
    `last_msg_id` (`null` included), its `deposited_at` and the cutoff 60
    days after it, and its inner `id` (the dedupe mark), so a crash
    partway resumes the same telling. Entries above `last_msg_id` are
    deposited again to P's current mailbox; the rest are dropped. A
    `last_msg_id` of `null` means every pinned entry goes again. **A
    second telling for the same mailbox (chosen; not in the spec)** is
    acked and ignored, audited `telling_repeated` with both values: the
    first one accepted binds.
  - **The order of the writes.** `Peer.flush` writes its dirty records
    sorted by kind (`conn` before `keep` before `outbox`), and `Apply`
    splits a write at 100 items or 3 MiB, so a split could commit the
    pin's cursor and the keep deletions without the re-deposits. So these
    writes are ordered explicitly, each step its own `Apply`, in this
    order:
    1. the outbox records of a batch's re-deposits (each carrying its
       entry's cutoff and first `201` time);
    2. the deletion of those keep records;
    3. the connection record with the pin's cursor advanced.

    A batch is sized to fit one `Apply`. A crash after step 1 queues the
    batch again at the next run: the re-deposits carry the same inner
    `id`, so the member's dedupe drops a second copy, and the queue
    holds at most one batch twice (which can pass `MaxOutboxPerConn` by
    that batch). Nothing is lost. The same order holds
    on the `201` path (the keep record before the outbox entry's
    deletion) and at a follow's re-address (re-addressed outbox records
    before the connection record). `peer.Store`'s "all or nothing"
    comment (store.go) is corrected to say a large `Apply` is several
    transactions.
  - **Re-deposits waiting in the keep.** An entry covered by a telling
    that has not been queued yet (the outbox has no room) stays in the
    keep until it is queued or its cutoff passes; at the cutoff it is
    told (a member message) or audited (anything else).
  - **The cutoff.** A re-deposit goes only within 60 days of the
    telling's `deposited_at`; a re-deposited entry keeps the first
    telling's cutoff across later rotations. The cutoff binds every
    attempt: an entry still waiting at it (for a token, behind a
    demotion, held, or for room in the outbox) ends at once.
  - **Re-deposits** are sealed again under the current epoch with the
    same inner `id`, a fresh `ts` and a new `seq` (their `msg_id` is
    above `last_msg_id`, so P never processed them), and judged by §8.3
    "At deposit".
  - **The dropped-entries record** tells when the telling's
    `last_msg_id` is below its highest `msg_id`, or at the 60-day
    deadline with no telling.
  - With no telling by 60 days after the follow, the pinned member
    messages are told lost.
  - **Attachments** do not arise: the service sends none.
- **When both sides' mailboxes end** is section 5's.

## 5. The service as P: rotating its own relay key

- **When it rotates (chosen; not in the spec).** The service has no
  recovery, transfer or `credential.rotate`. A rotation starts from an
  operator command, `service-vault admin rotate-relay`, run with the
  owner's go in the service's environment (like `admin bootstrap`, it
  refuses while the identity key isn't the table's), or from a lost
  mailbox (below). The command writes only a **request** record, as
  `admin bootstrap` arms a bootstrap; the running daemon picks it up and,
  in one `Apply`, deletes the request and records the **relay-key
  rotation owed** mark with the request's time (a mark already set keeps
  its earlier time, so a second run can't push its deadline back, and a
  replayed request can't start a second rotation). The reasons to run
  it:
  - a suspected exposure of the relay key (§3.4's MUST, for what the
    relay key alone covers: an exposure of the whole state, the `ik`
    included, still means new keys and new invitations);
  - a new URL for the same relay (the command's `-relay-url`, the URL
    the new key's mailbox is reached at; each key's URL is kept with it,
    and the service's own address comes from the current key's).

  **A move to a different relay** has no path in the spec: §3.4's order
  makes the successor mailbox with the current relay's rotate, signed by
  the current key, on that relay. It is a question for the spec erratum
  (section 7), not something the command does.
- **What a holder of the relay key can do** while a rotation waits (the
  exposure the rotation answers): collect, ack or delete what members
  deposit in the service's mailbox, so the service misses it; mint or
  revoke tokens for that mailbox; rotate or delete the mailbox. It cannot
  read those deposits (they are sealed under the epochs' keys) or forge
  the service's messages (they are signed by its `ik`). Members ended
  `stale` by a per-incident move (below) have the tokens the old mailbox
  issued them revoked (S7).
- **A mailbox already lost** (no key pending). Only its key's holder,
  or the relay losing data, deletes a current mailbox, so the key is
  probably exposed. It shows two ways:
  - while running, as `mailbox_unknown` to a collect;
  - at a start, as a **`201`** to the start's registration of a key
    `relaykeys` records as registered before (the relay makes a fresh
    mailbox at the same id). `Start` registers only after the load and
    the restore check (today it registers before the load and ignores
    `Created`: GC #10525 fixes that first, on its own). Before each
    start's registration a **registration attempted** mark is stored on
    the current key; a `201`, or a `200` after an attempt that got no
    answer or a `5xx`, stores a durable **re-mint owed** mark before
    anything else, so a crash after it still re-mints at the next start.

  Then (the lead's decision, following the owner's b, GC #10521):
  - **With the gate open and the P switch on:** a rotation, on the
    registration path: a fresh key is generated, stored by the first
    write and registered (§3.4 "After the grace"); the telling (RK14)
    covers what members deposited. It needs the relays' grace confirmed
    (below); without that, the mark waits.
  - **With the gate closed, or the P switch off (chosen against the
    spec, the lead's decision):** the current key is registered again
    (§12.2; RELAY-PROTOCOL §6.10), although the spec says the gate never
    holds back a fresh key for a lost mailbox; a fresh key that members
    can't follow would only lose every connection. The alarm
    `relay_mailbox_lost` and a relay-key rotation owed record it. The
    cost, stated in the alarm: the relay refuses for good the tokens the
    old mailbox issued, so the service mints new standing and reconnect
    tokens for every member, after the 241-second wait counted from the
    answer (it can't know the deletion's time), and sends them in
    `relay.token.issued` on the tokens the members issued to it; the
    re-mint owed mark clears in the write that queues the last of them.
    Members' deposits refused `mailbox_unknown` meanwhile are held by
    them and end at their hold's 60 days, since no follow comes (a gap
    in the spec, in the lead's erratum).
  - Neither a key `relay_key_rolled_back` flags nor the table's current
    key once the log names a newer one (below) is ever registered again.
  - While a key is pending (and not refused), a `mailbox_unknown` from
    the collect loop starts §3.4's rotate-then-registration path
    instead.
- **Where the relay keys live (chosen; not in the spec).** Today the
  relay key is a seed in the keystore item, loaded once. They move into
  a sealed peer record of their own, `relaykeys` (listed in
  `peer.Kinds()` with the request record): the current key with its URL,
  its registration limits and its anchor; a pending key with its state
  (preparing, prepared, refused), `retry_after`, registration-attempted
  mark and fresh-mailbox time; and the old keys with their anchors,
  stops, `last_msg_id` and telling cursor. PR 6 creates it from the
  keystore's seed at the first start, whatever the switches say.
  - **The keystore** keeps the current key's seed, in the field the code
    before PR 6 reads. The keystore item lives in the same table
    (`blob#<name>`), so it is no escrow against a restore: the pending
    key's seed is escrowed **outside the table**, in an SSM SecureString
    encrypted under the service's KMS key, next to the log (below), at
    the first step of preparing (replacing an orphaned pending seed left
    there). After the flip's `Apply`, the keystore's field is set to the
    new key's seed (redone at the next start if a crash comes between):
    a release rollback to before PR 6 then loads the current key, never
    a superseded one. Old keys are kept, deposit-only, in `relaykeys`.
  - The registration limits are stored with each key, since a start
    with a key pending registers nothing; a rotate's or registration's
    answer refreshes them.
- **A table restore across the service's own rotation (chosen; not in
  the spec).** The relay keys live in the table, so a restore takes them
  back too, and a new rotation from the restored key would make a
  second successor of it: every member that followed the first would see
  a relay fork. So:
  - **an SSM log outside the table** (public keys and signed links
    only, no secret) records, durably and before the step it guards:
    each pending key, before the rotate (the rotate waits if that write
    fails); each key made current, with its time, and the signed relay
    link from the key before it, before the flip (the flip waits if it
    fails); and each pending key discarded by `-discard-refused`. The
    `relaykeys` migration seeds it with the current key only when it is
    empty;
  - **at start**, after the `relaykeys` migration and before any
    registration, the table's keys are compared with the log. If the log
    names a key newer than any key the table holds:
    - the service **recovers** only when it can carry on without a
      second successor: the newest key's seed is in the SSM escrow, and
      every link from the table's current key to it is in the log
      (signed, so the chain can be sent again, whichever seeds are gone).
      It then stores that key again (pending, or current if the log
      shows it made current, with the anchor taken from the log entry's
      time), and prepares the updates again with that chain, so members
      follow the same links they may have followed already. A restored
      key is completed before the restore's reconnects start;
    - otherwise it raises the alarm `relay_key_rolled_back`, registers
      nothing for any key the log has superseded, and refuses any
      rotation until the operator confirms; README "Restoring the table"
      says every member then connects again;
    - completing a restored pending key equal to the log's newest is
      not refused;
  - **at the first start after a restore** (the restore marker), every
    pending key is treated as unconfirmed, as after 0.90.11's lost run:
    completed only after the 241-second wait, with every held token
    minted again, since the restore may have lost a fresh mailbox's
    stored time.
- **The gate** (§3.4.1 "The gate"). A new relay key is generated only
  while every active connection advertises `relay_follow` (sticky once
  seen). It is checked wherever a key would be generated: at a mark, for
  the next key after a pending one, at the way out of the refused state,
  and for a lost mailbox. While it is closed the mark waits, checked
  again at each start (and at housekeeping: chosen; not in the spec).
  - **Today no member vault advertises `relay_follow`**, so an owed
    rotation waits. The application gets `relay.waiting` with the
    connections waited for, and the operator the alarm
    `relay_rotation_waiting` once per mark (chosen; not in the spec).
  - **The deadline.** The spec moves the connections still not
    advertising to new invitations 30 days after the mark, but "Receivers
    first" says a closed gate only waits until a release enforces that;
    the service doesn't enforce it, which is the spec's own rule today.
    **Chosen (not in the spec):** the owner may decide, per incident, to
    move those members to new invitations at once (an option on the
    command, ending them as `stale`, with their events). While it waits,
    the exposure the rotation answers is not closed; the alarm says so.
- **The order of a rotation** (§3.4 "The order of a relay-key
  rotation"), with "an unlock" read as "a start" (RELEASE-29 §2). With
  thousands of members, `Apply` splits a write into many transactions,
  and `Peer.flush` writes its dirty records sorted by kind, so neither of
  §3.4's two writes can be one transaction. Each is a sequence of steps,
  each its own `Apply`, in this order, with a commit point:
  1. **Preparing (the first write):**
     1. the SSM escrow of the new key's seed;
     2. the `relaykeys` record with the key as pending, state
        **preparing**: the commit point;
     3. in batches by connection id, each connection's new standing and
        reconnect tokens and its `relay.address.update`, held, with a
        marker naming the pending key and the mint generation. **Each
        batch, marker included, is sized to fit one transaction** (as
        the telling's batches are, section 4), so the marker never
        commits without its payload; a connection whose marker names
        this key and generation is skipped on resume;
     4. state **prepared**, then the SSM log entry for the pending key.
        Only then is the rotate made.

     At load, held updates and tokens are deleted when they name a key
     that is neither the pending key nor, if not yet marked released,
     the current key (a crash during step 3.4 leaves those). A key still
     preparing resumes at step 3. No other key is generated while one is
     preparing, pending or refused, except the next key a pending key's
     flip stores when a rotation is owed (below).
  2. **The rotate** (`POST /v1/mailbox/rotate`, signed by the current
     key), with the pending key; RK14's anchor for the current key is
     stored in a write just before the first attempt.
     - **No definite answer** (a timeout, a `5xx`, `429` after its
       `retry_after`) is retried with the same key: sooner while running,
       with full jitter up to an hour, and at each start; `retry_after`
       is stored with the key and honored at a start.
       `timestamp_stale` and `replay_detected` are retried at once with a
       freshly signed request (up to three times in a row, then with the
       backoff above); they are not definite refusals.
     - `mailbox_unknown` leads to the registration of the stored pending
       key. Before each registration, a **registration attempted** mark
       is stored; it clears in the write that records the answer to a
       definite one. A `201` is a fresh mailbox: its time is stored with
       the key in a write of its own, and the key is completed only after
       the 241-second wait, with every held token minted again. **A
       `200` after an attempt that got no answer or a `5xx` (chosen;
       stricter than the spec)** may have followed an unseen `201`, so it
       is treated as fresh too: the wait, counted from that `200`, then
       the re-mint. The relay's own `429`, `timestamp_stale`,
       `replay_detected` or other `4xx` (with RELAY-PROTOCOL §7.1's error
       body) show nothing was created.
     - **At a start while a key is pending or refused,** the service
       registers nothing: in place of today's registration of its key,
       it makes the rotate-then-registration attempt (one attempt,
       honoring a stored `retry_after`; a failure doesn't stop the
       start, and the collects of the current mailbox go on while it
       lives). Registering the current key then would, after the grace,
       make the old mailbox again. An old key is never registered.
  3. **Completing (the second write),** under the peer lock from step 1
     through step 3, so no connection is added meanwhile:
     1. in batches by connection id, each sized to one transaction with
        its marker (naming the pending key and the mint generation),
        each connection record stores explicitly the service's key for
        it (the old key, S1; never derived from "current"), and its held
        tokens are re-minted if nearly spent (or all of them after a
        fresh mailbox), with its held update **rebuilt and sealed again**
        around them (entries are sealed when queued); connections added
        since the first write get tokens and an update, and those ended
        lose theirs;
     2. the SSM log entry for the new key as current, with its signed
        link and the flip's time; and, when a rotation is owed, the SSM
        escrow of the next key's seed;
     3. **the flip,** one write of the `relaykeys` record: the new key
        current, the old one deposit-only with its anchor, S1's clock
        started at the flip's time (RK13), and, when a rotation is owed,
        the next key stored as pending (preparing) with the owed mark
        cleared in that same write (§3.4): the commit point. After it,
        the keystore's field gets the new seed;
     4. the reconnects abandoned at the flip (RK8 below) are started
        again;
     5. the held updates are released, in batches by connection id, each
        marked released in its batch; a sweep then covers connections
        made since step 1.

     A crash before the flip leaves the key pending, and the next start
     completes it again (step 3.1 skips connections whose marker names
     this key and generation). A crash between 3.2 and 3.3 just resumes.
     A crash after the flip resumes at 3.4.
  - **A definite refusal** (any `4xx` but `429`, `timestamp_stale` and
    `replay_detected`, and `mailbox_unknown` for the rotate) puts the
    pending key in the **refused** state: kept with its tokens and
    updates, the alarm `relay_rotation_failed`, and no new key generated
    on its own. It is attempted again at each start, daily while running,
    and when the operator runs the command (chosen; not in the spec).
    Meanwhile the service collects the old mailbox if it still lives (a
    refused rotate), and otherwise (a refused registration) receives
    nothing; the alarm says which. A plain run of the command while
    refused keeps the refused key and owes a rotation, as a member
    vault's transfer does. **The way out (chosen; not in the spec):** the
    command with `-discard-refused` discards the refused key, its tokens
    and updates and its escrow, logs the discard in SSM (so no start
    takes it for a rolled-back table), and stores a new pending key if the
    gate is open; if it is closed, it records the relay-key rotation owed
    mark instead (keeping an earlier mark's time), as `credential.rotate`'s
    way out does. The current key's anchor, stop and `last_msg_id`
    survive the discard and serve the next key's rotation (RK14 step 1).
  - **Audits** (§3.4 "What is audited"): `identity.rotated` at the flip;
    `identity.rotation_failed` at a start whose attempt doesn't complete
    the pending key (at most once per start), and at once on a definite
    refusal.
  - **A rotation owed while a key is pending** is met by the pending
    key's completion storing the next key (the gate permitting), as §3.4
    says.
- **Collecting both mailboxes.** While a key is pending the service
  collects the old mailbox with the current key, and once the rotate has
  succeeded the new one too, in §3.4.1's order of processing:
  (`deposited_at`, `msg_id`) across both, nothing processed past the
  earliest collected-to time (a mailbox's collected-to time is the
  start, by the service's clock, of its last collect that returned fewer
  than `max`, less 90 seconds). A mailbox answered `mailbox_unknown`
  leaves that set, and so does the old mailbox once RK14 step 1 ends its
  collects, so neither holds back the other.
  - **While the anchor is more than 13 days old and a key is pending,**
    the old mailbox is collected only after a rotate or registration
    attempt that got no `200` since its last collect, or while no
    attempt may be made (a `retry_after` runs, or the refused state).
  - After the flip the service collects the old mailbox until RK14 step 1
    ends it: 13 days after the anchor (at once if past), or at
    `mailbox_unknown` for it, which is final. At the stop, messages from
    it still deferred (rule T, at most two minutes) or left unacked are
    processed first, and `last_msg_id` stays below any that are not; a
    batch already collected is processed and acked. After the stop,
    nothing from the old mailbox is processed again.
- **S1, the service's key for each member** (stored on its connection
  record): the newest of its relay keys whose `relay.token.issued` from
  that member has arrived. It deposits to the member only with that key,
  except on a carried token (RK3: with the key the token's `sub` names,
  while the service still holds it). While it isn't the current key, the
  member is sent only the update (with the links from that key to the
  current one), its `relay.token.issued`, a reconnect's messages (its
  `hs.init` announcing the current key with `relay_links`, RK8; its
  `hs.fin`; an `hs.resp` to the member's reconnect) and `hs.confirm`;
  everything else waits in the outbox. An update goes only after every
  earlier deposit to that member with the old key has had a definite
  answer.
  - **The outbox bound** doesn't hold back what lets S1 end (chosen; not
    in the spec): the update and its resends, the RK8 handshake
    messages, `relay.token.issued` and `relay.mailbox.closed` are exempt
    from `MaxOutboxPerConn`, as `hs.confirm` is.
  - **The update's `rotations`** are empty: the service's `ik` never
    rotates, so the update's `ik` is the member's current `ik` for the
    service and RK5's requirement holds.
  - **RK13's clock:** a member that hasn't acknowledged 30 days after
    the flip's time becomes `stale`, the clock paused while the service has
    accepted, within the last 16 days, an authenticated message from it
    that passed dedupe and the `ts` window: a handshake message whose
    signature it verified (`hs.resp`, `hs.fin`; a reconnect `hs.init`
    alone doesn't count) or a message under an epoch. It ends in any case
    60 days after the flip. So every member whose vault doesn't process
    the update within that time is lost (section 7, question 1).
  - **S9, a sign of a fork:**
    - **a revoked standing token:** if the service gets `token_revoked`
      for a standing token a member issued to the old key while that key
      is still its key for the member, and the member's token for the
      current key hasn't come 24 hours after the service's first short
      collect after that refusal (read through RELEASE-29 §2's latch), it
      audits `connection.fork_suspected` (`ref` = `relay_revoked`) and
      raises the alarm `fork_suspected`. The connection is not ended (the
      spec only audits);
    - **a revoked reconnect token** starts no 24-hour wait; S9 is judged
      at S1's end instead (RK9): a member S1 ends `stale` after such a
      revocation is audited `connection.fork_suspected` as well as
      `connection.stale`, and the application gets `connection.stale`
      with the reason `relay_revoked` (chosen; not in the spec; a new
      reason, section 7), one event in place of the plain one.
  - **Resends (§3.4 (b)),** to each member that hasn't acknowledged and
    whose standing token for the old key is still valid (with several old
    keys, the newest valid standing token whose `sub` is the service's
    key for that member): the update, deposited again with that key on
    that token, with its links and tokens made again for the member's
    current relay key and sent to its current mailbox. At each start, and
    while running at most once an hour per member (chosen; not in the
    spec: a member vault resends at each unlock, and the service runs for
    weeks between starts). Between vaults a `mailbox_unknown` holds it
    (RK14's hold, section 4); any other definite refusal ends the resends
    to that member.
- **S2, when a member's token arrives** (one write): the service's key
  for it advances; its open reconnects that announced the old key and
  sent no `hs.fin` are abandoned and started again; deposits held by S1,
  and an open handshake's `hs.resp` or `hs.fin` deposited with the old
  key, are deposited again with the new key, the same bytes only on held
  tokens (RK4; an entry on a carried token keeps its token's key, an
  update is sealed afresh).
- **RK8 as the sender.** During S1 toward a member:
  - the service's reconnect `hs.init` to it announces the current key in
    `from.relay`, with `relay_links` from the deposit key to it (1 to 32)
    and tokens minted by the current key's mailbox;
  - its `hs.resp` to the member's reconnect announces the current key in
    `relay`, with the same links and tokens;
  - both carry empty `rotations` (RK5; the `ik` never rotates), and are
    deposited with the key RK3 or S1 gives them (never §3.4 (a)'s old-key
    minting);
  - after the member's `hs.confirm`, the service sends its prompt
    `relay.token.issued` (§6.3.1), which the member takes past the
    cut-off by rule T.

  In the flip's write, the service abandons its open reconnects with a
  member that announced the old key and sent no `hs.fin`; step 3.4
  starts them again under this rule. Other definite refusals of its reconnect during S1
  count as failed tries (RK10, section 4).
- **S3:** every token the service puts in a message to a member names
  the member's key as the service has it; a held token minted for an
  earlier key of the member is minted again when deposited.
- **S7:** a token is revoked at the mailbox that issued it; for the old
  mailbox, only while it lives.
- **RK9:** during S1, a `token_revoked` on a reconnect token a member
  issued for the old key is not a failed try and starts no S9 wait; while
  the service holds no reconnect token for that member only because of
  such revocations, it doesn't judge "no reconnect token" until RK13's
  cap, and waits for the member's reconnect or its `relay.token.issued`.
- **RK11, both sides rotating:** while the service has followed a
  member's new key and holds tokens from it that name a relay key of the
  service's newer than its key for that member, it doesn't judge "no
  valid standing token" or "no reconnect token" toward it, until the
  earlier of those tokens' `exp` and RK13's cap, or sooner at the
  member's `relay.token.issued` for the newer key.
- **First contacts (S6, the relay part).** Invitations made before the
  flip carry the current (old) key's address, those made after it the
  new one's. Invitations, requests and first contacts begun on the old
  address finish there with the old key while its mailbox lives; the
  new connection then gets the update and new tokens. Those still open
  when the old mailbox's collects end, end as expired
  (`connection.expired` to the application).
- **RK14, the telling as the sender** (step 1 and 2):
  - **The anchor** is stored with the current key in a write just before
    the first rotate attempt (cleared only by the relay's own `400` or
    `401`, with §7.1's error body, to that attempt); several old keys
    each keep their own.
  - **`last_msg_id`** for the old mailbox is kept in the flush of each
    batch from it: the largest `msg_id` up to which every message given
    has been processed and flushed. The stop records it in a write (the
    flip itself when the stop is already due).
  - **The telling:** `relay.mailbox.closed {mailbox, last_msg_id}` (null
    when none) to each connection, under its current epoch, queued at
    the stop (or after the flip for a stop before it), in batches by
    connection id with a cursor in the old key's record. Its inner `id`
    is derived from the connection and the mailbox, so a batch queued
    twice after a crash is one message to the member, whose dedupe drops
    the copy. It isn't on S1's list, so for a
    member still in S1 it waits for S2.
  - **Dedupe after the telling:** the inner `id`s processed from the old
    mailbox above `last_msg_id` are kept per connection in a record kind
    of their own, `closeddedupe` (listed in `peer.Kinds()`; `kindInner`
    keeps only 16 days), each record's expiry moved to 76 days after
    that connection's latest telling's `201` (or its last attempt that
    may have reached the relay), so a member's re-deposit is dropped as
    a duplicate.
- **The old key's life** (§3.4 (a), "When the old key is deleted"):
  deposit-only, never registered again; deleted when every member has
  acknowledged or become `stale`, not before the relay's grace ends while
  a reconnect may still reach an unacknowledged one, and not before RK14
  step 1 is done for it.
- **When both sides' mailboxes end** (both rotate, and S1 or RK10's wait
  ends the connection `stale` while the service holds RK14 deposits to
  it): the application's `connection.stale` event carries `reason:
  "relay_moved"`.
- **What the application and the operator see (chosen; not in the
  spec):** the events `relay.waiting` (the gate), `relay.rotated` (the
  flip, with the count of members to acknowledge) and
  `relay.acknowledged` (all have, or the rest are `stale`); the alarms
  `relay_rotation_waiting`, `relay_rotation_failed` (pending past its
  retries for a day, or refused), `relay_mailbox_lost`,
  `relay_key_rolled_back` and, as today, `fork_suspected` and
  `connection.stale`'s.
- **Depends on the relay's grace being 14 days** (RK14: no vault rotates
  before the deployed relays' grace is exactly 14 days). Staging's and
  production's relays are at 7 days today; GC #9440 raises them. The
  relay doesn't advertise its grace (RELAY-PROTOCOL §6.1's limits don't
  include it), so the operator confirms it (`-relay-grace-14d` on the
  command, chosen; not in the spec), and the confirmation is stored with
  its time; a rotation the daemon starts on its own (a lost mailbox once
  the gate opens) needs it too, and waits without it. The daemon also refuses
  to rotate while the relay's advertised `message_ttl_seconds` is above
  14 days, which RK14 step 2 assumes.
- **Its own switch (chosen; not in the spec).** The P side has a second
  one-way constant, `rotate`, off until PR 8, so that PRs 6 and 7 never
  go live half-built: with it off the command and the daemon refuse to
  generate a key. PR 6's `relaykeys` migration, the SSM log and the
  keystore escrow, and the lost-mailbox handling with the gate closed
  (re-registration and re-minted tokens), run whatever either switch
  says. It is one-way for the same reason as the Q switch: once a
  rotation has started, turning it off would strand the members in S1.

## 5a. Times

The service has no `time_scale` (STAGING-TIME-SCALE applies to vaults
on staging). Every wait here is real time: the 60-day waits of RK6,
RK10 and RK14, the 16-day deferral bound, the 60-second visibility
timeout, and as P the 30-day S1 and its 60-day cap (RK13), the 13 days
to the old mailbox's stop (real time in the spec too) and the 76-day
dedupe. **(Chosen; not in the spec.)** On staging a member's S1 (30
days, scaled down) can end long before the service's 60 days do; the
member then ends `stale` first, which a test run on staging should
expect. If staging needs the service's waits shorter, a setting comes
later, with the owner's approval.

## 6. The work

Each PR is reviewed by the lead's blind pair (keys and handshakes). All
of it stays behind the switch (section 1) until the last PR turns it on,
so each can be merged and deployed on its own.

1. **`vms` (vettid-vault, al-cal):** the wire types, checks and vectors
   of section 2. The service pins it in a PR of its own.
2. **The §3.4.1 base**, in two PRs:
   - **2a:** relay-key states and the cut-off in `acceptFrom`; Table A by
     relay key; rule C on relay links; rule U with binding L, the
     follow's answer and the cached refresh answers;
   - **2b:** rule T with the deferral (`defer` kind); RK2 with its
     token-carrying entries.
3. **The handshakes:** RK6, RK7 (with its per-epoch records), RK8 (with
   the `relay.token.issued` after its follow), RK10 with the restore
   rule, RK12.
4. **The hold:** RK14's hold, its §13 rules and the outbox exemptions,
   `relay_held` in the connection API, the `connection.held` and
   `connection.released` events, the 60-day end; RELEASE-29 §13's
   additions marked built.
5. **The keep and the telling:** the `keep` kind with its counters, cap
   and ordered ids, the pin record and cursor, `relay.mailbox.closed`,
   the re-deposits and the cutoffs, the notices. Then, **once the spec
   answers the restore question (section 4),** the switch is turned on
   and `relay_follow` advertised (RK0). A change of the
   advertised features sends existing connections a `profile.update` at
   their next version, as a change of `contract` does (contract.go);
   RELEASE-29 §6 and the README say so.

The P side (section 5) follows, after the Q side, behind its own
one-way switch (on in PR 8), and needs the relays' grace at 14 days
(GC #9440) before it is used. What PR 6 adds outside the switch (the
`relaykeys` migration, the SSM log, the keystore escrow, a lost
mailbox's re-registration with the gate closed) runs at once:

6. **The rotation's order:** the relay keys moved into the `relaykeys`
   record (from the keystore's seed at the first start), the keystore
   escrow, the SSM log, the restore check with its recovery and
   `relay_key_rolled_back`; the request record, the owed mark and
   `admin rotate-relay` (with `-discard-refused`, `-relay-grace-14d`,
   `-relay-url` and the per-incident move to new invitations); the gate
   and `relay.waiting`; preparing in its ordered steps, the rotate and
   registration with retries, the registration-attempted mark and the
   stored fresh-mailbox time; the start that attempts in place of
   registering; the refused state; completing in its ordered steps;
   collecting both mailboxes in order; the audits; a lost mailbox (a
   rotation with the gate open, a re-registration with re-minted tokens
   with it closed). Crash tests inside each step.
7. **S1 and its peers:** S1 (what is held, the update's order, the
   resends, the outbox exemptions), S2, S3, S7, RK3, RK4, RK8 as the
   sender, RK9, RK10 while in its own S1, RK11, RK13's clock, S9 (both
   paths), first contacts on the old address.
8. **The old mailbox's end:** RK14's anchor, `last_msg_id` and stop, the
   telling with its cursor and its 76-day dedupe (`closeddedupe`), the
   old key's deletion, the `relay.rotated` and `relay.acknowledged`
   events and the alarms. Then the P switch is turned on.

RK1-b's narrowing (section 4) is a separate conformance PR.

Tests use `peertest` members that rotate: a follow by update and by
reconnect (from the current key and from an earlier one), a duplicate,
binding L's refusals, a relay fork, the cut-off passes and their
closure, a refused reconnect after `mailbox_unknown` with and without a
newer mailbox and after a restore, a hold re-addressed at a follow (a
held entry untried and one tried before its hold) and one that ends at
60 days, a telling with entries above and below `last_msg_id` and with
`null`, a crash between telling batches, the cutoff, and the keep's
cap. For the P side: a closed gate that waits, a rotation with a crash
between each step, a refused rotate and its way out, a registration
past the grace, members that acknowledge, one that goes `stale` at
RK13's end (and one with S9), both sides rotating (RK11), the telling
sent and a member's re-deposit dropped by the dedupe, and the old key's
deletion. Each is mutation-checked, and each runs with the switch off
too, showing today's behaviour unchanged.

## 7. Open questions

1. **Decided (owner b, GC #10505): the service rotates its relay key
   too** (section 5). Still open there, for the owner: the deadline. The
   service waits on a closed gate instead of moving members to new
   invitations after 30 days, unless the owner decides per incident; and
   today every member's gate is closed, so until member vaults advertise
   `relay_follow`, a relay-key exposure is answered by waiting or by new
   invitations. And once a rotation goes ahead, RK13 makes `stale` every
   member whose vault doesn't process the update within 30 to 60 days
   (a member offline that long connects again).
2. **The application events** of sections 4 and 5 (`connection.held`,
   `connection.released`, `message.not_delivered`,
   `message.delivery_unconfirmed`, `connection.suspended` with the
   reason `relay`, `connection.stale` with the reasons `relay_revoked`
   and `relay_moved`, `relay.waiting`, `relay.rotated` and
   `relay.acknowledged`): their names and payloads change the service's
   webhook contract (README "Events"), which the application team
   should see before PR 4.
3. **Which service messages are "member messages"** (told when lost) is
   this document's reading of §3.4.2 step 3 for a service: `vote.*` and
   `connection.authenticate.challenge` and `.withdraw`.
4. **What changes toward today's vaults once the switch is on,** even
   before any member rotates:
   - up to 60 days of the service's sends kept (sealed) in the table and
     its backups;
   - a `mailbox_unknown` from a member's mailbox holds instead of ending
     the connection `stale`;
   - every existing connection gets a `profile.update` advertising
     `relay_follow` (a fan-out to every member at that start), and with
     it every member's gate (RK0) opens: member vaults that implement
     §3.4.2 may then rotate toward the service. That is why the switch
     is one-way (section 1).
5. **For the spec (the lead's erratum):** a restore across a member's
   follow (section 4, gating PR 5); RK14's re-deposit `ts`;
   `connection.approved` in step 3's list; RK2's token-carrying entries;
   and a path for moving a vault to a different relay (section 5: §3.4's
   order rotates on the current relay only); and that RELAY-PROTOCOL
   advertises no rotation grace, which RK14 needs to check.

**Residual.** A table restore forgets the relay and identity links the
service followed since the backup. Until the spec answers question 5's
first item, a member that rotated since then must connect again.

## Changes

- **0.7.0 (2026-11-14):** section 5, after the blind pair: recovery
  after a restore only with the whole signed chain in the SSM log, and
  the escrow in SSM (the keystore item is in the table); every batch
  sized to one transaction with its marker, the marker naming the key
  and mint generation, held updates rebuilt around re-minted tokens;
  the load rule keeps the current key's unreleased updates; the next key
  committed in the flip's write; a lost mailbox seen at a start as a
  `201`, with the registration-attempted and re-mint-owed marks (and GC
  #10525 for today's code); every pending key unconfirmed at the first
  start after a restore; the peer lock across completing; S1's clock
  from the flip's time; the log entries' order, discards logged, the
  check against any key the table holds, superseded keys never
  registered; the telling's derived inner `id`; the keystore field set
  after the flip; the chosen labels; the stored grace confirmation;
  nits.
- **0.6.0 (2026-11-14):** section 5, after the blind pair: the first and
  second writes as ordered steps, each its own `Apply`, with commit
  points (the `relaykeys` record, the flip), held updates naming their
  key, each connection's key for the service stored explicitly, releases
  and the telling resumable by cursor, crash tests in each step; a lost
  mailbox rotates with the gate open and re-registers with it closed
  (the lead's decision); the registration-attempted mark and a `200`
  after an unanswered attempt treated as fresh; the pending seed
  escrowed in the keystore, the SSM log before the flip, and a restored
  table's key recovered from them; the keystore drops the old seed at
  the flip; the P side's own switch; outbox exemptions during S1;
  `last_msg_id` and deferred messages at the stop; the refused state
  attempted daily and by command; the request deleted with the mark;
  limits and URLs per key; RK13's cost; S9's standing-token path
  audit-only; `closeddedupe`; what a relay-key holder can do; nits.
- **0.5.0 (2026-11-14):** the owner's b (GC #10505): the service also
  rotates its own relay key. Section 1 becomes "both Q and P"; a new
  section 5 gives the P side (the operator command and the owed mark,
  the gate and its waiting, the order of a rotation with its retries and
  refused state, collecting both mailboxes, S1 to S3, S7, S9, RK3, RK4,
  RK9, RK11, RK13, first contacts on the old address, RK14's telling as
  the sender, the old key's life, the events and alarms, the relays'
  14-day grace); PRs 6 to 8; Times gains the P-side waits. Within it,
  after the author's review: a start attempts the pending key in place
  of registering; a restore across the service's own rotation (the SSM
  log, `relay_key_rolled_back`); the relay keys in a `relaykeys` record;
  the command writes a request the daemon acts on; a lost mailbox's
  re-registration re-mints tokens; S9 for a standing token, and S9 at
  S1's end as `connection.stale` (`relay_revoked`); RK8 as the sender;
  the way out keeps the mark, the anchor and the stop; a relay move left
  to the spec; the grace confirmed by the operator; the anchor-old order,
  the stored fresh-mailbox time, the audits, the refused state's
  collects, resends and RK13's counting. The Q side changes where the
  service rotating makes it false: RK6's and RK10's waits and RK10's
  cases while the service is in its own S1, the keep's list
  (`relay.mailbox.closed` kept, `relay.address.update` not), and rule
  T's deferral across two mailboxes.
- **0.4.1 (2026-11-14):** the hold's 60-day end clears `relay_held`;
  the follow's dedupe marks after its connection record, entries moved
  back or re-addressed at load, the follow redone after a crash; a
  durable owed mark for the follow's answer; `restore_relay_moved`
  service-wide; the keep's 60-day exit for unpinned entries only; a
  tried entry ended by case 2 after a long hold is told; nits.
- **0.4.0 (2026-11-14):** the write order made explicit (outbox, keep,
  connection record; batches sized to one `Apply`; a re-address
  idempotent at load; counters recomputed); the telling stored in a
  list of pins before any re-deposit, a second telling ignored; a
  restore across a follow is open and gates PR 5, with an alarm and the
  residual; new entries during a hold queued held; re-deposits waiting
  in the keep; refresh answers not answered after a follow; the switch
  a one-way code constant; the kept-`ts` and `connection.approved`
  readings marked chosen; `message.not_delivered` against
  `.delivery_unconfirmed`; nits.
- **0.3.0 (2026-11-14):** RK8 accepts the current key too, with the
  chain-end check at parse; held entries against RELEASE-29 §13 (the
  start rule, case 2, when a re-addressed entry takes a fresh `ts`); the
  outbox bound's exemptions and batches; the telling's write order and
  pin record; the keep's ordered ids, size and backups; a restore across
  a follow decided; the cached refresh answers deleted at a follow; a
  switch instead of a deploy freeze; `connection.approved` not kept; the
  application told, reversing §13 for these cases; the deferral in its
  own kind; RK1-b split out; an owed restart; shared vectors and a
  staging run with a real vault; staging's S1 against the service's
  waits; PR 2 split.
- **0.2.0 (2026-11-14):** RK10 limited to `mailbox_unknown`, with the
  failed-try rule; RK6's wait covers every reconnect after a follow;
  RK7's conditions and closure; RK8's refusals and the token after its
  follow; binding L's order and reasons; the cut-off for an RK8 follow;
  RK2's token-carrying entries (chosen); the hold's rules, the outbox
  bound and today's `mailbox_unknown` handling; the keep's exits and
  storage; the duplicate's clock; the deferral's details; RK1-b's
  difference; legacy moves; a features change sends `profile.update`;
  open questions.
- **0.1.0 (2026-11-14):** first draft.
