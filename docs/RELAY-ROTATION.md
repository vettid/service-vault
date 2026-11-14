# Relay-key rotation in the service vault

**Status:** 0.4.1, draft (2026-11-14). Against VAULT-MESSAGING 0.90.11
(§3.4.1, §3.4.2). GC #9442.

VAULT-MESSAGING §3.4.2 RK0 asks a service vault to follow the relay-key
rotation rules "as a member vault does", and to advertise
`relay_follow` only once it implements §3.4.1 and §3.4.2 in full. The
rules are written for two vaults that may each rotate. This document
states how they read for this service, which does not rotate its own
relay key (section 1), says where the spec leaves a choice to it, and
splits the work. The code follows this text; none of it is built yet.

Choices are marked **(chosen; not in the spec)**. Everything else is
the spec's own rule, restated for a service; where this text is shorter
than the spec, the spec governs. As in RELEASE-29.md, the service runs
as one task, and one lock (the peer's) covers every state change.

## 1. Scope: the service is only ever Q

- **The service does not rotate its relay key (chosen; not in the spec;
  for the owner's approval, GC #10473).** A vault's relay key rotates
  only within §3.4's paths (a recovery, a transfer, a
  `credential.rotate`), together with its `ik`, and the service has none
  of them. §3.4 also says a vault "MUST rotate after any suspected
  exposure of its state". For the service the substitute is the one
  RELEASE-29 §1 gives for its `ik`: new keys and new invitations for
  every member. The same holds for:
  - **a lost or ended service mailbox.** A fresh mailbox at the same id
    refuses the tokens issued before the deletion (§3.4 "After the
    grace"), so members' deposits fail at the token, and nothing a
    service that never rotates sends can give them a newer mailbox to
    follow;
  - **a change of relay or relay URL.** Rule U needs a link whose `old`
    differs from its `new`, so moving relays means a key change.
- **So the rotating side's rules are inert:** S1, S2 and their resends,
  the second write, RK3, RK4, RK9, RK11 (both sides rotating), RK13's
  clock (a side in its own S1), RK14's telling as the sender (the anchor,
  the stop, `last_msg_id`), and "The gate".
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
  Tests set it through a test hook, so every test also runs with it off. PR 5's switch also
  waits on the spec's answer to the restore question (section 4).

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

- **Order of processing.** The service has one mailbox, so the
  multi-mailbox order and collected-to times do not arise.
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
    the service waits up to 60 days after the follow (it is never in its
    own S1) and does not judge "no reconnect token" meanwhile. Past the
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
- **RK10.** Of RK10's cases only `mailbox_unknown` applies to the
  service's own reconnect `hs.init` (the others need the service in its
  own S1, or a reconnect token issued for an earlier key of its own).
  - With a newer mailbox of P's followed (by rule U or RK8): the try
    ends at once, counts as a failed try under "The reconnect bound", and
    the next starts at once.
  - With none followed: the refusal is not counted. The service doesn't
    retry; it waits for P's links up to 60 days after the first such
    refusal, then the connection becomes `stale` with the alarm
    `reconnect_failed`. Except after a restore (below).
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
    - `profile.update`, upkeep, audited only.

    Not kept: handshakes, `hs.confirm`, `relay.token.issued` and
    `relay.token.refresh`, `connection.removed`, and `connection.approved`.
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
- **When both sides' mailboxes end** does not arise.

## 5. Times

The service has no `time_scale` (STAGING-TIME-SCALE applies to vaults
on staging). Every wait here is real time: the 60-day waits of RK6,
RK10 and RK14, the 16-day deferral bound, the 60-second visibility
timeout. **(Chosen; not in the spec.)** On staging a member's S1 (30
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

RK1-b's narrowing (section 4) is a separate conformance PR.

Tests use `peertest` members that rotate: a follow by update and by
reconnect (from the current key and from an earlier one), a duplicate,
binding L's refusals, a relay fork, the cut-off passes and their
closure, a refused reconnect after `mailbox_unknown` with and without a
newer mailbox and after a restore, a hold re-addressed at a follow (a
held entry untried and one tried before its hold) and one that ends at
60 days, a telling with entries above and below `last_msg_id` and with
`null`, a crash between telling batches, the cutoff, and the keep's
cap. Each is mutation-checked, and each runs with the switch off too,
showing today's behaviour unchanged.

## 7. Open questions

1. **For the owner (GC #10473): no relay-key rotation for the service.**
   §3.4's "MUST rotate after any suspected exposure" is replaced, for the
   service, by new keys and new invitations for every member; so is a
   lost mailbox or a relay change (section 1).
2. **The application events** of section 4 (`connection.held`,
   `connection.released`, `message.not_delivered`,
   `message.delivery_unconfirmed`, and `connection.suspended` with the
   reason `relay`): their names and payloads change the service's
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
   `connection.approved` in step 3's list; RK2's token-carrying entries.

**Residual.** A table restore forgets the relay and identity links the
service followed since the backup. Until the spec answers question 5's
first item, a member that rotated since then must connect again.

## Changes

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
