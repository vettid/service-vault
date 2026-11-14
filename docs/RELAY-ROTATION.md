# Relay-key rotation in the service vault

**Status:** 0.2.0, draft (2026-11-14). Against VAULT-MESSAGING 0.90.11
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
  for the owner's approval, section 7).** A vault's relay key rotates
  only within §3.4's paths (a recovery, a transfer, a
  `credential.rotate`), together with its `ik`, and the service has none
  of them. §3.4 also says a vault "MUST rotate after any suspected
  exposure of its state". For the service the substitute is the one
  RELEASE-29 §1 gives for its `ik`: new keys and new invitations for
  every member. The same holds for:
  - **a lost or ended service mailbox.** Members that implement RK14
    hold their refused deposits until they follow the service to a newer
    mailbox. A service that never rotates gives no follow, so they stay
    held up to 60 days and then end `message.not_delivered`, the
    connection `stale`. Re-registering the same key at start does not
    release them (a fresh mailbox at a deleted id refuses tokens issued
    before the deletion, §3.4 "After the grace");
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

  The refusal of updates ends with PR 2, the `mailbox_unknown` handling
  with PR 4, and `relay_follow` comes with PR 5 (section 6).

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
    wins over `relay_unlinked`.

  The service pins the `vms` release that has them; that pin change is
  its own PR, with `docs/SOURCE.md` regenerated.
- **No member vault rotates a relay key yet** (§3.4.1 A5), and none
  advertises `relay_follow`. Nothing here changes how the service talks
  to today's vaults until a member vault release rotates. Tests run
  against `peertest` members that rotate.

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
    application gets `connection.suspended` with that reason, and the
    operator the alarm `fork_suspected` (RELEASE-29 §7);
  - the only exit is a new invitation, as the spec says
    (`connection.rotation.resolve` answers `not_found` and the service
    has no member UI anyway).
- **Legacy moves.** A connection a `relay.address.update` moved before
  #152 (`LegacyPrevRelayPK`) stays suspended (`relay_moved_unlinked`);
  it never enters the earlier-key state, and nothing here revives it.
- **Rule U, the follow.** Rule U's checks as written (chain form and
  count, ends, the followed prefix, `relay_rollback`, the cap, rule T on
  `token`, else `token_unusable`), then, in one state write: the links,
  the cut-offs, `relay.pk` made current, the tokens kept (a
  `reconnect_token` that fails rule T is ignored, no reason to refuse).
  After it: `relay.token.issued` for the new key (standing and
  reconnect), the reconnect tokens issued to the passed keys revoked
  (those that open answers and pending epochs carry included), and the
  reconnect token held for the passed mailbox replaced by the update's,
  if kept (without one, RK6's wait).
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
    first time it was seen, stored by `msg_id` so a restart doesn't
    reset it (the unacked records of `kindUnacked` serve);
  - at most 8 deferred messages per member and reason, each kept at most
    16 days;
  - a deferred message takes no dedupe mark: session.go marks the inner
    `id` before dispatch today, so the deferral is decided before that
    mark;
  - past either bound it is processed, and its token ignored (not
    refused).

## 4. §3.4.2 for a service

- **RK1** is built (RELEASE-29 §14 item 4b), with one difference from
  RK1-b: the service discards a member's rekey `hs.init` during **any**
  open reconnect of its own (audited `rekey_while_reconnecting`,
  handshake.go; RELEASE-29 §3), where RK1-b names only a reconnect that
  names an epoch other than the current one (`rekey_replaced_by_reconnect`).
  PR 3 narrows it to RK1-b and takes RK1-b's audit name.
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
    dropped, like a waiting `relay.token.issued`: the follow's
    `relay.token.issued` gives the member fresh tokens. A kept
    `connection.approved` is never deposited again once the connection
    is active (activation shows the member had it). No other message the
    service sends carries a token. (Worth a spec line: RK2 moves such
    entries without saying they are minted again.)
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
  - **Accepted** from an earlier key, before or after its cut-off, when
    the links connect `sender` to the announced key and pass rule C.
  - **Refused:**
    - a fault in a link's form, a wrong count, or a last `new` that is
      not the announced key: `relay_unlinked`, at parse;
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
  - **After an RK8 follow** the service sends its `relay.token.issued` for
    the new key, as after rule U's, on a token for the new mailbox (the
    member's prompt `relay.token.issued`, or the `hs.init`'s carried
    token for its `hs.confirm`). Without it the member's S1 toward the
    service never ends.
- **RK10.** Of RK10's cases only `mailbox_unknown` applies to the
  service's own reconnect `hs.init` (the others need the service in its
  own S1, or a reconnect token issued for an earlier key of its own).
  - With a newer mailbox of P's followed (by rule U or RK8): the try
    ends at once, counts as a failed try under "The reconnect bound", and
    the next starts at once.
  - With none followed: the refusal is not counted, and the service waits
    for P's links up to 60 days after the first such refusal; then the
    connection becomes `stale`.
  - Every other refusal is as "The reconnect bound" says.
- **RK12.** While a connection is suspended, relay links that pass rule
  C are still kept as seen (step 1).
- **RK14, the hold.** Replacing today's handling (section 1), a durable
  deposit to P's mailbox refused `mailbox_unknown` is **held**, without
  `stale`, while the connection exists and the service has not followed
  P to a newer mailbox:
  - a handshake message is not held: it ends as a refusal of its carried
    token does (§6.3.1);
  - neither `stale` nor an update the service refuses or doesn't follow
    ends a hold;
  - at a follow, held deposits are re-addressed to the new mailbox,
    sealed again under the current epoch with a fresh `ts` and a new
    `seq`, and `relay_held` ends (a later refusal starts a new episode);
  - at the connection's end, they end as §8.3 says;
  - at 60 days after the episode's first refusal, every held entry for
    that member ends undelivered (`undelivered_mailbox_unknown`), and the
    connection becomes `stale` if it isn't already. Past that limit in
    the same episode, a `mailbox_unknown` ends an entry at once.
  - **The outbox bound stays (chosen; not in the spec).** Held entries
    count toward `MaxOutboxPerConn` (256). During a long hold, new sends
    past it are refused at once (`outbox_full`, the caller gets an
    error), so a held connection can't grow the outbox without bound.
    The application learns of the hold from `connection.held` (below).
  - **What the application sees (chosen; not in the spec).** The service
    has no member feed. The connection record carries `relay_held:
    {since}`, shown in the connection API. Its start and end are events
    to the application, `connection.held` and `connection.released`, so
    it can tell its users that messages wait. An entry that is a "member
    message" (below) ended undelivered also emits
    `message.not_delivered` to the application, with the request it came
    from.
- **RK14, the keep.**
  - **What is kept.** For 60 days after each `201` to a member's
    mailbox, the inner message of every durable session entry except
    those §3.4.2 step 3 lists as not kept. For what the service sends,
    that is:
    - the "member messages", told when lost: `vote.*` (its sends and its
      answers to members' requests), `connection.authenticate.challenge`
      and `.withdraw`, and `connection.approved`;
    - `profile.update`, upkeep, audited only.

    Not kept: handshakes, `hs.confirm`, `relay.token.issued` and
    `relay.token.refresh`, and `connection.removed`.
  - **When an entry leaves the keep:** at its 60 days; when its `exp`
    passes (a pinned one is audited `drop.held_expired`, an unpinned one
    ends silently; the service's challenges carry `exp`); at the
    connection's removal, which deletes all its kept and pinned entries.
  - **The cap:** 2,000 entries and 8 MiB of kept inners per member, the
    oldest dropped first, with the record of dropped member messages
    (count, highest `msg_id`, first inner `id`) the spec describes.
  - **Storage (chosen; not in the spec).** A record kind of its own,
    `keep`, one record per kept entry, sealed like every record and
    listed in `peer.Kinds()`. Each record is written in the same state
    write that records its `201`, so a crash loses none. The connection
    record carries the member's kept count and bytes, kept in the same
    writes, so the cap is enforced at each `201` without reading the
    records. They are not loaded into memory at start: they are read
    per member at a follow or a telling, and pruned in batches at
    housekeeping.
- **RK14, the pin and the telling as received.**
  - **At a follow** the entries kept for the passed mailbox are pinned
    until P's `relay.mailbox.closed` for it, or 60 days after the follow.
  - **The telling** is accepted only for such a pinned mailbox, never for
    P's current one (acked and ignored otherwise). Entries above
    `last_msg_id` are deposited again to P's current mailbox; the rest are
    dropped. A `last_msg_id` of `null` means every pinned entry goes
    again.
  - **The cutoff.** A re-deposit goes only within 60 days of the
    telling's `deposited_at`; a re-deposited entry keeps the first
    telling's cutoff across later rotations. The cutoff binds every
    attempt: an entry still waiting at it (for a token, behind a
    demotion, held) ends at once.
  - **Re-deposits** are sealed again under the current epoch with the
    same inner `id`, a fresh `ts` and a new `seq`, and judged by §8.3 "At
    deposit".
  - **The dropped-entries record** tells when the telling's
    `last_msg_id` is below its highest `msg_id`, or at the 60-day
    deadline with no telling.
  - With no telling by 60 days after the follow, the pinned member
    messages are told lost.
  - **Told (chosen; not in the spec):** a member message the service
    gives up on emits `message.delivery_unconfirmed` to the application,
    as §8.3's notice would to a member, with the request it came from.
    Everything else is audited only.
  - **Attachments** do not arise: the service sends none.
- **When both sides' mailboxes end** does not arise.

## 5. Times

The service has no `time_scale` (STAGING-TIME-SCALE applies to vaults
on staging). Every wait here is real time: the 60-day waits of RK6,
RK10 and RK14, the 16-day deferral bound, the 60-second visibility
timeout. **(Chosen; not in the spec.)** If staging needs them shorter, a
setting comes later, with the owner's approval.

## 6. The work

Each PR is reviewed by the lead's blind pair (keys and handshakes).
**None is deployed before PR 5 is merged (chosen):** between PR 2 and
PR 5 the service would follow updates without the hold and the keep. As
with RELEASE-29 §14, the changes deploy together.

1. **`vms` (vettid-vault, al-cal):** the wire types and checks of
   section 2. The service pins it in a PR of its own.
2. **The §3.4.1 base:** relay-key states and the cut-off in
   `acceptFrom`; Table A by relay key; rule C on relay links; rule U
   with binding L; rule T with the deferral; RK2 with its token-carrying
   entries. `relay.address.update` is followed instead of refused.
3. **The handshakes:** RK6, RK7 (with its per-epoch records), RK8 (with
   the `relay.token.issued` after its follow), RK10, RK12, and RK1-b
   narrowed as section 4 says.
4. **The hold:** RK14's hold replacing today's `mailbox_unknown`
   handling, `relay_held` in the connection API, the
   `connection.held`/`connection.released` events, the 60-day end.
5. **The keep and the telling:** the `keep` kind with its counters and
   caps, the pin, `relay.mailbox.closed`, the re-deposits and the
   cutoffs, the notices. Then `relay_follow` is advertised (RK0). A
   change of the advertised features sends existing connections a
   `profile.update` at their next version, as a change of `contract`
   does (contract.go); RELEASE-29 §6 and the README say so.

Tests use `peertest` members that rotate: a follow by update and by
reconnect, a duplicate, binding L's refusals, a relay fork, the cut-off
passes and their closure, a refused reconnect after `mailbox_unknown`
with and without a newer mailbox, a hold re-addressed at a follow and
one that ends at 60 days, a telling with entries above and below
`last_msg_id` and with `null`, the cutoff, and the keep's cap. Each is
mutation-checked.

## 7. Open questions

1. **For the owner: no relay-key rotation for the service.** §3.4's
   "MUST rotate after any suspected exposure" is replaced, for the
   service, by new keys and new invitations for every member; so is a
   lost mailbox or a relay change (section 1). Is that acceptable, or
   must the service implement the rotating side too?
2. **For the lead (a spec question): a service restore across a member's
   follow.** A table restore can bring back a connection from before the
   service followed a member's relay link: the earlier key current, no
   cut-offs. The member's deposits from its new key are then
   `foreign_sender`; the restore's reconnect goes to the old mailbox and
   meets `mailbox_unknown` once the grace has passed; and RK10 waits up
   to 60 days for links the member won't send again, its S1 being over.
   Neither the spec nor this note covers it yet.
3. **The application events** of section 4 (`connection.held`,
   `connection.released`, `message.not_delivered`,
   `message.delivery_unconfirmed`): their names and payloads change the
   service's webhook contract (README "Events"), which the application
   team should see before PR 4.
4. **Which service messages are "member messages"** (told when lost) is
   this document's reading of §3.4.2 step 3 for a service: `vote.*`,
   `connection.authenticate.challenge` and `.withdraw`, and
   `connection.approved`.

## Changes

- **0.2.0 (2026-11-14):** RK10 limited to `mailbox_unknown`, with the
  failed-try rule; RK6's wait covers every reconnect after a follow;
  RK7's conditions and closure; RK8's refusals and the token after its
  follow; binding L's order and reasons; the cut-off for an RK8 follow;
  RK2's token-carrying entries (chosen); the hold's rules, the outbox
  bound and today's `mailbox_unknown` handling; the keep's exits and
  storage; the duplicate's clock; the deferral's details; RK1-b's
  difference; legacy moves; deploy only after PR 5; a features change
  sends `profile.update`; the exposure MUST, a lost mailbox, a relay
  change and a restore across a follow as open questions.
- **0.1.0 (2026-11-14):** first draft.
