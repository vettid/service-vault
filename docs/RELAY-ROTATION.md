# Relay-key rotation in the service vault

**Status:** 0.1.0, draft (2026-11-14). Against VAULT-MESSAGING 0.90.11
(§3.4.1, §3.4.2). GC #9442.

VAULT-MESSAGING §3.4.2 RK0 asks a service vault to follow the relay-key
rotation rules "as a member vault does", and to advertise
`relay_follow` only once it implements §3.4.1 and §3.4.2 in full. The
rules are written for two vaults that may each rotate. This document
states how they read for this service, which never rotates its own
relay key, says where the spec leaves a choice to it, and splits the
work. The code follows this text; none of it is built yet.

Choices are marked **(chosen; not in the spec)**. Everything else is
the spec's own rule, restated for a service. As in RELEASE-29.md, the
service runs as one task, and one lock (the peer's) covers every state
change.

## 1. Scope: the service is only ever Q

- **The service never rotates its relay key (chosen; not in the
  spec).** It has no recovery, transfer or `credential.rotate`, which
  are what make a member vault rotate (§3.4, §11.14.2). Replacing its
  relay key would mean new invitations for every member, as replacing
  its `ik` does (RELEASE-29 §1). So it is never P, and the rotating
  side's rules are inert:
  - S1, S2 and their resends, the second write, RK3, RK4 and RK9;
  - RK11, which needs both sides to rotate;
  - RK13's clock, which runs only for a side in its own S1;
  - RK14's telling as the sender, the anchor, the stop and
    `last_msg_id`;
  - "The gate", since it gates the rotating side.
- **What it does as Q,** toward a member vault P that rotates:
  1. **§3.4.1's receiving side:** the relay-key states (current,
     earlier, foreign) and the cut-off in `acceptFrom`; Table A by
     relay key; rule C on relay links (seen, forks); rule U to follow
     `relay.address.update`; rule T for the tokens.
  2. **§3.4.2:** RK2, RK5 (binding L), RK6, RK7, RK8, RK10, RK12, and
     RK14's receiving side: the hold, the keep, the pin, the telling
     as received, and the re-deposits.
  3. **RK0:** advertise `relay_follow` once 1 and 2 are built, never
     before.
- **Today** a `relay.address.update` is refused outright and audited
  `address_update_refused` (session.go, from vettid-vault #241), and
  `relay_follow` is not advertised (RELEASE-29 §6). Both stay until the
  last PR below.

## 2. What it depends on

- **The wire types belong in vettid-vault's `vms`, not here (chosen
  with the lead, GC #10442).** Member vaults need the same receiving-side
  code, and the two must agree byte for byte:
  - the relay link (`{v, suite, old, new, sig_old, sig_new}`, label
    `vettid/vms/2/relay-rotate`) with its form checks and verification;
  - the `relay.address.update` body (`relay`, `relay_links`, `rotations`,
    `token`, `reconnect_token`) and the `relay.mailbox.closed` body
    (`mailbox`, `last_msg_id`);
  - `relay_links` and `relay` in a reconnect `hs.init` and `hs.resp`, with
    rule U's precedence (malformed body wins over `relay_unlinked`).

  The service pins the `vms` release that has them; that pin change is
  its own PR, with `docs/SOURCE.md` regenerated.
- **No member vault rotates a relay key yet** (§3.4.1 A5), and none
  advertises `relay_follow`. Nothing here changes how the service talks
  to today's vaults until a member vault release rotates. Tests run
  against `peertest` members that rotate.

## 3. §3.4.1 for a service

- **Order of processing.** The service has one mailbox (it never
  rotates), so the multi-mailbox order and collected-to times do not
  arise.
- **Relay-key states and the cut-off.** Each connection keeps P's
  current relay key, and every earlier key with its followed link and
  its cut-off (the followed update's mailbox position: `msg_id`, and
  `deposited_at`). An earlier key leaves from the oldest end once no
  token the service issued to it can still deposit (a revoked reconnect
  token counts until its revocation has left the outbox; a denied
  standing token until its `exp`).
  - **At most 32 earlier keys per member** (the spec's reading, to be
    confirmed): a follow that would keep more is refused `unexpected`.
- **Table A** runs at `acceptFrom` step 4 as written, with the
  three exceptions between vaults (RK7's `hs.confirm` and `hs.fin`,
  RK8's linked reconnect messages).
- **Rule C, relay links.** Every valid relay link that passes step 3 is
  kept as seen, at most 32 per member (counted apart from identity
  links). A second successor suspends the connection as a relay fork:
  - audit `connection.fork_suspected` with `ref` = `relay`; the
    application gets `connection.suspended` with that reason, and the
    operator the alarm `fork_suspected` (RELEASE-29 §7);
  - `connection.rotation.resolve` doesn't apply to a service (it has no
    member UI); the only exit is a new invitation, as the spec says.
- **Rule U, the follow.** As written, in one state write: the links, the
  cut-offs, `relay.pk` made current, the tokens kept. After it:
  `relay.token.issued` for the new key (standing and reconnect), the
  reconnect tokens issued to the passed keys revoked (those that open
  handshakes and pending epochs carry included), and the reconnect
  token held for the passed mailbox replaced by the update's, if kept.
  - **A duplicate** gets a fresh `relay.token.issued`, **at most one an
    hour per member** (the spec's reading of §7.2's limits, taken as
    is).
  - **Binding L (RK5, RK10):** rule U's checks that don't depend on the
    `ik` run first; then the update's identity links are judged as an
    `identity.rotate`'s (Table B), and RK5's `ik` requirement against
    the `ik` they lead to, before anything is applied. Only an update
    that is then followed (or a duplicate that passes) has its identity
    links applied, then its relay links, then its tokens, in the same
    write. The service already follows identity links (rotation.go,
    R29-K9); this reuses it.
- **Rule T** as written. A `relay.token.issued` whose `iss` is a mailbox
  the service doesn't know for P is **deferred**: at most two visibility
  timeouts of **60 seconds** each (the relay's value is not read: the
  spec's fail-closed reading), at most 8 deferred messages per member
  and reason, each kept at most 16 days.

## 4. §3.4.2 for a service

- **RK1** is already built (RELEASE-29 §14 item 4b).
- **RK2.** Every token the service puts in a message to P names P's key
  on record when the message is deposited; for a handshake message,
  when it is sealed. At a follow, queued deposits on the held standing
  token move to the new mailbox; a queued `relay.token.issued` is
  dropped (the follow's answer replaces it). A handshake's own deposits
  keep their mailbox.
- **RK6.** At a follow, the service's own open reconnects whose
  `hs.init` carried tokens for the passed key and that have sent no
  `hs.fin` are abandoned (their tokens revoked) and started again,
  only on a held reconnect token for P's current mailbox. Without one,
  the restart waits up to 60 days after the follow (the service is never
  in its own S1), and "no reconnect token" is not judged meanwhile.
  The service starts reconnects only after a restore (RELEASE-29 §3),
  so this matters only when a restore and a member's rotation overlap.
- **RK7.** The cut-off pass for an `hs.confirm` and for an `hs.fin` to
  an answer the service has open, closed per epoch by establishment
  order. Each closure is recorded with the epoch and never undone; the
  records live as long as the earlier key does.
- **RK8.** A member's reconnect `hs.init` (to the service) and
  `hs.resp` (to the service's reconnect) may announce a newer key with
  `relay_links`. The service accepts them from an earlier key when the
  links connect `sender` to the announced key and pass rule C, and
  follows at the verified `hs.fin` (an `hs.init`'s) or at `sig_R` (an
  `hs.resp`'s), in RK8's order: identity links, relay links, tokens.
- **RK10.** A definite refusal of the service's reconnect `hs.init`
  tied to the member's rotation (`mailbox_unknown`, or a refusal while
  links are known to be pending) ends the try at once. After
  `mailbox_unknown` the next try starts once the service has followed
  a newer mailbox; with none known, the refusal is not counted and the
  service waits up to 60 days for the member's links, then the
  connection becomes `stale`.
- **RK12.** While a connection is suspended, relay links that pass rule
  C are still kept as seen (step 1).
- **RK14, the hold.** A durable deposit refused `mailbox_unknown` is
  held, not dropped (today: `undelivered_mailbox_unknown`, outbox.go),
  while the connection exists and the service has not followed P to a
  newer mailbox. A handshake message is not held. At a follow, held
  deposits are re-addressed to the new mailbox, sealed again under the
  current epoch with a fresh `ts` and `seq`. At 60 days after the
  episode's first refusal, every held entry ends undelivered and the
  connection becomes `stale`.
  - **What the application sees (chosen; not in the spec).** The service
    has no member feed. The connection record carries `relay_held:
    {since}`, shown in the connection API; its start and end are events
    to the application, `connection.held` and `connection.released`, so
    it can tell its users that messages wait. An entry ended undelivered
    raises the existing `undelivered` audit; one that is a "member
    message" (below) also emits `message.not_delivered` to the
    application, carrying the request it came from.
- **RK14, the keep and the telling as received.**
  - **What is kept.** For 60 days after each `201` to a member's
    mailbox, the inner message of every durable session entry except
    those §3.4.2 step 3 lists as not kept. For what the service sends
    that is: `vote.*`, its sends and its answers to members' requests,
    `connection.authenticate.challenge` and `.withdraw`, and
    `connection.approved` (the "member messages", told when lost), and
    `profile.update` (upkeep, audited only). Handshakes, `hs.confirm`,
    `relay.token.issued` and `relay.token.refresh`,
    `connection.removed` and `connection.declined` are not kept.
  - **The cap:** 2,000 entries and 8 MiB of kept inners per member, the
    oldest dropped first, with the record of dropped member messages
    (count, highest `msg_id`, first inner `id`) the spec describes.
  - **Storage (chosen; not in the spec).** A record kind of its own,
    `keep`, one record per kept entry, sealed like every record and
    listed in `peer.Kinds()`. It is not loaded into memory at start: it
    is read per member at a follow or a telling, and pruned in batches
    at housekeeping.
  - **At a follow** the entries kept for the passed mailbox are pinned
    until P's `relay.mailbox.closed` for it or 60 days after the follow.
    The telling is accepted only for such a pinned mailbox, never for
    P's current one (acked and ignored otherwise). Entries above
    `last_msg_id` are deposited again to P's current mailbox, within 60
    days of the telling's `deposited_at` (the first telling's cutoff
    is kept across later rotations), each sealed again with the same
    inner `id`, a fresh `ts` and a new `seq`. With no telling by 60 days
    after the follow, the pinned member messages are told lost.
  - **Told (chosen; not in the spec):** a member message the service
    gives up on emits `message.delivery_unconfirmed` to the application,
    as §8.3's notice would to a member, with the request it came from.
    Everything else is audited only.
  - **Attachments** do not arise: the service sends none.
- **When both sides' mailboxes end** does not arise (the service never
  rotates).

## 5. Times

The service has no `time_scale` (STAGING-TIME-SCALE applies to vaults
on staging). Every wait here is real time: the 60-day waits of RK6,
RK10 and RK14, the 16-day deferral bound, the 60-second visibility
timeout. **(Chosen; not in the spec.)** If staging needs them shorter, a
setting comes later, with the owner's approval.

## 6. The work

Each PR is reviewed by the lead's blind pair (keys and handshakes).

1. **`vms` (vettid-vault, al-cal):** the wire types and checks of §2.
   The service pins it in a PR of its own.
2. **The §3.4.1 base:** relay-key states and the cut-off in
   `acceptFrom`; Table A by relay key; rule C on relay links; rule U
   with binding L (RK5, RK10's order); rule T with the deferral; RK2.
   `relay.address.update` is followed instead of refused. `relay_follow`
   is still not advertised.
3. **The handshakes:** RK6, RK7 (with its per-epoch records), RK8,
   RK10, RK12.
4. **The hold:** RK14's hold, `relay_held` in the connection API, the
   `connection.held`/`connection.released` events, the 60-day end.
5. **The keep and the telling:** the `keep` kind with its caps, the pin,
   `relay.mailbox.closed`, the re-deposits and the cutoffs, the notices.
   Then `relay_follow` is advertised (RK0), and RELEASE-29 §6 and the
   README say so.

Tests use `peertest` members that rotate: a follow by update and by
reconnect, a duplicate, a relay fork, the cut-off passes, a refused
reconnect after `mailbox_unknown`, a hold re-addressed at a follow, a
telling with entries above and below `last_msg_id`, and the 60-day ends.
Each is mutation-checked.

## 7. Open questions

1. **Is "never rotates its relay key" right for a service?** If the
   service ever must (a relay change, a compromised relay key), the
   rotating side's rules apply and this document grows. Until then a
   relay-key change for the service is a new set of invitations.
2. **The application events** of §4 (`connection.held`,
   `connection.released`, `message.not_delivered`,
   `message.delivery_unconfirmed`): their names and payloads are a
   change to the service's webhook contract (README "Events"), which
   the application team should see before PR 4.
3. **Which service messages count as "member messages"** (told when
   lost) is this document's reading of §3.4.2 step 3 for a service:
   `vote.*`, `connection.authenticate.challenge` and `.withdraw`, and
   `connection.approved`.

## Changes

- **0.1.0 (2026-11-14):** first draft.
