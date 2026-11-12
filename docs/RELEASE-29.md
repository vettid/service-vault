# Release 29 in the service vault

**Status:** 0.5.0, draft (2026-11-12). Against VAULT-MESSAGING 0.89.2, and
0.90.0 for `relay_follow` (section 6).

VAULT-MESSAGING §6.3.1 ("Lifetimes and activation on confirmation",
release 29) asks a service vault to follow its rules "on either side as
a member vault does". The rules are written for a member vault: one
that locks and unlocks, pairs devices and rotates its own identity key.
A service vault does none of that. This document states how each rule
reads for this service: where the spec leaves the choice to it, and
where a rule rests on something a service lacks. The code follows this
text. Rule IDs are those of VAULT-MESSAGING §6.3.2.

Choices are marked **(chosen; not in the spec)**. Everything else is the
spec's own rule, restated for a service. The service runs as one task
(`desiredCount: 1`), and within it one lock (the peer's) covers the
drain, key changes and every state change; several of the rules below
assume one process holds a connection's state at a time.

## 1. What does not apply

- **No identity-key rotation of its own.** A service vault never
  rotates its `ik`. The rules its own rotation triggers are inert: the
  rotating side's part of S5, K3 (§3.4.1), and "at its own `ik`
  rotation" among the initiator's abandonments (R29-I7). S5's three
  rekey blocks apply as written: the service starts no rekey with a
  member while one of its answers to that member awaits `hs.fin`, while
  its own epoch with the member is pending, or while its own rekey
  `hs.init` awaits `hs.resp`. Replacing a service's `ik` means new
  invitations for every member. A stored handshake that names another
  `ik` than the service's is dropped at start with the alarm
  `outgoing_identity_changed`, as today; a stored pending epoch under
  another `ik` is abandoned the same way (R29-I7): the tokens its
  `hs.init` carried are revoked and its unsent `hs.fin` is dropped.
- **No devices or agents.** A service vault pairs none. §6.3.1 "Devices
  and agents", "An app from before release 29", R29-D1 to D4 and G2's
  device part do not apply.
- **No member-facing feed.** Where a member vault raises a feed item
  (the neutral item of a suspension, `connection.stale`), the service
  emits the matching event to its application and logs an alarm for its
  operator (section 7).

## 2. "After an unlock" is "after a start" (chosen; not in the spec)

`B`, the 32 days an initiator's pending epoch waits for confirmation,
is judged "only after the first collect after an unlock that returns
fewer than `max` messages" (§6.3.1 Lifetimes, §12.2). A service is never
locked, but its process can be down (a deploy, a replaced task, an
outage), and the confirmation may then be waiting in its mailbox.

So for a service, "an unlock" is a start of the process (`Peer.Start`).
A latch, kept in memory and clear at every start, is set by a collect
that succeeds with fewer than `MaxBatch` messages, once that batch has
been processed and written; only a failed collect clears it. `B` is
judged only while the latch is set. A busy service still reaches it at
its next short collect, and a relay outage cannot let `B` pass with the
confirmation unread.

The same reading holds wherever §6.3.1 or §3.4.1 speaks of a peer being
locked: for a service, "locked" is "not running". Handshakes and
reconnects open at a restart stay open (§6.6 "After a restore", 0.72.1):
the stored initiator state is kept and no new try is spent.

## 3. Reconnects

The spec requires a connection's vault to reconnect in more cases than
after a table restore, the only case the service handles today; a
service that doesn't would leave the pair split, the stuck state
release 29 exists to remove. The service starts a reconnect, naming its
current epoch unless stated:

1. when it abandons its rekey's pending epoch at `B` (R29-I5);
2. for want of a valid standing token: abandoning a pending rekey
   (R29-I6), and at a start or a `token_expired` when its held standing
   token has expired (§7.2 "On unlock" step 3, §8.6), unless "No
   reconnect while carried tokens wait" holds (§6.3.1);
3. when its pending epoch's `hs.fin` is answered `token_revoked`
   (§6.3.1 "A carried token refused");
4. when `token_revoked` answers a deposit under its **held** standing
   token and it holds no other valid one (§8.6, 0.88.2), unless "No
   reconnect while carried tokens wait" holds. The answer ends that
   token only, not the connection: the refused entry and the others to
   the member wait in the outbox for a valid standing token. (Before
   the second change the service made the connection `stale` and
   dropped its other entries.) A reconnect's own `hs.init`
   answered `token_revoked` is a failed try at once, as §8.6 says (it can
   never be answered); a carried token's refusal is not a try at all;
5. after `quota_exceeded` on its standing token, at once and also while
   its own rekey is pending (which the reconnect abandons), when the
   refresh itself is refused for the token's quota, when a deposit is
   refused for quota after the token's `exp`, or when a waiting entry
   comes due after the `exp`; before the `exp`, with no reconnect token,
   it keeps asking for a fresh token instead (§8.6, 0.88.6). The
   exception for carried tokens applies as in item 4;
6. when an answer of its own to a rekey is destroyed by rule J and it
   holds no valid standing token;
7. when a carried-token discard leaves it with no valid standing token
   (§6.3.1 "A handshake's tokens are adopted at confirmation");
8. at a change of the member's `ik`, H5 restarts the service's own open
   rekeys and reconnects under the new `ik`. A restarted reconnect spends
   one of the reconnect token's deposits, not a failed try, at most once
   per change of the member's `ik`; the change it was spent for is
   stored, so a restart of the process does not spend another. **(Chosen;
   not in the spec)** a `relay.address.update` from the member while a
   try's `hs.init` awaits its `hs.resp` starts that try again the same
   way, uncounted: the `hs.init` went to the old mailbox;
9. after a demotion of its current epoch by position, naming the newest
   epoch that has been current and is neither demoted nor destroyed
   (with none, the connection becomes `stale`); after strict F1, naming
   the epoch F1 names (E). Either starts only when the service has no
   current epoch left and no reconnect of its own open or pending
   (§3.4.1, K5, K7).

**Bounded** as §3.4.1 "The reconnect bound" says: the connection becomes
`stale`, with the alarm `reconnect_failed`, at the third failed try for
one named epoch, when a try's `hs.init` is refused `quota_exceeded`,
when no try can start for want of a reconnect token (not judged while
"No reconnect while carried tokens wait" holds), or when a try's pending
epoch reaches `B`. A try counts as failed when it expires unanswered,
or when its `hs.init` is answered `token_revoked` (item 4). §3.4.1 says
a refused try counts only if it then expires unanswered, and §8.6 that
this refusal is a failed try; the service follows §8.6, and the
difference is flagged for an erratum. A new try after a pending
epoch's `hs.fin` is refused `token_revoked` is not a failed try
(§6.3.1); repeated, it is bounded by the reconnect token's 4 deposits,
whose `quota_exceeded` makes the connection `stale`. `stale` is not final (0.88.7): the outbox is kept, and the
next epoch established makes the connection active again.

**While a reconnect is open** (from its first `hs.init` until it is
confirmed or ends) the connection sends nothing but the handshake: no
messages, rekeys, token refreshes or re-mints **(chosen; not in the
spec** beyond §6.6 "After a restore" for a restore's reconnect and
§6.3.1 Initiator for a pending one). What the application sends waits
in the outbox. A member's rekey `hs.init` that arrives while a reconnect
of the service's is open is acked and dropped, audited
`rekey_while_reconnecting`, as today: the reconnect settles the session,
and the member's rekey stays open on its side for its lifetime (16 days)
unless the reconnect ends it first. One reconnect at a time per member (R29-X4); crossing
reconnects are settled as today, the service yielding (§6.6).

## 4. The restore reconnect's 7 days (chosen how)

§6.3.1's Lifetimes table gives an initiator's handshake awaiting
`hs.resp` 16 days from its `hs.init`, and 7 days for §6.6 "After a
restore". The service applies the 7 days **per try**, from that try's
`hs.init`, as the table does; a restore reconnect has at most 3 tries
(§6.6). Once the service has sent `hs.fin`, the reconnect is a pending
reconnect like any other: it ends at its confirmation, or at `B` with
`stale` (R29-I5). (Before the second change the 7 days ran from the first try to the
end.)

## 5. `hs.confirm` (R29-R1 to R3)

- **A batch is one collect** (chosen; not in the spec): "for each
  collected batch holding one" (§6.3.1 Responder) is one `Step`, at
  most `MaxBatch` messages, the service's unit of collect, write and
  ack.
- **The last one's time is stored** with the connection, in the same
  write as its outbox entry, so a restart does not reset the 12 days of
  "`hs.confirm` again".
- **A waiting one older than 2 days is replaced** by a fresh one
  (chosen; not in the spec): it keeps its `ts` while it waits, and the
  member would drop it past its 16-day window.
- **At most one is queued per connection.** `hs.confirm` and the
  handshake's own messages are exempt from the per-connection outbox
  bound `MaxOutboxPerConn` (chosen; not in the spec): one dropped
  silently would cost up to 12 days.
- **It waits while a reconnect of the service's is open** (section 3),
  held in the outbox like everything but the handshake, although it may
  carry a token. Nothing is queued while the current epoch is demoted or
  the connection suspended.
- **An `hs.fin` whose answer is gone** (a duplicate, or one for an
  answer dropped or expired) is acked and ignored: audited
  `drop.unknown_kid` when it opens under no epoch, ignored without audit
  when it opens under the current one. No `hs.fin` ever moves the
  confirmed epoch or sets the received flag (R29-T3).

## 6. Advertising `hs_confirm` (R29-G1; chosen how)

The service advertises `hs_confirm` in the inner `features` of every
message it deposits, and in the `features` of its `profile.update`
(§10.8), sent when a connection becomes active. It does not advertise
`relay_follow`: VAULT-MESSAGING 0.90.0 (vettid.org #584) lets a vault
advertise it only once it implements both §3.4.1 and §3.4.2, and the
service's §3.4.2 is later work (GC #9442). The first change advertised
it; the second stops. The `profile.update` body is the one §10.8 gives: a
`version` (stored per connection: 1 at activation, one more at each
change of the profile, unchanged when an epoch is activated again; the
service's profile cannot change yet, so it stays 1), the invitation's
profile names, the service's `ik`, `items: []`, and `features`
(`["hs_confirm"]`).
Nothing in §6.3.1 depends on seeing `hs_confirm`, so a member that
misses it loses nothing.

## 7. Suspensions and alarms (chosen; not in the spec)

When a rule makes a member vault suspend with `ref` = `epoch` (fork
evidence by rule E, R29-R6; fork by `ctx`, F1; the demotion rules K4,
K7, K9), the service suspends the connection as it does for a rotation
conflict: nothing is sent or accepted, and its sign-ins and approvals
can't be answered. It emits `connection.suspended` with the reason
`epoch`, beside `rotation_conflict`, and logs the alarm
`fork_suspected`. A demotion that does not suspend, an epoch ended at
the member's `identity.rotate` (K9), and a message refused as possible
fork evidence without a suspension are audited, the last with the
reason `fork_suspected`. A member's new connection from a new invitation
replaces a suspended one, as for a rotation conflict.

## 8. Bounds

- **Answers per member** (chosen; not in the spec, beside §3.4.1 H5): at
  most 2 open rekey answers, the one whose `hs.init` has the oldest inner
  `ts` dropped beyond that, and, as H5 says, at most 4 open reconnect
  answers per member, the oldest dropped beyond that, except an answer
  that is fork evidence (H5's exemption).
- **A yielded reconnect.** When the service's reconnect yields to a
  member's (§6.6), its answer to the member's is kept for `L`, 16 days,
  like any answer, and no new try starts while it is open (§6.6 "After a
  restore"). When it expires unanswered, a new try starts; a try
  abandoned before it expires is not counted. (Before the second change it waited 1 hour, after which the member's
  `hs.fin` found no answer.)
- **Rekey backoff:** a failed rekey of the service's own waits 1 hour,
  doubling to 24 hours, before the next (chosen; not in the spec). It
  holds in addition to S5's three blocks (section 1).

## 9. Rule E's scope

The service applies rule E only at the `hs.fin` of a handshake whose
`hs.init` named the service's confirmed epoch while that epoch was not
current, judged when the `hs.init` is answered, as the member vault does
(vettid-vault `vault/handshakes.go`, at `425a5ae`) and as VAULT-MESSAGING
0.89.2 states. 0.89.1's wording ("every other epoch with `I` later than
the confirmed one", at any establishing `hs.fin`) was wider. Read that
way, a member that abandoned a pending epoch and came back to the
current one, then reconnected naming it while it was not yet confirmed,
would have that current epoch destroyed at the reconnect's `hs.fin`; its
next message under it, with a later `ts`, would be taken as fork
evidence and an honest pair suspended. The residual 0.89.2 accepts for
this scope (§3.4.1 Residuals, "A copy using an unconfirmed epoch a
reconnect passed over") is accepted for the service too.

## 10. The received flag (R29-F3)

The received flag (§6.3.1) is read by §3.4.1's "Epochs after an `ik`
link", Strict F1, K9 ("Epochs abandoned while pending, at P's
`identity.rotate`") and Fork by `ctx`. The service records it from the
first change on, before the changes that add the rules that read it
(chosen; not in the spec), so every epoch established under the release
has it.

## 11. No upgrade (R29-U1; the service's own check)

§6.3.1 "No upgrade: release 29 starts clean" leaves a service vault's
own check to it: there is no migration of an earlier release's epochs,
handshakes or connections, and the members connect again from fresh
invitations.

- **The marker.** From the fourth change on, when the rules are
  complete, the service writes `messaging_release: 29` on every
  connection record it writes.
- **What it vouches for.** The marker is on the connection record; it
  vouches for the connection's other records too (its handshakes,
  tokens and outbox entries, stored as separate kinds).
- **Records without it.** At every start, right after the state is
  loaded and before any reconnect (a restore's included), housekeeping,
  drain or any other write, the service ends every
  connection record that lacks the marker or holds a value below 29: it
  sends the member `connection.removed` (best effort), revokes every
  token it issued for the connection (its relay registrations), audits
  `connection_pre29_ended`, emits `connection.removed` to the
  application with the reason `pre29` (so that the application can tell
  it from an operator's removal and invite the member again), and logs
  one alarm with the count. Its stored handshakes and tokens end with
  it, and its waiting messages end audited `drop.undelivered_removed`. Running it at every start covers a point-in-time
  restore of older records.
- **A rollback** to a version before the fourth change is an operator
  step that ends every connection first (runbook): code from before the
  marker could otherwise write records under a connection that still
  carries it. The deployment's circuit breaker can roll a failed deploy
  back by itself, so the fourth change adds the runbook step: after a
  `deploy_failed` rollback across the fourth change, end every
  connection before deploying forward.
- **Invitations** are not ended: one claimed under this version makes a
  connection under its rules, which carries the marker.
- **On staging,** where every connection is ended this way, the deploy
  of that version needs the owner's go of its own, and the runbook says
  to re-invite the staging test members after it.

(Migrating such records as release-29 pairs was considered and
rejected: it would keep splits the spec's re-enrolment removes, such as
a responder-activated epoch whose `hs.confirm` expired at the relay,
which a migration would take as confirmed and so never confirm again.)

## 12. Revocations at a refresh (R29-T1)

After `quota_exceeded`, a member asks for a fresh standing token, and
the service answers with one. Today the service also revokes every
standing token it issued to that member. Under §6.3.1 "Revocation by
the issuer" the refresh never revokes: a token that a still-open
handshake carried; the standing token of the newest token-carrying
handshake with the member; the newest standing token the service
re-minted at a confirmation ("The prompt to adopt"); or any token newer
than the one the refresh was deposited under. The others it may still
revoke.

## 13. Waiting messages: re-sealed, re-stamped, or not delivered (§8.3)

Today an outbox entry is sealed once, when it is queued. One that waits
long (for a token, behind an open reconnect, through a quota wait) is
deposited under an epoch the member may have dropped (`unknown_kid`), or
with a `ts` past 16 days (`stale_or_future`); the relay accepts it and
the member drops it, unseen by the service. The service follows §8.3
("Re-sealed at a key change", "Not delivered", "At deposit") for its
durable messages to a connection; handshake messages, `hs.confirm` and
best-effort notices (`connection.removed`) are not covered.

- **Tried.** An entry is *tried* once an attempt to deposit it may have
  reached the relay: a `201`, a `5xx`, no answer, or `replay_detected`
  (an earlier copy reached the relay). The mark is stored with the
  entry. A deposit is one client attempt: the relay client's own
  retries are off for deposits, so that the mark covers every copy that
  can exist. A service has no clean end (§8.3 "A clean end": it is never
  locked), so **at every start every waiting session-mode deposit is
  marked tried**: a write that would have stored the mark after an
  accepted deposit may have been lost. Every deploy and every replaced
  task is such an end, so a message that waited across one is noted late
  rather than sealed again with a fresh `ts` (a clean end at `SIGTERM`
  would avoid that; it is not built).
- **At a key change.** Just before the current epoch is replaced (a
  responder's activation, and the initiator's confirmation of a pending
  epoch), every durable entry still waiting under it is sealed again
  under the new epoch, in its place, with the same inner `id`: with a
  fresh `ts` if untried, keeping its `ts` if tried (so that the member's
  16-day `ts` window ends it no later than its inner-`id` dedupe forgets
  the first copy). A waiting `hs.confirm` for the replaced epoch is
  dropped (the new epoch gets its own). An ephemeral entry ends
  silently. The re-sealed entries are written before any is deposited,
  with the activation, in one write.
- **At deposit.** Before each deposit of a waiting durable entry under
  the current epoch: an untried one whose `ts` is older than 2 days is
  sealed again with a fresh `ts` and a new `seq` (§8.4), written before
  it goes, the member's later deposits waiting behind it in order; one
  that cannot be sealed again goes as it is while within 16 days, and
  ends `drop.held_unsealable` otherwise. A tried one older than 16 days
  is not delivered (case 2); a tried one within 16 days goes as it is,
  noted once in the service's log (`unconfirmed_late`) when older than 2
  days.
- **Told to whom** (chosen; not in the spec): the service audits and
  logs these; the application is not told. A member vault tells its
  member (`message.delivery_unconfirmed`); the service has no member to
  tell, and its application learns of a failed delivery the way it does
  today, from the missing answer.
- **Not delivered**, each with its own audit entry (`ref` the inner
  `id`), never silently (§8.3 cases):
  1. an entry whose `exp` passed while it waited: `drop.held_expired`;
  2. a tried entry past the 16-day window: `drop.undelivered_window`;
  3. one that cannot be sealed under the new epoch: `drop.held_unsealable`;
  4. the connection is removed or replaced: `drop.undelivered_removed`;
  5. a deposit is answered `mailbox_unknown`: `drop.undelivered_mailbox_unknown`;
  7. the connection is suspended on fork evidence: `drop.undelivered_suspended`;
  8. the relay refuses the deposit with a `4xx` other than `429` and
     the codes §8.6's table handles (`token_expired`, `token_revoked`,
     `quota_exceeded`, `token_used`, `mailbox_unknown`):
     `drop.undelivered_refused`. `timestamp_stale` and `replay_detected`
     are about the attempt, not the message: retried with the backoff,
     never ended; an entry refused `timestamp_stale` a third time is
     logged once (`relay_clock_stale`), so that a stuck clock shows.

  (Case 6, a `stale` connection that can no longer come back, is
  proposed in §8.3 and not built here yet. `drop.undelivered_unreadable`,
  an entry under an epoch whose send key is gone, does not arise: every
  key change re-seals what waits under the epoch it replaces, so nothing
  waits under an older one; the records from before this release are
  ended (section 11).)
- **Held after a demotion** (§3.4.1, the fourth change): a durable
  message made while the current epoch is demoted waits unsealed in its
  place and is sealed when an epoch is current again. So does one
  already sealed under the demoted epoch and not yet deposited: it goes
  back to held; a tried one keeps its `ts`; one whose `exp` passes ends
  `drop.held_expired`, and one that cannot be sealed ends
  `drop.held_unsealable`.

## 14. The work

In four changes to service-vault, each reviewed independently. They
are merged in order and **deployed to staging together, after the
fourth**: between changes the rules are partial (for example, a
handshake naming the confirmed epoch is accepted only from the third
change on, until then only one naming the current epoch is; the fork
rules come with the third and fourth), so no deploy runs them
separately. The README's release-29 status paragraph shrinks with each.

1. **The responder.** The epoch list and the confirmed epoch; the
   confirmation hook (before the rate limit, the `ts` window and dedupe,
   never for an `hs.fin`); the received flag (section 10); `hs.confirm`
   (section 5); the 48 and 16 days a responder keeps keys; "A reconnect
   ends R's rekey answers"; a rekey `hs.init` answered once (a `th1`
   mark); advertising `hs_confirm` (section 6; it also advertised
   `relay_follow`, which the second change stops); the
   tried mark, re-sealing at the responder's activation, the check at
   deposit, and the not-delivered cases that need no other change
   (section 13).
2. **The initiator.** Pending epochs until confirmed and every
   abandonment; `B` (section 2); crossings; rule J; the reconnects of
   section 3 that need no carried tokens (items 1, 2 without the
   exception, 4 without it, 5, 6, 8) with their bound, and nothing sent
   while one is open; the 7 days per try (section 4); the yielded answer
   kept for `L` (section 8); `token_revoked` ending one token; the
   handshakes a newer one ends that the initiator owns; re-sealing at the
   initiator's confirmation (section 13, with the tried mark of change
   1); `relay_follow` no longer advertised (section 6). The tokens of the
   service's own reconnect's `hs.resp` are kept with its pending epoch,
   its `hs.fin` going on the carried standing token, and adopted at its
   confirmation (§6.3.1), so that a new try after an abandonment goes on
   the held reconnect token; the rest of carried tokens is the third
   change's. A pending epoch
   abandoned by a link (K2) is abandoned here; its demotion from the
   start, which refuses messages under it, comes with the fourth.
3. **Forks and tokens.** Rule E (section 9) and its fork evidence; a
   handshake naming the confirmed epoch; fork by `ctx`; a handshake's
   tokens adopted at confirmation, on both sides, with the refresh's
   revocations (section 12) and the reconnects that rest on carried
   tokens (section 3, items 3 and 7, and the exceptions in items 2, 4
   and 5); a stale reconnect answer ending at a later message.
4. **`ik` links and the marker.** The `rotations` of `identity.rotate`;
   demotion by position and the held outbox; strict F1 and the
   reconnects of section 3 item 9; seen links; epochs abandoned while
   pending at the member's `identity.rotate`; the links of a refused
   reconnect still applied (X4's second half); messages held after a
   demotion (section 13); the marker and the end of records without it
   (section 11).

| Rule | Change | Rule | Change |
|---|---|---|---|
| G1 | 1 | R6 | 3 |
| G2 | n/a (a device's) | X1 crossing | 2 |
| U1 | 4 | X2 a verified `hs.fin` first | 2 |
| L1 | 1 (the responder's keys), 2 (`B`, the initiator's 16 days) | X3 rule J | 2 |
| I1 to I7 | 2 | X4 one reconnect at a time | 2; a refused reconnect's links 4 |
| R1 | done (service-vault #147), its abandonment part 2 | X5 the reconnect's `ctx` | 2 (while a reconnect is pending), 3 (the rest) |
| R2, R3 | 1 | X6 a sealed-mode rekey refused | done (before release 29) |
| R4 | 3 | K1 | 4 |
| R5 rule E | 3 | K2 a pending epoch at a link | 2 |
| F1 | 3 | K3 | n/a (section 1) |
| F3 | 1 | K4, K5, K7 | 4 |
| T1 | 3 | K6 the reconnect bound | 2 |
| T2 items 1 to 3 | 2 | K8 | 4 |
| T2 item 4 | 1 | K9 | 4 |
| T2 item 5 (0.88.9) | 3 | D1 to D4 | n/a (section 1) |
| T3 `th1` mark; `hs.fin` ignored | 1 | | |

## Changes

- **0.5.0 (2026-11-12):** §6, `relay_follow` is not advertised
  (VAULT-MESSAGING 0.90.0); §14, the service's own reconnect adopts its
  carried tokens at confirmation in the second change; §3 item 8, a
  `relay.address.update` restarts
  an open try uncounted (chosen); §14, K2's demotion comes with the
  fourth change; §3, §4 and §8 describe the second change as done.
- **0.4.2 (2026-11-12):** §5, a waiting `hs.confirm` older than 2 days
  is replaced (chosen); §6, `version` stays 1 while the profile cannot
  change.
- **0.4.1 (2026-11-12):** the runbook step for a rollback by the
  circuit breaker (change 4); case 8's codes; entries wait at a
  `token_revoked` on a held token; held after a demotion covers sealed
  entries; an untried entry that cannot be re-sealed; who is told;
  `relay_clock_stale`; the stored `version`; unclean ends; one lock.
- **0.4.0 (2026-11-12):** §13 restated as §8.3: the stored tried mark
  (one client attempt per deposit, every waiting deposit tried at each
  start), the check at deposit, and the not-delivered cases. §11: what
  the marker vouches for, when it runs, a rollback as a runbook step,
  invitations. §3: a `token_revoked` try fails at once (flagged), and a
  member's rekey during our open reconnect. §6's `version`; §9's
  accepted residual.
- **0.3.0 (2026-11-12):** pinned to VAULT-MESSAGING 0.89.2. §13, new:
  re-sealing at a key change. The marker moves to change 4, and §11
  runs at every start before any reconnect, with a `pre29` reason. The
  received flag is recorded from change 1. The changes are deployed to
  staging together. §3 marks "nothing sent while open" as chosen, says
  what H5's restart spends, adds the carried-token exceptions and
  restates item 9; the carried-token reconnects move to change 3. §2's
  latch; §6's body and `relay_follow`; §8's oldest answer by `ts` and
  the yielded answer's expiry; S5's three rekey blocks.
- **0.2.0 (2026-11-12):** pinned to VAULT-MESSAGING 0.89.1 and the
  0.89.2 erratum. §11 ends records without the marker instead of
  migrating them. §3's list is complete, and nothing is sent while a
  reconnect is open. §8 keeps a yielded answer for `L`. §12 states the
  refresh's revocations. A table assigns every rule to a change. Smaller
  corrections throughout.
- **0.1.0 (2026-11-12):** first draft (GC #9134).
