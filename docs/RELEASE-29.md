# Release 29 in the service vault

**Status:** 0.2.0, draft (2026-11-12). Against VAULT-MESSAGING 0.89.1,
with the 0.89.2 erratum on rule E's scope (vettid.org #583).

VAULT-MESSAGING §6.3.1 ("Lifetimes and activation on confirmation",
release 29) asks a service vault to follow its rules "on either side as
a member vault does". The rules are written for a member vault: one
that locks and unlocks, pairs devices and rotates its own identity key.
A service vault does none of that. This document states how each rule
reads for this service: where the spec leaves the choice to it, and
where a rule rests on something a service lacks. The code follows this
text. Rule IDs are those of VAULT-MESSAGING §6.3.2.

Choices are marked **(chosen; not in the spec)**. Everything else is the
spec's own rule, restated for a service.

## 1. What does not apply

- **No identity-key rotation of its own.** A service vault never
  rotates its `ik`. The rules its own rotation triggers are inert: the
  rotating side's part of S5, K3 (§3.4.1), and "at its own `ik`
  rotation" among the initiator's abandonments (R29-I7). S5's other
  parts, the blocks on rekeys while a peer's handshake is open, apply.
  Replacing a service's `ik` means new invitations for every member. A
  stored handshake that names another `ik` than the service's is
  dropped at start with the alarm `outgoing_identity_changed`, as
  today; a stored pending epoch under another `ik` is abandoned the same
  way (R29-I7): the tokens its `hs.init` carried are revoked and its
  unsent `hs.fin` is dropped.
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
`B` is judged for a pending epoch only while the last collect succeeded
and returned fewer than `MaxBatch` messages. A failed collect clears the
condition, so a relay outage cannot let `B` pass with the confirmation
unread. The condition is kept in memory, not stored: every start begins
without it.

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
   token and it holds no other valid one (§8.6, 0.88.2). The answer
   ends that token only, not the connection; today the service makes
   the connection `stale`, which changes;
5. after `quota_exceeded` on its standing token, at once and also while
   its own rekey is pending (which the reconnect abandons), when the
   refresh itself is refused for the token's quota, when a deposit is
   refused for quota after the token's `exp`, or when a waiting entry
   comes due after the `exp`; before the `exp`, with no reconnect token,
   it keeps asking for a fresh token instead (§8.6, 0.88.6);
6. when an answer of its own to a rekey is destroyed by rule J and it
   holds no valid standing token;
7. when a carried-token discard leaves it with no valid standing token
   (§6.3.1 "A handshake's tokens are adopted at confirmation");
8. at a change of the member's `ik`: its own open reconnect is started
   again under the new `ik`, spending one try at most once per change
   (§3.4.1 H5);
9. after a demotion of its current epoch, and by strict F1, naming the
   newest epoch not demoted, by position (§3.4.1, K5, K7).

**Bounded** as §3.4.1 "The reconnect bound" says: the connection becomes
`stale`, with the alarm `reconnect_failed`, at the third failed try for
one named epoch, when a try's `hs.init` is refused `quota_exceeded`,
when no try can start for want of a reconnect token (not judged while
"No reconnect while carried tokens wait" holds), or when a try's pending
epoch reaches `B`. `stale` is not final (0.88.7): the outbox is kept, and
the next epoch established makes the connection active again.

**While a reconnect is open** (from its first `hs.init` until it is
confirmed or ends) the connection sends nothing but the handshake: no
messages, rekeys, token refreshes or re-mints (§6.6 "After a restore",
applied to every reconnect of the service's; §6.3.1 Initiator for the
pending part). What the application sends waits in the outbox. One
reconnect at a time per member (R29-X4); crossing reconnects are settled
as today, the service yielding (§6.6).

## 4. The restore reconnect's 7 days (chosen how)

§6.3.1's Lifetimes table gives an initiator's handshake awaiting
`hs.resp` 16 days from its `hs.init`, and 7 days for §6.6 "After a
restore". The service applies the 7 days **per try**, from that try's
`hs.init`, as the table does; a restore reconnect has at most 3 tries
(§6.6). Once the service has sent `hs.fin`, the reconnect is a pending
reconnect like any other: it ends at its confirmation, or at `B` with
`stale` (R29-I5). (Today the 7 days run from the first try to the end;
this changes.)

## 5. `hs.confirm` (R29-R1 to R3)

- **A batch is one collect** (chosen; not in the spec): "for each
  collected batch holding one" (§6.3.1 Responder) is one `Step`, at
  most `MaxBatch` messages, the service's unit of collect, write and
  ack.
- **The last one's time is stored** with the connection, in the same
  write as its outbox entry, so a restart does not reset the 12 days of
  "`hs.confirm` again".
- **At most one is queued per connection**, and `hs.confirm` is exempt
  from the per-connection outbox bound `MaxOutboxPerConn` (chosen; not
  in the spec): one dropped silently would cost up to 12 days.
- **It waits while the service's own reconnect is pending**: held in
  the outbox like everything but the handshake (§6.3.1 Initiator,
  0.88.2), although it may carry a token. Nothing is queued while the
  current epoch is demoted or the connection suspended.
- **An `hs.fin` whose answer is gone** (a duplicate, or one for an
  answer dropped or expired) that reaches the session is acked and
  ignored. No `hs.fin` ever moves the confirmed epoch or sets the
  received flag (R29-T3).

## 6. Advertising `hs_confirm` (R29-G1; chosen how)

The service advertises `hs_confirm` in the inner `features` of every
message it deposits, and in the `features` of its `profile.update`
(§10.8), sent when a connection becomes active. To every active
connection it has not yet told, it sends a new version once, at the
first start of the release that adds the capability; the version sent
is stored per connection. Nothing in §6.3.1 depends on seeing the
capability, so a member that misses it loses nothing. The service does
not advertise `relay_follow` today (it follows a member's relay-key
rotation by `relay.address.update`); that does not change here.

## 7. Suspensions and alarms (chosen; not in the spec)

When a rule makes a member vault suspend with `ref` = `epoch` (fork
evidence by rule E, R29-R6; fork by `ctx`, F1; the demotion rules K4,
K7, K9), the service suspends the connection as it does for a rotation
conflict: nothing is sent or accepted, and its sign-ins and approvals
can't be answered. It emits `connection.suspended` with the reason
`epoch`, beside `rotation_conflict`, and logs the alarm
`fork_suspected`. Where a rule refuses a message as possible fork
evidence without suspending, the service audits it with the reason
`fork_suspected`. A member's new connection from a new invitation
replaces a suspended one, as for a rotation conflict.

## 8. Bounds

- **Answers per member** (chosen; not in the spec, beside §3.4.1 H5): at
  most 2 open rekey answers and, as H5 says, at most 4 open reconnect
  answers per member, the oldest dropped beyond that, except an answer
  that is fork evidence (H5's exemption).
- **A yielded reconnect.** When the service's reconnect yields to a
  member's (§6.6), its answer to the member's is kept for `L`, 16 days,
  like any answer; no new try starts while it is open (§6.6 "After a
  restore"). Today it waits 1 hour (`YieldWait`), after which the
  member's `hs.fin` would find no answer while the member holds that
  epoch pending; that changes.
- **Rekey backoff:** a failed rekey of the service's own waits 1 hour,
  doubling to 24 hours, before the next (chosen; not in the spec). It
  holds in addition to R29-I4 (no rekey while an epoch is pending).

## 9. Rule E's scope

The service applies rule E only at the `hs.fin` of a handshake whose
`hs.init` named the service's confirmed epoch while that epoch was not
current, as the member vault does (vettid-vault `vault/handshakes.go`,
at `425a5ae`) and as VAULT-MESSAGING 0.89.2 states (vettid.org #583).
0.89.1's wording ("every other epoch with `I` later than the confirmed
one", at any establishing `hs.fin`) is wider. Read that way, a member's
ordinary reconnect naming the current epoch, established while that
epoch is not yet confirmed, would destroy the current epoch the member
had just used; the member's next message under it, with a later `ts`,
would then be taken as fork evidence and an honest pair suspended.

## 10. The received flag before its rules (chosen; not in the spec)

The received flag (§6.3.1, R29-F3) is read by §3.4.1's "Epochs after an
`ik` link", Strict F1, K9 ("Epochs abandoned while pending, at P's
`identity.rotate`") and Fork by `ctx`. The service records it from the
change that adds rule E onwards, before the change that adds the rules
that read it, so that epochs established in between have it. Epochs
established before that change have the flag clear: the demotion rules
then treat them as unused, which can only demote, never suspend (a
fail-safe residual).

## 11. No upgrade (R29-U1; the service's own check)

§6.3.1 "No upgrade: release 29 starts clean" leaves a service vault's
own check to it: there is no migration of an earlier release's epochs,
handshakes or connections, and the members connect again from fresh
invitations.

- **The marker.** From the first change below on, the service writes
  `messaging_release: 29` on every connection record it writes.
- **Records without it.** At the first start of that version, the
  service ends every connection record without the marker: it sends
  the member `connection.removed` (best effort), revokes every token it
  issued for the connection, audits `connection_pre29_ended`, emits
  `connection.removed` to the application so that it can tell the
  member and invite them again, and logs one alarm with the count. Its
  stored handshakes end with it.
- **On staging,** where every connection would be ended this way, the
  deploy of that version needs the owner's go of its own.

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

## 13. The work

In four changes to service-vault, each reviewed independently; the
README's release-29 status paragraph shrinks with each:

1. **The responder.** The epoch list and the confirmed epoch; the
   confirmation hook (before the rate limit, the `ts` window and dedupe,
   never for an `hs.fin`); `hs.confirm` (section 5); the 48 and 16 days
   a responder keeps keys; "A reconnect ends R's rekey answers"; a
   rekey `hs.init` answered once (a `th1` mark); advertising `hs_confirm`
   (section 6); the marker and the end of records without it
   (section 11).
2. **The initiator.** Pending epochs until confirmed and every
   abandonment; `B` (section 2); crossings; rule J; the reconnects of
   section 3 with their bound, and nothing sent while one is open; the
   7 days per try (section 4); the yielded answer kept for `L`
   (section 8); `token_revoked` ending one token (section 3, item 4);
   the handshakes a newer one ends that the initiator owns.
3. **Forks and tokens.** Rule E (section 9) and its fork evidence; a
   handshake naming the confirmed epoch; fork by `ctx`; the received
   flag (section 10); a handshake's tokens adopted at confirmation, on
   both sides, with the refresh's revocations (section 12); a stale
   reconnect answer ending at a later message.
4. **`ik` links.** The `rotations` of `identity.rotate`; demotion by
   position and the held outbox; strict F1; seen links; epochs
   abandoned while pending at the member's `identity.rotate`.

| Rule | Change | Rule | Change |
|---|---|---|---|
| G1 | 1 | R6 | 3 |
| G2 | n/a (a device's) | X1 crossing | 2 |
| U1 | 1 | X2 a verified `hs.fin` first | 2 |
| L1 | 1 (the responder's keys), 2 (`B`, the initiator's 16 days) | X3 rule J | 2 |
| I1 to I7 | 2 | X4 one reconnect at a time | 2 |
| R1 | done (service-vault #147), its abandonment part 2 | X5 the reconnect's `ctx` | 2 (while a reconnect is pending), 3 (the rest) |
| R2, R3 | 1 | X6 a sealed-mode rekey refused | done (before release 29) |
| R4 | 3 | K1 | 4 |
| R5 rule E | 3 | K2 a pending epoch at a link | 2 |
| F1 | 3 | K3 | n/a (section 1) |
| F3 | 3 | K4, K5, K7 | 4 |
| T1 | 3 | K6 the reconnect bound | 2 |
| T2 items 1 to 3 | 2 | K8 | 4 |
| T2 item 4 | 1 | K9 | 4 |
| T2 item 5 (0.88.9) | 3 | D1 to D4 | n/a (section 1) |
| T3 `th1` mark; `hs.fin` ignored | 1 | | |

## Changes

- **0.2.0 (2026-11-12):** pinned to VAULT-MESSAGING 0.89.1 and the
  0.89.2 erratum. §11 ends records without the marker instead of
  migrating them. §3's list is complete, and nothing is sent while a
  reconnect is open. §8 keeps a yielded answer for `L`. §12 states the
  refresh's revocations. A table assigns every rule to a change. Smaller
  corrections throughout.
- **0.1.0 (2026-11-12):** first draft (GC #9134).
