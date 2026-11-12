# Release 29 in the service vault

**Status:** 0.1.0, draft (2026-11-12)

VAULT-MESSAGING §6.3.1 ("Lifetimes and activation on confirmation",
release 29) asks a service vault to follow its rules "on either side as
a member vault does". The rules are written for a member vault: one
that locks and unlocks, pairs devices and rotates its own identity key.
A service vault does none of that. This document states how each rule
reads for this service: where the spec leaves the choice to it, and
where a rule rests on something a service lacks. The code follows this
text. The rule IDs are those of VAULT-MESSAGING §6.3.2.

Choices are marked **(chosen; not in the spec)**. Everything else is the
spec's own rule, restated for a service.

## 1. What does not apply

- **No identity-key rotation of its own.** A service vault never
  rotates its `ik`. Every rule that its own rotation triggers is
  inert: S5 and K3 (§3.4.1), and "at its own `ik` rotation" among the
  initiator's abandonments (R29-I7). Replacing a service's `ik` means
  new invitations for every member. A stored handshake that names
  another `ik` than the service's is dropped at start with the alarm
  `outgoing_identity_changed`, as today.
- **No devices or agents.** A service vault pairs none. §6.3.1 "Devices
  and agents", "An app from before release 29" and R29-D1 to D4 do not
  apply.
- **No member-facing feed.** Where a member vault raises a feed item
  (the neutral item of a suspension, `connection.stale`), the service
  emits the matching event to its application and logs an alarm for
  its operator (section 7).

## 2. "After an unlock" is "after a start" (chosen; not in the spec)

`B`, the 32 days an initiator's pending epoch waits for confirmation,
is judged "only after the first collect after an unlock that returns
fewer than `max` messages" (§6.3.1 Lifetimes, §12.2). A service is never
locked, but its process can be down (a deploy, a replaced task, an
outage), and the confirmation may then be waiting in its mailbox.

So for a service, "an unlock" is a start of the process (`Peer.Start`).
`B` is judged for a pending epoch only once a collect since that start
has returned fewer than `MaxBatch` messages. That condition is kept in
memory, not stored: every start begins without it.

The same reading holds wherever §6.3.1 or §3.4.1 speaks of a peer being
locked: for a service, "locked" is "not running".

## 3. Reconnects outside a restore (chosen; not in the spec)

Today the service starts a reconnect only after a table restore (§6.6
"After a restore"). §6.3.1 has the initiator reconnect in more cases,
and a service that doesn't would leave the pair split (the stuck state
release 29 exists to remove, §6.3.1 "`hs.confirm` again").

The service starts a reconnect, naming its current epoch:
- when it abandons its rekey's pending epoch at `B`, or for want of a
  valid standing token (R29-I5, I6);
- when an answer of its own to a rekey is destroyed by rule J;
- when its pending epoch's `hs.fin` is answered `token_revoked`;
- when a carried-token discard leaves it with no valid standing token
  (§6.3.1 "A handshake's tokens are adopted at confirmation");
- at a start, and at `token_expired`, when its held standing token has
  expired, unless "No reconnect while carried tokens wait" holds (§7.2
  "On unlock" step 3, §8.6).

These reconnects are bounded as §3.4.1 "The reconnect bound" says:
three failed tries for one named epoch, no reconnect token, or
`quota_exceeded` make the connection `stale` with the alarm
`reconnect_failed`. One reconnect at a time per member; crossing
reconnects are settled as today (§6.6).

## 4. The restore reconnect and `B` (chosen; not in the spec)

§6.6 "After a restore" ends a restore's reconnect "not completed in" 7
days. Under release 29 a reconnect is not complete at `hs.fin`; it is
pending until confirmed. So the 7 days run from the reconnect's first
`hs.init` until the service sends its `hs.fin`. From then on it is a
pending reconnect like any other: it ends at its confirmation, or at
`B` with `stale` (R29-I5).

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
- **A duplicate `hs.fin`** that reaches the session (it opens under the
  current epoch) is acked and ignored. It never moves the confirmed
  epoch and never sets the received flag (R29-T3).

## 6. Advertising `hs_confirm` (R29-G1; chosen how)

The service advertises `hs_confirm` in the inner `features` of every
message it deposits, and in the `features` of its `profile.update`
(§10.8). It sends that `profile.update` at each activation. To every
active connection it has not yet told, it sends a new version once, at
the first start of the release that adds the capability; the version
sent is stored per connection. Nothing in §6.3.1 depends on seeing the
capability, so a member that misses it loses nothing.

## 7. Suspensions and alarms (chosen; not in the spec)

When a rule of §6.3.1 or §3.4.1 makes a member vault suspend with
`ref` = `epoch` (fork evidence by rule E, R29-R6, F1), the service
suspends the connection as it does for a rotation conflict: nothing is
sent or accepted, and its sign-ins and approvals can't be answered. It
emits `connection.suspended` with the reason `epoch`, beside
`rotation_conflict`, and logs the alarm `fork_suspected`. A member's
new connection from a new invitation replaces it, as for a rotation
conflict.

## 8. Bounds

- **Answers per member** (chosen; not in the spec, beside §3.4.1 H5):
  at most 2 open rekey answers and, as H5 says, at most 4 open
  reconnect answers per member, the oldest dropped beyond that.
- **Rekey backoff:** a failed rekey of the service's own waits 1 hour,
  doubling to 24 hours, before the next (chosen; not in the spec). It
  holds in addition to R29-I4 (no rekey while an epoch is pending).
- **Yield wait:** a reconnect of ours that yielded to a member's waits
  1 hour for that one's `hs.fin` (chosen; not in the spec), as today.

## 9. Rule E's scope

§6.3.1 Rule E reads: "In the write that establishes a rekey's or
reconnect's epoch at its verified `hs.fin`, `R` destroys every other
epoch with `I` later than the confirmed one". The member vault applies
it only at the `hs.fin` of a handshake whose `hs.init` named `R`'s
confirmed epoch while that epoch was not current (vettid-vault
`vault/handshakes.go`, at `425a5ae`). Read literally, the text would
also destroy an unconfirmed current epoch at a reconnect naming it.

The service follows the member vault's code. Whether the spec's wording
needs an erratum is for the specification's owner; this section changes
with it.

## 10. The received flag before its rules (chosen; not in the spec)

The received flag (§6.3.1, R29-F3) is read only by §3.4.1's demotion
rules ("Epochs after an `ik` link", Strict F1). The service records it
from the change that adds rule E onwards, before it implements those
rules, so that epochs established in between don't all read as never
used.

## 11. No upgrade (R29-U1; the service's own check)

§6.3.1 "No upgrade: release 29 starts clean" leaves a service vault's
own check to it, and says an operator step removes its connections from
before release 29. The service's connections on staging were made under
release 29 after that step.

- **The marker.** The service writes `messaging_release: 29` on every
  connection record it writes.
- **Records without it.** At the first start of the version that adds
  the marker, a connection record without it is taken to be a release-29
  pair made before the marker existed: its current epoch becomes its
  confirmed epoch, with the received flag clear, and the marker is
  written. One split can survive this: an `hs.fin` of the service's that
  was lost before the upgrade, under the code that made an epoch current
  at `hs.resp`. That connection needs a new invitation, the same
  accepted residual as for member vaults.
- **Answers and handshakes** stored before the upgrade complete under
  the rules of the version that reads them; none is treated as having
  named the confirmed epoch, so rule E never destroys an epoch for one.

## 12. The work

In four changes to service-vault, each reviewed independently, the
README's release-29 status paragraph shrinking with each:
1. The responder: the epoch list, the confirmed epoch, `hs.confirm`
   (section 5), "A reconnect ends R's rekey answers" (§6.3.1 R29-T2),
   and advertising `hs_confirm` (section 6).
2. The initiator: pending epochs until confirmed (R29-I1 to I7),
   crossing, rule J, `B` (section 2), the reconnects of section 3, and
   the handshakes a newer one ends that the initiator owns (R29-T2).
3. Rule E (section 9), the received flag (section 10), and a
   handshake's tokens adopted at confirmation (R29-T1) on both sides.
4. §3.4.1's `ik` rules that §6.3.1 rests on: the `rotations` of
   `identity.rotate` (K1), demotion and the held outbox (K4, K5, K7),
   seen links (K8) and K9.

## Changes

- **0.1.0 (2026-11-12):** first draft (GC #9134).
