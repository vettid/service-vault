package peer

import (
	"bytes"
	"encoding/hex"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Reconnecting after a restore (VAULT-MESSAGING §6.6 "After a restore",
// 0.72.0). A restored table puts the service's sessions back to older
// epochs than the members' vaults hold, so its messages and theirs no
// longer open. At the first start after the restore (the marker) the
// service reconnects every active or stale connection, naming its last
// epoch; a member's vault accepts that older epoch from its history of a
// service connection's epochs. The service itself keeps no history: when
// a member reconnects, ctx must name its last epoch (handshake.go). It
// never rotates its identity, so its rotations are always empty.

// reconnectKey is the dedupe key (kindInner) of a reconnect hs.init we
// answered, by its th1: a replay is refused for the durable ts window of
// §8.4 (DedupeRetention, plus the clock skew hs.init may have ahead).
func reconnectKey(th1 [32]byte) string { return "reconnect|" + hex.EncodeToString(th1[:]) }

// MaxReconnectTries bounds the reconnects started for one restore, over
// every start (the count is stored): each spends one of the 4 messages of
// the member's reconnect token (§6.6).
const MaxReconnectTries = 3

// ReconnectTimeout is how long each try of a restore's reconnect waits
// for its hs.resp (§6.3.1 Lifetimes, §6.6 "After a restore": 7 days, per
// try, RELEASE-29 §4); another reconnect's try waits HandshakeTTL. Once
// its hs.fin is sent, B governs (initiator.go).
const ReconnectTimeout = 7 * 24 * time.Hour

// ReconnectSlowAfter is when an unanswered reconnect raises
// reconnect_slow, once: the member's vault may be locked, and answers
// when it is unlocked (chosen; not in the spec).
const ReconnectSlowAfter = 24 * time.Hour

// reconnectAll starts a reconnect on every active or stale connection
// and returns how many started. One that cannot start (no usable
// reconnect token) fails at once.
func (p *Peer) reconnectAll(now time.Time) int {
	n := 0
	for _, c := range p.conns {
		// Per restore: counters that came back with the backup (taken
		// while an earlier reconnect was open) start again.
		c.clearReconnect()
		c.ReconnectRestore = true
		if p.startReconnect(c, now) {
			n++
		} else if c.State == StateActive || c.State == StateStale {
			c.Reconnecting = true // so that reconnectFailed ends it
			p.reconnectFailed(c)
		}
	}
	return n
}

// resumeReconnects runs at a start without a restore (§6.6, 0.72.1): a
// reconnect still open keeps its stored initiator, and an hs.init whose
// deposit was not confirmed is deposited again from the stored outbox,
// with the same bytes; no try is used. Nor does one that yielded to a
// member's and awaits its hs.fin start anything. A new hs.init (one try)
// goes out only when the stored state was lost.
func (p *Peer) resumeReconnects(now time.Time) {
	for _, c := range p.conns {
		if c.Reconnecting {
			p.reconnectIfIdle(c, now)
		}
	}
}

// reconnectOpen reports whether any part of a connection's reconnect is
// still open: our hs.init awaiting its hs.resp, or a member's reconnect
// awaiting its hs.fin.
func (p *Peer) reconnectOpen(c *Connection) bool {
	for _, og := range p.outgoing {
		if og.ConnID == c.ID && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
			return true
		}
	}
	for _, aw := range p.awaiting {
		if aw.ConnID == c.ID && aw.Reconnect != nil {
			return true
		}
	}
	return c.pendingReconnect()
}

// reconnectIfIdle starts a new try of an open reconnect when nothing of
// it is open any more (§6.6, 0.72.1: never while a member's hs.fin is
// awaited, and never over our own hs.init in flight).
func (p *Peer) reconnectIfIdle(c *Connection, now time.Time) {
	if c.Reconnecting && c.State != StateSuspended && !p.reconnectOpen(c) {
		p.retryReconnect(c, now)
	}
}

// retryReconnect starts a new try of an open reconnect, or ends it.
func (p *Peer) retryReconnect(c *Connection, now time.Time) {
	if !p.startReconnect(c, now) {
		c.Reconnecting = true // startReconnect cleared it
		p.reconnectFailed(c)
	}
}

// checkReconnect (housekeeping) raises reconnect_slow after a day, and
// starts the next try of an open reconnect of which nothing is open any
// more. Each try ends at its own expiry (housekeeping), a pending one at
// B (tickPending).
func (p *Peer) checkReconnect(c *Connection, now time.Time) {
	if now.Sub(c.ReconnectSince) >= ReconnectSlowAfter && !c.ReconnectSlow {
		c.ReconnectSlow = true
		p.markDirty(kindConn, c.ID)
		p.log().Error("reconnect unanswered for a day: the member's vault may be locked", "alarm", "reconnect_slow", "connection_id", c.ID)
	}
	p.reconnectIfIdle(c, now)
}

// reconnectFailed ends a reconnect that cannot complete: the connection
// becomes stale (§6.6), and the alarm tells the operator the member must
// connect again from a new invitation (README "Restoring the table").
func (p *Peer) reconnectFailed(c *Connection) {
	if !c.Reconnecting {
		return
	}
	c.clearReconnect()
	p.abandonPending(c, "stale", false, p.now()) // a pending epoch ends with the reconnect
	if c.State == StateSuspended {
		// Ended by the suspension, not failed: no reconnect_failed.
		p.markDirty(kindConn, c.ID)
		return
	}
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID && e.Token != "" && e.Token == c.Reconnect.Token })
	if c.State == StateActive {
		c.State = StateStale
		p.audit("peer_stale", c.ID)
	}
	p.markDirty(kindConn, c.ID)
	p.log().Error("reconnect failed: the member must connect again", "alarm", "reconnect_failed", "connection_id", c.ID)
}

// startReconnect sends a reconnect hs.init to the member's mailbox on the
// reconnect token the member's vault issued us (§6.6): sealed to its
// static key, naming our last epoch, with fresh standing and reconnect
// tokens. A rekey of ours in flight is dropped: it travels in an epoch the
// member may no longer hold.
func (p *Peer) startReconnect(c *Connection, now time.Time) bool {
	if c.State != StateActive && c.State != StateStale || len(c.LastEpochID) == 0 ||
		c.Reconnect.Token == "" || !now.Before(c.Reconnect.Exp) || c.ReconnectTries >= MaxReconnectTries {
		p.log().Warn("reconnect not possible", "connection_id", c.ID, "state", c.State, "tries", c.ReconnectTries)
		return false
	}
	kem, err := suite.ParsePublicKey(c.Peer.KEM)
	if err != nil {
		return false
	}
	c.Reconnecting = false // a try replaced is not a failure
	// A reconnect names the current epoch, never a pending one (§6.6): a
	// pending epoch is abandoned, and so are our rekeys in flight.
	p.abandonPending(c, "reconnect", false, now)
	p.dropConnOutgoing(c)
	// An earlier try's hs.init is replaced (§6.6). What else waits stays:
	// nothing in the session goes while the reconnect is open, and it is
	// sealed again under the reconnect's epoch at its confirmation (§8.3).
	p.dropOutbox(func(e *outboxEntry) bool {
		return e.ConnID == c.ID && e.Op == opDeposit && e.Token != "" && e.Token == c.Reconnect.Token
	})
	st, rt, jtis, err := p.mintReconnectPair(c.ID, &c.Peer, now)
	if err != nil {
		p.log().Warn("reconnect: mint tokens", "connection_id", c.ID, "err", errCode(err))
		return false
	}
	var eid [suite.EpochIDSize]byte
	copy(eid[:], c.LastEpochID)
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(eid),
		Identity: p.cfg.Keys.IK, StaticKEM: p.cfg.Keys.KEM.Public(), Relay: p.ownAddr(),
		Token: st, ReconnectToken: rt,
		ResponderIK: c.Peer.IK, KnownResponderChain: chainOf(c), ResponderEK: kem, ResponderRelayKey: c.Peer.Relay.PK,
		PinnedSuite: c.Suite, Policy: handshake.PolicyVaultToVault, Features: features(), Now: now,
	})
	var s handshake.InitiatorState
	if err == nil {
		if s, err = ini.Export(); err != nil {
			ini.Abort()
		}
	}
	if err != nil {
		for _, j := range jtis {
			p.denyJTI(j, now)
		}
		return false
	}
	id := p.newID(now)
	kid, th1 := ini.EphKid(), ini.Th1()
	og := &outgoing{ID: id, ConnID: c.ID, EphKid: kid[:], Th1: th1[:], Init: s, Created: now, Issued: jtis,
		Named: bytes.Clone(c.LastEpochID), ini: ini}
	p.outgoing[id] = og
	p.markDirty(kindOutgoing, id)
	if c.ReconnectSince.IsZero() {
		c.ReconnectSince = now
	}
	c.Reconnecting = true
	c.ReconnectTries++
	p.markDirty(kindConn, c.ID)
	e := &outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Token: c.Reconnect.Token, Payload: ini.Envelope(), Handshake: true}
	p.queueDeposit(e, now)
	og.InitEntry = e.ID
	p.log().Info("reconnect started", "connection_id", c.ID)
	return true
}

// finishReconnect processes a reconnect the service started, once its
// hs.resp verified: the member's tokens are kept with the pending epoch
// (adopted at its confirmation), its
// identity follows the rotation links it sent that we had not followed
// (made while our state was older), and hs.fin goes out in the new
// epoch, which is pending until the member confirms it (§6.3.1
// Initiator). The reconnect stays open until then.
func (p *Peer) finishReconnect(c *Connection, og *outgoing, res *handshake.Result, now time.Time) disposition {
	st, err1 := p.heldToken(res.Resp.Token, &c.Peer, tokStanding)
	rt, err2 := p.heldToken(res.Resp.ReconnectToken, &c.Peer, tokReconnect)
	if err1 != nil || err2 != nil {
		p.audit("reconnect_bad_token", c.ID)
		res.Epoch.Destroy()
		for _, j := range og.Issued {
			p.denyJTI(j, now)
		}
		p.reconnectFailed(c)
		return ackAfterFlush
	}
	fresh := res.Resp.Rotations[handshake.KnownPrefix(chainOf(c), res.Resp.Rotations):]
	if p.revisits(c, fresh) {
		p.audit("bad_rotation", c.ID)
		res.Epoch.Destroy()
		for _, j := range og.Issued {
			p.denyJTI(j, now)
		}
		p.reconnectFailed(c)
		return ackAfterFlush
	}
	// §6.3.1 "I's rekeys end at its reconnect's hs.resp" (R29-T2): before
	// the reconnect's epoch becomes pending, our open rekeys are
	// abandoned (an hs.init not yet deposited is not sent). Defensive, as
	// in vettid-vault: startRekey starts none while a reconnect is open.
	for id, o := range p.outgoing {
		if o.ConnID == c.ID && o.ini != nil && o.ini.Purpose() == handshake.PurposeRekey {
			p.audit("rekey_ended_by_reconnect", c.ID)
			p.dropOutgoing(id)
		}
	}
	// Not open while the links are followed: an answer following them
	// drops (dropStaleAnswers) must not start another try, nor H5 restart
	// this one, whose message makes the change.
	c.Reconnecting = false
	if len(fresh) > 0 {
		p.followRotation(c, res.ResponderIK, res.ResponderKEM, fresh, false)
	}
	if c.State == StateSuspended {
		// Following judged an answer's links: a fork. The suspension
		// stands: no hs.fin, no epoch, our tokens revoked.
		c.clearReconnect()
		res.Epoch.Destroy()
		for _, j := range og.Issued {
			p.denyJTI(j, now)
		}
		p.markDirty(kindConn, c.ID)
		return ackAfterFlush
	}
	// Our open answers to the member's rekeys end too, as at a crossing
	// with our reconnect (§6.5: answered, then dropped when the reconnect
	// completes; their links were judged above); kept, they would hold our rekeys back for up to L.
	for aid, aw := range p.awaiting {
		if aw.ConnID == c.ID && aw.New == nil && aw.Purpose == handshake.PurposeRekey {
			p.audit("rekey_answer_ended_by_reconnect", c.ID)
			p.dropAwaiting(aid, now)
		}
	}
	c.Reconnecting = true
	p.activeAgain(c)
	p.markDirty(kindConn, c.ID)
	p.makePending(c, og, res, &PendingEpoch{Standing: st, Reconnect: rt}, now)
	p.log().Info("reconnected: epoch pending", "connection_id", c.ID)
	return ackAfterFlush
}

// chainOf parses a connection's followed rotation links; one that does
// not parse is skipped.
func chainOf(c *Connection) []*handshake.Rotation {
	var out []*handshake.Rotation
	for _, raw := range c.Chain {
		if r, err := handshake.ParseRotation(raw); err == nil {
			out = append(out, r)
		}
	}
	return out
}
