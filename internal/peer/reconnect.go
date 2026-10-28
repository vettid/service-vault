package peer

import (
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

// ReconnectTimeout ends a reconnect not completed in time (§6.6: 7 days,
// the idle lock's): the connection becomes stale and needs a new
// invitation.
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
		if p.startReconnect(c, now) {
			n++
		} else if c.State == StateActive || c.State == StateStale {
			c.Reconnecting = true // so that reconnectFailed ends it
			p.reconnectFailed(c)
		}
	}
	return n
}

// resumeReconnects runs at a start without a restore: a reconnect still
// open sends a new hs.init (a new th1; the stored bytes would be refused
// as a replay), within MaxReconnectTries.
func (p *Peer) resumeReconnects(now time.Time) {
	for _, c := range p.conns {
		if c.Reconnecting && !p.startReconnect(c, now) {
			p.reconnectFailed(c)
		}
	}
}

// checkReconnect raises reconnect_slow after a day and ends the reconnect
// after ReconnectTimeout (housekeeping).
func (p *Peer) checkReconnect(c *Connection, now time.Time) {
	switch age := now.Sub(c.ReconnectSince); {
	case age >= ReconnectTimeout:
		p.dropConnOutgoing(c)
		p.reconnectFailed(c)
	case age >= ReconnectSlowAfter && !c.ReconnectSlow:
		c.ReconnectSlow = true
		p.markDirty(kindConn, c.ID)
		p.log().Error("reconnect unanswered for a day: the member's vault may be locked", "alarm", "reconnect_slow", "connection_id", c.ID)
	}
}

// reconnectFailed ends a reconnect that cannot complete: the connection
// becomes stale (§6.6), and the alarm tells the operator the member must
// connect again from a new invitation (README "Restoring the table").
func (p *Peer) reconnectFailed(c *Connection) {
	if !c.Reconnecting {
		return
	}
	c.Reconnecting, c.ReconnectTries, c.ReconnectSlow, c.ReconnectSince = false, 0, false, time.Time{}
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
	c.Reconnecting = false // a reconnect replaced is not a failure
	p.dropConnOutgoing(c)
	// An earlier hs.init still waiting in the outbox is not sent: it is
	// replaced (§6.6).
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID && e.Token != "" && e.Token == c.Reconnect.Token })
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
		PinnedSuite: c.Suite, Policy: handshake.PolicyVaultToVault, Now: now,
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
	p.outgoing[id] = &outgoing{ID: id, ConnID: c.ID, EphKid: kid[:], Th1: th1[:], Init: s, Created: now, Issued: jtis, ini: ini}
	p.markDirty(kindOutgoing, id)
	if c.ReconnectTries == 0 {
		c.ReconnectSince = now
	}
	c.Reconnecting = true
	c.ReconnectTries++
	p.markDirty(kindConn, c.ID)
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Token: c.Reconnect.Token, Payload: ini.Envelope()}, now)
	p.log().Info("reconnect started", "connection_id", c.ID)
	return true
}

// finishReconnect completes a reconnect the service started, once its
// hs.resp verified: the member's tokens replace the held ones, its
// identity follows the rotation links it sent that we had not followed
// (made while our state was older), and hs.fin goes out in the new epoch.
func (p *Peer) finishReconnect(c *Connection, og *outgoing, res *handshake.Result, now time.Time) disposition {
	st, err1 := p.heldToken(res.Resp.Token, &c.Peer)
	rt, err2 := p.heldToken(res.Resp.ReconnectToken, &c.Peer)
	if err1 != nil || err2 != nil {
		p.audit("reconnect_bad_token", c.ID)
		res.Epoch.Destroy()
		for _, j := range og.Issued {
			p.denyJTI(j, now)
		}
		p.reconnectFailed(c)
		return ackAfterFlush
	}
	if fresh := res.Resp.Rotations[handshake.KnownPrefix(chainOf(c), res.Resp.Rotations):]; len(fresh) > 0 {
		p.followRotation(c, res.ResponderIK, res.ResponderKEM, fresh)
	}
	c.Standing, c.Reconnect = st, rt
	c.State = StateActive
	c.Reconnecting, c.ReconnectTries, c.ReconnectSlow, c.ReconnectSince = false, 0, false, time.Time{}
	p.markDirty(kindConn, c.ID)
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: res.Fin}, now)
	p.installEpoch(c, res.Epoch, now) // and retries the connection's outbox
	p.log().Info("reconnected", "connection_id", c.ID)
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
