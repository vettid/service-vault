package peer

import (
	"crypto/subtle"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Reconnecting after a restore (VAULT-MESSAGING §6.6, per the pending
// change for restores). A restored table puts the service's sessions back
// to older epochs than the members' vaults hold, so its messages and
// theirs no longer open. Each side keeps the ids of the epochs it
// activated in the last EpochHistory and accepts a reconnect naming any
// of them; the restored side starts the reconnects, naming its last
// epoch, which the member's vault still has in its history.

// EpochHistory is how long an activated epoch's id is kept: the reconnect
// token's longest lifetime (§6.6).
const EpochHistory = 365 * 24 * time.Hour

// MaxEpochs bounds a connection's history (a rekey a day keeps about
// 365).
const MaxEpochs = 512

// EpochRef is an activated epoch: its id and when it became current.
type EpochRef struct {
	ID []byte    `json:"id"`
	At time.Time `json:"at"`
}

// recordEpoch adds an activated epoch to the history and drops what is
// older than EpochHistory or beyond MaxEpochs.
func (c *Connection) recordEpoch(id []byte, now time.Time) {
	c.Epochs = append(c.Epochs, EpochRef{ID: append([]byte(nil), id...), At: now.UTC()})
	drop := 0
	for drop < len(c.Epochs) && now.Sub(c.Epochs[drop].At) > EpochHistory {
		drop++
	}
	drop = max(drop, len(c.Epochs)-MaxEpochs)
	c.Epochs = c.Epochs[drop:]
}

// knownEpoch reports whether ctx names the connection's last epoch or
// one in its history.
func (c *Connection) knownEpoch(ctx string) bool {
	match := func(id []byte) bool {
		var eid [suite.EpochIDSize]byte
		if len(id) != len(eid) {
			return false
		}
		copy(eid[:], id)
		return subtle.ConstantTimeCompare([]byte(handshake.EpochCtx(eid)), []byte(ctx)) == 1
	}
	if match(c.LastEpochID) {
		return true
	}
	for _, e := range c.Epochs {
		if match(e.ID) {
			return true
		}
	}
	return false
}

// reconnectAll starts a reconnect on every active or stale connection
// and returns how many started.
func (p *Peer) reconnectAll(now time.Time) int {
	n := 0
	for _, c := range p.conns {
		if p.startReconnect(c, now) {
			n++
		}
	}
	return n
}

// startReconnect sends a reconnect hs.init to the member's mailbox on the
// reconnect token the member's vault issued us (§6.6): sealed to its
// static key, naming our last epoch, with fresh standing and reconnect
// tokens. A rekey of ours in flight is dropped: it travels in an epoch the
// member may no longer hold.
func (p *Peer) startReconnect(c *Connection, now time.Time) bool {
	if c.State != StateActive && c.State != StateStale || len(c.LastEpochID) == 0 ||
		c.Reconnect.Token == "" || !now.Before(c.Reconnect.Exp) {
		p.log().Warn("reconnect not possible", "connection_id", c.ID, "state", c.State)
		return false
	}
	kem, err := suite.ParsePublicKey(c.Peer.KEM)
	if err != nil {
		return false
	}
	p.dropConnOutgoing(c)
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
		return ackAfterFlush
	}
	if fresh := res.Resp.Rotations[handshake.KnownPrefix(chainOf(c), res.Resp.Rotations):]; len(fresh) > 0 {
		p.followRotation(c, res.ResponderIK, res.ResponderKEM, fresh)
	}
	c.Standing, c.Reconnect = st, rt
	c.State = StateActive
	p.markDirty(kindConn, c.ID)
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: res.Fin}, now)
	p.installEpoch(c, res.Epoch, now)
	p.retryConn(c.ID)
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
