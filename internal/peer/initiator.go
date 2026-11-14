package peer

import (
	"bytes"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// Release 29, the initiator half (VAULT-MESSAGING 0.89.2 §6.3.1
// "Initiator"; docs/RELEASE-29.md, the second change). Once the service
// has sent hs.fin for a rekey or reconnect of its own, the new epoch is
// pending: established, not current. Until a message from the member
// opens under it (any type but hs.fin) the service keeps sending in the
// current epoch, opens messages under both, and starts no rekey; while a
// reconnect's epoch is pending it sends nothing but the handshake. The
// confirming message makes the pending epoch current before anything else
// is done with it, and what waits in the outbox is sealed again under it.
// The pending epoch is abandoned at B, for want of a standing token (a
// rekey), when its hs.fin is refused token_revoked, at a change of the
// member's ik, at a crossing, when the service activates the member's
// handshake as responder, and when it starts a reconnect.

// PendingLife is B: how long the service's pending epoch waits for its
// confirmation, from its hs.fin (L + T + 2 days, §6.3.1 Lifetimes), judged
// only while the start latch is set (RELEASE-29 §2, Peer.drained).
const PendingLife = 32 * 24 * time.Hour

// PendingEpoch is the service's own rekey or reconnect epoch awaiting
// confirmation (§6.3.1 Initiator). The epoch's keys are in the keyring's
// pending slot.
type PendingEpoch struct {
	ID      []byte            `json:"id"`
	Purpose handshake.Purpose `json:"purpose"`
	// FinAt is when its hs.fin was queued: B runs from it.
	FinAt time.Time `json:"fin_at"`
	// RespTS is the inner ts of the hs.resp that made it, for a crossing
	// rekey of the member's (§6.3.1 "Crossing").
	RespTS time.Time `json:"resp_ts,omitzero"`
	// Issued are the jtis of the tokens a reconnect's hs.init carried,
	// revoked when the epoch is abandoned (§6.6).
	Issued []string `json:"issued,omitempty"`
	// Standing and Reconnect are the tokens a reconnect's hs.resp carried:
	// its hs.fin is deposited with Standing, and both are adopted at the
	// confirmation, never before (§6.3.1 "A handshake's tokens are adopted
	// at confirmation"); the held tokens stay until then, and a new try
	// after an abandonment goes on the held reconnect token.
	Standing  HeldToken `json:"standing,omitzero"`
	Reconnect HeldToken `json:"reconnect,omitzero"`
	// OwnIK is the service's identity key the handshake was made under: a
	// pending epoch stored under another is abandoned at load (R29-I7).
	OwnIK []byte `json:"own_ik,omitempty"`
	// Signer is the member's key its hs.resp was signed under, and RespAt
	// and RespMsg that hs.resp's relay position: the epoch was established
	// there (§3.4.1 "Epochs after an ik link").
	Signer  []byte    `json:"signer,omitempty"`
	RespAt  time.Time `json:"resp_at,omitzero"`
	RespMsg string    `json:"resp_msg,omitempty"`
}

// standingValid reports whether the service holds a standing token for
// the member that is valid by its exp on the service's clock.
func (c *Connection) standingValid(now time.Time) bool {
	return c.Standing.Token != "" && now.Before(c.Standing.Exp)
}

// reconnectValid reports whether the service holds a reconnect token for
// the member that is valid by its exp on the service's clock.
func (c *Connection) reconnectValid(now time.Time) bool {
	return c.Reconnect.Token != "" && now.Before(c.Reconnect.Exp)
}

// makePending records the service's verified rekey or reconnect epoch as
// pending and queues its hs.fin (a handshake message, marked with the
// epoch so that an abandonment drops it unsent). An earlier pending epoch
// is abandoned.
func (p *Peer) makePending(c *Connection, og *outgoing, res *handshake.Result, carried *PendingEpoch, now time.Time) {
	if c.kr == nil {
		c.kr = &handshake.Keyring{}
	}
	if c.Pending != nil {
		p.abandonPending(c, "replaced", false, now)
	}
	c.kr.SetPending(res.Epoch, now)
	if og.ini.Purpose() == handshake.PurposeReconnect {
		p.supersedeCarried(c) // this reconnect supersedes earlier carried tokens
	}
	id := res.Epoch.ID()
	pe := &PendingEpoch{ID: bytes.Clone(id[:]), Purpose: og.ini.Purpose(), FinAt: now, Issued: og.Issued,
		OwnIK: bytes.Clone(p.cfg.Keys.IKPublic()), Signer: bytes.Clone(res.ResponderIK), RespAt: p.relayAt, RespMsg: p.msgID}
	if carried != nil {
		pe.Standing, pe.Reconnect = carried.Standing, carried.Reconnect
	}
	if res.Inner != nil {
		pe.RespTS = res.Inner.TS
	}
	c.Pending = pe
	p.markDirty(kindConn, c.ID)
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Token: pe.Standing.Token, Payload: res.Fin,
		Handshake: true, FinEpoch: pe.ID}, now)
}

// confirmPending makes the pending epoch current: a message from the
// member other than hs.fin opened under it (noteFromMember). What waits
// in the outbox under the current epoch is sealed again under it first
// (§8.3 "Re-sealed at a key change"). At a rekey's confirmation the
// service's open reconnects that name another epoch end (§6.3.1 "I's
// open reconnects end at its rekey's confirmation"); at a reconnect's,
// the reconnect has succeeded.
func (p *Peer) confirmPending(c *Connection, now time.Time) {
	pe := c.Pending
	if pe == nil {
		return
	}
	c.Pending = nil
	p.markDirty(kindConn, c.ID)
	if c.kr == nil || c.kr.Pending() == nil {
		return
	}
	p.resealAtKeyChange(c, c.kr.Pending(), now)
	ep := c.kr.ConfirmPending(now)
	eid := ep.ID()
	c.LastEpochID = bytes.Clone(eid[:])
	p.recordActivated(c, eid[:], true, epochPos{at: pe.RespAt, msg: pe.RespMsg, signer: pe.Signer}, now)
	p.setConfirmed(c, eid[:], now) // an epoch the service activated at confirmation is confirmed
	if ep.Suite() > c.Suite {
		c.Suite = ep.Suite() // §13.4 pin
	}
	c.RekeyFailures, c.RekeyNotBefore = 0, time.Time{}
	// The reconnect's carried tokens are adopted now: one replaces the
	// held token of its kind if its exp is later (§6.3.1).
	if pe.Standing.Token != "" && pe.Standing.Exp.After(c.Standing.Exp) {
		c.Standing, c.RefreshID = pe.Standing, ""
	}
	if pe.Reconnect.Token != "" && pe.Reconnect.Exp.After(c.Reconnect.Exp) {
		c.Reconnect = pe.Reconnect
	}
	p.activeAgain(c)
	switch pe.Purpose {
	case handshake.PurposeRekey:
		// Defensive, as in vettid-vault: the service starts no reconnect
		// while its rekey is pending (startReconnect abandons it), so none
		// is open here.
		for id, og := range p.outgoing {
			if og.ConnID == c.ID && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect && !bytes.Equal(og.Named, c.LastEpochID) {
				p.audit("reconnect_stale_at_confirm", c.ID)
				p.dropOutgoing(id)
			}
		}
	case handshake.PurposeReconnect:
		p.markCarried(pe.Issued)
		c.clearReconnect()
		// §6.3.1 "The prompt to adopt", §6.6 "Re-minted after every
		// successful reconnect": fresh tokens under the new epoch.
		p.issue(c, tokStanding, true, now)
		p.issue(c, tokReconnect, true, now)
	}
	if c.Reconnecting && !p.reconnectOpen(c) {
		c.clearReconnect() // its last try ended above: the session is settled
	}
	p.retryConn(c.ID)
	p.log().Info("epoch confirmed", "connection_id", c.ID, "purpose", string(pe.Purpose))
}

// abandonPending abandons the service's pending epoch (why: b_passed,
// no_token, fin_revoked, link, crossing, peer_activated, reconnect,
// replaced, suspended, stale): its receive key is
// kept 16 days as a previous epoch's (messages under it are processed
// without confirming it), the tokens its hs.init carried are revoked, and
// its hs.fin, if still in the outbox, is dropped unsent (§6.3.1, R29-T2).
// A pending reconnect that reaches B makes the connection stale (§3.4.1
// "The reconnect bound"). With restart, the service then reconnects
// naming its current epoch (RELEASE-29 §3 items 1 to 3).
func (p *Peer) abandonPending(c *Connection, why string, restart bool, now time.Time) {
	pe := c.Pending
	if pe == nil {
		return
	}
	if c.kr != nil {
		c.kr.AbandonPending(now)
	}
	for _, j := range pe.Issued {
		p.denyJTI(j, now)
	}
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID && bytes.Equal(e.FinEpoch, pe.ID) })
	if why != "link" {
		// Kept until a newer epoch is confirmed: a reconnect may name it
		// (§6.6). One abandoned by a link is demoted from the start
		// ("Pending epochs at a link", K2): never named.
		c.Abandoned = append(c.Abandoned, bytes.Clone(pe.ID))
	}
	p.recordAbandoned(c, pe, why == "link", now)
	c.Pending = nil
	p.markDirty(kindConn, c.ID)
	p.audit("pending_abandoned_"+why, c.ID)
	if pe.Purpose == handshake.PurposeReconnect && why == "b_passed" {
		c.Reconnecting = true // so that reconnectFailed ends it
		p.reconnectFailed(c)
		return
	}
	if !restart {
		return
	}
	if c.Reconnecting {
		p.restartReconnect(c, now) // a pending reconnect's next try (not a failed one)
	} else {
		p.beginReconnect(c, now)
	}
}

// clearReconnect ends the record of an open reconnect of the service's.
func (c *Connection) clearReconnect() {
	c.Reconnecting, c.ReconnectTries, c.ReconnectSlow, c.ReconnectSince = false, 0, false, time.Time{}
	c.ReconnectRestore, c.ReconnectRestartIK, c.ReconnectNamed = false, nil, nil
}

// standingWaiting reports whether a deposit to c on the standing token
// waits in the outbox.
func (p *Peer) standingWaiting(c *Connection) bool {
	for _, e := range p.outbox {
		if e.ConnID == c.ID && e.Op == opDeposit && e.Token == "" {
			return true
		}
	}
	return false
}

// outgoingReconnect reports whether a reconnect hs.init of the service's
// to c awaits its hs.resp.
func (p *Peer) outgoingReconnect(c *Connection) bool {
	for _, og := range p.outgoing {
		if og.ConnID == c.ID && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
			return true
		}
	}
	return false
}

// activeAgain makes a stale connection active when an epoch becomes
// current (§3.4.1: stale is not final).
func (p *Peer) activeAgain(c *Connection) {
	if c.State == StateStale {
		c.State = StateActive
		p.markDirty(kindConn, c.ID)
		p.log().Info("connection active again", "connection_id", c.ID)
	}
}

// tickPendings runs, after a batch has been processed (a confirmation or
// a fresh token in it comes first) and at a tick: B and R29-I6
// (tickPending), and the reconnect of a connection that has a waiting
// entry and no valid standing token (RELEASE-29 §3 items 2 and 5).
func (p *Peer) tickPendings(now time.Time) {
	if p.mintWait(now) {
		return // its reconnects mint tokens the relay would refuse (mailbox.go)
	}
	for id := range p.discardCheck {
		if c := p.conns[id]; c != nil && c.State == StateActive {
			p.afterCarriedDiscard(c, now)
		}
	}
	p.discardCheck = nil
	for _, c := range p.conns {
		p.tickPending(c, now)
		if c.State == StateActive && !c.Reconnecting && !c.standingValid(now) && p.standingWaiting(c) {
			p.noTokenReconnect(c, now)
		}
	}
}

// tickPending applies B, judged only while the start latch
// is set, and abandons a pending rekey when the service holds no valid
// standing token for the member (R29-I6; a pending reconnect is not: it
// ends at B).
func (p *Peer) tickPending(c *Connection, now time.Time) {
	pe := c.Pending
	switch {
	case pe == nil || c.State == StateSuspended:
	case p.drained && now.Sub(pe.FinAt) > PendingLife:
		p.abandonPending(c, "b_passed", true, now)
	case pe.Purpose == handshake.PurposeRekey && !c.standingValid(now) && !p.carriedWait(c, now):
		p.abandonPending(c, "no_token", true, now)
	}
}

// beginReconnect starts a reconnect of the service's own, naming its
// current epoch (RELEASE-29 §3), unless one is open already (one at a
// time, R29-X4). Its tries are counted afresh; one that cannot start (no
// valid reconnect token) makes the connection stale (§3.4.1 "The
// reconnect bound").
func (p *Peer) beginReconnect(c *Connection, now time.Time) {
	if c.State != StateActive || c.Reconnecting {
		return // a stale connection waits for a new epoch (the member's reconnect, or a new invitation)
	}
	c.ReconnectTries, c.ReconnectSlow, c.ReconnectSince, c.ReconnectRestore = 0, false, time.Time{}, false
	c.Reconnecting = true
	p.markDirty(kindConn, c.ID)
	p.retryReconnect(c, now)
}

// restartReconnect starts the open reconnect again without counting a
// failed try (§3.4.1 H5: at a change of the member's ik, at most once per
// change; RELEASE-29 §3 item 8). It spends one of the reconnect token's
// deposits.
func (p *Peer) restartReconnect(c *Connection, now time.Time) {
	if !c.Reconnecting || c.State == StateSuspended {
		return
	}
	if c.ReconnectTries > 0 {
		c.ReconnectTries--
	}
	p.retryReconnect(c, now)
}

// pendingReconnect reports whether the service's reconnect epoch with c
// is pending.
func (c *Connection) pendingReconnect() bool {
	return c.Pending != nil && c.Pending.Purpose == handshake.PurposeReconnect
}
