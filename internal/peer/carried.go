package peer

import (
	"bytes"
	"time"
)

// A handshake's tokens are adopted at confirmation (VAULT-MESSAGING
// §6.3.1, R29-T1; RELEASE-29 §14, the third change), the responder side.
// The standing and reconnect tokens a member's reconnect hs.init carried
// are kept with the epoch that reconnect established, as carried tokens,
// and replace the held tokens (each only if its exp is later) in the
// write in which the confirmed epoch reaches that epoch, never at hs.fin:
// until then the member may still abandon the epoch and revoke them. They
// are used only for the handshake's own messages (the hs.resp, and our
// hs.confirm and its re-sends); everything else uses the held tokens. The
// initiator side is the pending epoch's (PendingEpoch.Standing/Reconnect).

// CarriedTokens are a member's reconnect's carried tokens, kept with the
// epoch it established.
type CarriedTokens struct {
	Epoch     []byte    `json:"epoch"`
	Standing  HeldToken `json:"standing,omitzero"`
	Reconnect HeldToken `json:"reconnect,omitzero"`
	// Since is when the service activated the epoch: the wait is bounded
	// at the carried standing token's exp, capped at B from here.
	Since time.Time `json:"since"`
	// Discarded marks the current epoch's record once its tokens are
	// discarded: "hs.confirm again" stays stopped for it.
	Discarded bool `json:"discarded,omitempty"`
}

// carriedFor is c's carried-token record for epoch id, or nil.
func (c *Connection) carriedFor(id []byte) *CarriedTokens {
	for i := range c.Carried {
		if bytes.Equal(c.Carried[i].Epoch, id) {
			return &c.Carried[i]
		}
	}
	return nil
}

// carriedUsable reports whether record r still waits for adoption: not
// discarded, its epoch known and not destroyed, within its bound.
func (c *Connection) carriedUsable(r *CarriedTokens, now time.Time) bool {
	if r.Discarded {
		return false
	}
	e := c.epochMeta(r.Epoch)
	if e == nil || e.Destroyed {
		return false
	}
	if r.Standing.Token != "" && !now.Before(r.Standing.Exp) {
		return false
	}
	return now.Before(r.Since.Add(PendingLife))
}

// confirmStopped reports whether "hs.confirm again" has stopped for the
// current epoch: its carried tokens were discarded.
func (c *Connection) confirmStopped() bool {
	r := c.carriedFor(c.LastEpochID)
	return r != nil && r.Discarded
}

// confirmToken is the token an hs.confirm to c goes on: the current
// epoch's carried standing token while it waits, else the held one ("").
func (c *Connection) confirmToken(now time.Time) string {
	if r := c.carriedFor(c.LastEpochID); r != nil && c.carriedUsable(r, now) {
		return r.Standing.Token
	}
	return ""
}

// recordCarried keeps the tokens of a member's reconnect established now,
// for its epoch (the current one); it supersedes every earlier record.
func (p *Peer) recordCarried(c *Connection, st, rt HeldToken, now time.Time) {
	c.Carried = nil
	c.Carried = append(c.Carried, CarriedTokens{Epoch: bytes.Clone(c.LastEpochID), Standing: st, Reconnect: rt, Since: now})
	p.markDirty(kindConn, c.ID)
}

// supersedeCarried drops c's records: a newer token-carrying handshake
// (our own reconnect becoming pending, or the member's established)
// supersedes them, and an earlier epoch's carried tokens are never
// adopted at a later confirmation. The current epoch's is kept, discarded,
// so that "hs.confirm again" stays stopped for it. No reconnect follows.
func (p *Peer) supersedeCarried(c *Connection) {
	if len(c.Carried) == 0 {
		return
	}
	var keep []CarriedTokens
	for _, r := range c.Carried {
		if bytes.Equal(r.Epoch, c.LastEpochID) {
			r.Discarded, r.Standing, r.Reconnect = true, HeldToken{}, HeldToken{}
			keep = append(keep, r)
		}
	}
	c.Carried = keep
	p.markDirty(kindConn, c.ID)
}

// adoptCarried replaces each held token by the carried one of its kind if
// the carried one's exp is later, and lets waiting entries go.
func (p *Peer) adoptCarried(c *Connection, r *CarriedTokens) {
	if r.Standing.Token != "" && r.Standing.Exp.After(c.Standing.Exp) {
		c.Standing, c.RefreshID = r.Standing, ""
	}
	if r.Reconnect.Token != "" && r.Reconnect.Exp.After(c.Reconnect.Exp) {
		c.Reconnect = r.Reconnect
	}
	p.markDirty(kindConn, c.ID)
	p.retryConn(c.ID)
}

// adoptReached runs when c's confirmed epoch moves to id, before the
// handler of the message that moved it: the carried tokens of id, or of an
// earlier epoch it was reached from by rekeys, are adopted; records no
// longer waited for are discarded.
func (p *Peer) adoptReached(c *Connection, id []byte, now time.Time) {
	if len(c.Carried) == 0 {
		return
	}
	var keep []CarriedTokens
	discarded := false
	for _, r := range c.Carried {
		switch {
		case !c.carriedUsable(&r, now):
			discarded = discarded || !r.Discarded
			if bytes.Equal(r.Epoch, c.LastEpochID) && !bytes.Equal(r.Epoch, id) {
				r.Discarded, r.Standing, r.Reconnect = true, HeldToken{}, HeldToken{}
				keep = append(keep, r)
			}
		case bytes.Equal(r.Epoch, id) || c.epochIndex(id) > c.epochIndex(r.Epoch):
			p.adoptCarried(c, &r)
			p.audit("carried_adopted", c.ID)
		default:
			keep = append(keep, r)
		}
	}
	c.Carried = keep
	p.markDirty(kindConn, c.ID)
	if discarded {
		// Judged after the batch (tickPendings), not before this
		// message's handler: a token in it may still come.
		if p.discardCheck == nil {
			p.discardCheck = map[string]bool{}
		}
		p.discardCheck[c.ID] = true
	}
}

// carriedWait is §6.3.1 "No reconnect while carried tokens wait": the
// current epoch is one the service activated as responder, the confirmed
// epoch has not reached it, and its carried tokens wait, within their
// bound. While it holds, no reconnect starts for want of a valid standing
// token, and "no reconnect token" is not judged.
func (p *Peer) carriedWait(c *Connection, now time.Time) bool {
	if len(c.LastEpochID) == 0 {
		return false
	}
	r := c.carriedFor(c.LastEpochID)
	if r == nil || !c.carriedUsable(r, now) {
		return false
	}
	cur := c.epochMeta(c.LastEpochID)
	return cur != nil && !cur.Mine && !bytes.Equal(c.Confirmed, c.LastEpochID)
}

// sweepCarried (housekeeping) discards the records no longer waited for:
// their epoch destroyed, or their bound passed. Then, with no valid
// standing token held, the service reconnects.
func (p *Peer) sweepCarried(c *Connection, now time.Time) {
	if len(c.Carried) == 0 {
		return
	}
	var keep []CarriedTokens
	dropped := false
	for _, r := range c.Carried {
		if c.carriedUsable(&r, now) {
			keep = append(keep, r)
			continue
		}
		dropped = dropped || !r.Discarded
		if bytes.Equal(r.Epoch, c.LastEpochID) {
			r.Discarded, r.Standing, r.Reconnect = true, HeldToken{}, HeldToken{}
			keep = append(keep, r)
		}
	}
	if !dropped && len(keep) == len(c.Carried) {
		return
	}
	c.Carried = keep
	p.markDirty(kindConn, c.ID)
	if dropped {
		p.audit("carried_discarded", c.ID)
		p.afterCarriedDiscard(c, now)
	}
}

// afterCarriedDiscard: a discard with no valid held standing token puts
// the service in §8.6's "no valid standing token" case.
func (p *Peer) afterCarriedDiscard(c *Connection, now time.Time) {
	if !c.standingValid(now) {
		p.noTokenReconnect(c, now)
	}
}

// noTokenReconnect starts a reconnect for want of a valid standing token
// (RELEASE-29 §3 items 2, 4, 5 and 6), unless carried tokens wait.
func (p *Peer) noTokenReconnect(c *Connection, now time.Time) {
	if p.carriedWait(c, now) {
		return
	}
	p.beginReconnect(c, now)
}

// carriedRevoked handles token_revoked on a deposit made with a carried
// token: the member abandoned or dropped that handshake. Our hs.confirm's
// record is discarded (the hs.resp's answer is dropped by the caller);
// not a failed try.
func (p *Peer) carriedRevoked(c *Connection, tok string, now time.Time) {
	p.audit("carried_token_revoked", c.ID)
	for i := range c.Carried {
		if r := &c.Carried[i]; r.Standing.Token == tok {
			p.recordRevokedHeld(c, r.Standing, now)
			r.Discarded, r.Standing, r.Reconnect = true, HeldToken{}, HeldToken{}
		}
	}
	p.markDirty(kindConn, c.ID)
	p.afterCarriedDiscard(c, now)
}
