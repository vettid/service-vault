package peer

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The demotion rules of VAULT-MESSAGING §3.4.1 for the service as Q
// (RELEASE-29 §14, change 4b), as vettid-vault vault/iklinks.go does:
// "Epochs after an ik link" (R29-K4), "After a demotion of the current
// epoch" (K5), "Strict F1" with its links applied at hs.fin (K7, 0.90.4,
// 0.90.6), "Pending epochs at a link" (K2) and "Epochs abandoned while
// pending, at P's identity.rotate" (K9).

// AbandonedEpoch records a pending epoch of the service's own that it
// abandoned. Its receive keys are kept 16 days (§6.3.1), so a message
// under it can still arrive: the record keeps what §3.4.1 judges it by.
type AbandonedEpoch struct {
	ID []byte `json:"id"`
	// At is when it was abandoned: the record goes with its receive keys.
	At time.Time `json:"at"`
	// Signer is the member's key its hs.resp was signed under, and EstAt
	// and EstMsg that hs.resp's relay position.
	Signer []byte    `json:"signer,omitempty"`
	EstAt  time.Time `json:"est_at,omitzero"`
	EstMsg string    `json:"est_msg,omitempty"`
	// Received: a message from the member opened under it after it was
	// abandoned (the received flag, §6.3.1).
	Received bool `json:"received,omitempty"`
	// ByLink: abandoned by a link whose old key signed its hs.resp
	// ("Pending epochs at a link", K2): demoted from the start, so every
	// message under it is refused.
	ByLink bool `json:"by_link,omitempty"`
	// Ended by R29-K9: a message under it is fork evidence, and a
	// reconnect naming it is refused.
	Ended bool `json:"ended,omitempty"`
}

func (c *Connection) abandonedMeta(id []byte) *AbandonedEpoch {
	for i := range c.AbandonedMeta {
		if bytes.Equal(c.AbandonedMeta[i].ID, id) {
			return &c.AbandonedMeta[i]
		}
	}
	return nil
}

// recordAbandoned keeps the record of an abandoned pending epoch.
func (p *Peer) recordAbandoned(c *Connection, pe *PendingEpoch, byLink bool, now time.Time) {
	if c.abandonedMeta(pe.ID) != nil {
		return
	}
	c.AbandonedMeta = append(c.AbandonedMeta, AbandonedEpoch{ID: bytes.Clone(pe.ID), At: now, Signer: bytes.Clone(pe.Signer),
		EstAt: pe.RespAt, EstMsg: pe.RespMsg, ByLink: byLink})
	p.markDirty(kindConn, c.ID)
}

// pruneAbandoned drops the records whose receive keys are gone.
func (p *Peer) pruneAbandoned(c *Connection, now time.Time) {
	keep := c.AbandonedMeta[:0]
	for _, a := range c.AbandonedMeta {
		if now.Sub(a.At) < handshake.ReceiveKeyRetention+storeMargin {
			keep = append(keep, a)
		}
	}
	if len(keep) != len(c.AbandonedMeta) {
		p.markDirty(kindConn, c.ID)
	}
	if len(keep) == 0 {
		keep = nil
	}
	c.AbandonedMeta = keep
}

// signedAtOrBefore reports whether signer is the link's oldIK or an
// ancestor of it: the old key of a followed link before the one from oldIK
// (§3.4.1 "that link's old_ik or an ancestor").
func signedAtOrBefore(c *Connection, signer, oldIK ed25519.PublicKey) bool {
	if len(signer) == 0 {
		return false
	}
	if suite.EqualPublic(signer, oldIK) {
		return true
	}
	for _, r := range chainOf(c) {
		if suite.EqualPublic(r.OldIK, oldIK) {
			return false
		}
		if suite.EqualPublic(r.OldIK, signer) {
			return true
		}
	}
	return false
}

// signedByLinks reports whether signer is the old key of one of links, or
// an ancestor of one.
func signedByLinks(c *Connection, signer ed25519.PublicKey, links []*handshake.Rotation) bool {
	for _, r := range links {
		if signedAtOrBefore(c, signer, r.OldIK) {
			return true
		}
	}
	return false
}

// currentDemoted reports whether the connection's current epoch is
// demoted.
func (c *Connection) currentDemoted() bool {
	e := c.epochMeta(c.LastEpochID)
	return e != nil && e.Demoted
}

// demoteAt applies "Epochs after an ik link" (R29-K4) and "Strict F1"
// (R29-K7) for links just followed, at the position of the message being
// handled (x). f1 is strict F1's E: the epoch an identity.rotate traveled
// under, or for links applied at an hs.fin the epoch the rekey's hs.init
// traveled under or the reconnect named (0.90.4); nil runs no strict F1.
// restart is false for links applied beside a handshake of the service's
// or the member's, which makes the next epoch itself: then no reconnect
// is started. It reports false when the connection was suspended.
func (p *Peer) demoteAt(c *Connection, links []*handshake.Rotation, f1 []byte, restart bool, now time.Time) bool {
	if len(links) == 0 || c.State == StateSuspended {
		return c.State != StateSuspended
	}
	x, xm := p.relayAt, p.msgID
	byPosition := func(e *EpochMeta) bool {
		return xm != "" && !e.Demoted && !e.Destroyed && signedByLinks(c, e.Signer, links) && e.EstMsg != "" &&
			posAfter(e.EstAt, e.EstMsg, x, xm)
	}
	for i := range c.Epochs {
		if e := &c.Epochs[i]; byPosition(e) && e.Received {
			// The member's side used an epoch its rotated key could not have
			// made, after the rotation: a copy did.
			p.suspendFor(c, SuspendEpoch, now)
			return false
		}
	}
	demotedCurrent := false
	for i := range c.Epochs {
		e := &c.Epochs[i]
		if !byPosition(e) {
			continue
		}
		e.Demoted, e.DemotedAt, e.DemotedMsg = true, x, xm
		p.markDirty(kindConn, c.ID)
		// A fork sign, audited without a suspension (S8, 0.86.6).
		p.log().Warn("epoch demoted", "reason", "fork_suspected", "ref", "epoch", "rule", "position", "connection_id", c.ID)
		if bytes.Equal(e.ID, c.LastEpochID) {
			demotedCurrent = true
		}
	}
	if !p.f1Demote(c, links, f1, restart, now) {
		return false
	}
	if demotedCurrent && restart {
		p.restartAfterDemotion(c, now)
	}
	return true
}

// f1Demote is "Strict F1, a link under an earlier epoch" (R29-K7): a link
// carried under (or, at an hs.fin, named by) an epoch E of the member,
// while the current epoch is later than E and signed by the link's old
// key, shows that the member never activated the epochs after E signed by
// that key, or that a copy did. Every such epoch, other than destroyed
// ones, is taken together (0.90.6: pending and abandoned epochs are not in
// the list): one with its received flag set suspends; otherwise all are
// demoted at x, and, unless restart is false, the service reconnects
// naming E. It reports false when the connection was suspended.
func (p *Peer) f1Demote(c *Connection, links []*handshake.Rotation, f1 []byte, restart bool, now time.Time) bool {
	if len(f1) == 0 || bytes.Equal(f1, c.LastEpochID) {
		return true
	}
	ic := c.epochIndex(c.LastEpochID)
	if ic < 0 {
		return true
	}
	// after reports whether the epoch at index i is later than E: by index
	// when E is in the list, else (E one of our abandoned pending epochs,
	// which the list never holds) by the position of its establishment.
	var after func(i int) bool
	if ie := c.epochIndex(f1); ie >= 0 {
		after = func(i int) bool { return i > ie }
	} else if a := c.abandonedMeta(f1); a != nil && a.EstMsg != "" {
		after = func(i int) bool {
			e := &c.Epochs[i]
			return e.EstMsg != "" && posAfter(e.EstAt, e.EstMsg, a.EstAt, a.EstMsg)
		}
	} else {
		return true
	}
	if !after(ic) {
		return true // the current epoch is not later than E
	}
	cur := &c.Epochs[ic]
	for _, r := range links {
		if !suite.EqualPublic(cur.Signer, r.OldIK) {
			continue
		}
		var later []*EpochMeta
		for i := range c.Epochs {
			if e := &c.Epochs[i]; after(i) && !e.Destroyed && signedAtOrBefore(c, e.Signer, r.OldIK) {
				later = append(later, e)
			}
		}
		for _, e := range later {
			if e.Received {
				p.suspendFor(c, SuspendEpoch, now)
				return false
			}
		}
		for _, e := range later {
			if !e.Demoted {
				e.Demoted, e.DemotedAt, e.DemotedMsg = true, p.relayAt, p.msgID
			}
		}
		p.markDirty(kindConn, c.ID)
		p.log().Warn("epochs demoted", "reason", "fork_suspected", "ref", "epoch", "rule", "strict_f1", "connection_id", c.ID)
		// Our rekeys in flight were abandoned already: following the links
		// dropped every outgoing handshake (followRotation, H5).
		if restart {
			c.ReconnectNamed = bytes.Clone(f1)
			p.markDirty(kindConn, c.ID)
			p.restartAfterDemotion(c, now)
		}
		return true
	}
	return true
}

// newestUsable is the newest epoch of the member's that has been current
// and is neither demoted nor destroyed (§3.4.1 "After a demotion", 0.86.5),
// or nil.
func (c *Connection) newestUsable() []byte {
	for i := len(c.Epochs) - 1; i >= 0; i-- {
		if e := c.Epochs[i]; !e.Demoted && !e.Destroyed {
			return e.ID
		}
	}
	return nil
}

// reconnectTarget is the epoch a reconnect of the service's names: the one
// strict F1 chose, else while the current epoch is demoted the newest
// usable one, else the current one.
func (c *Connection) reconnectTarget() []byte {
	if !c.currentDemoted() {
		return c.LastEpochID // a strict F1 choice ended with the demotion
	}
	if len(c.ReconnectNamed) > 0 {
		return c.ReconnectNamed
	}
	return c.newestUsable()
}

// restartAfterDemotion starts "the reconnect after a demotion" (K5): it
// names E after strict F1, else the newest usable epoch; with none, the
// connection becomes stale. It starts only while no reconnect of the
// service's is open and no epoch of its own is pending (one at a time,
// §6.6; RK1); tickDemoted tries again later.
func (p *Peer) restartAfterDemotion(c *Connection, now time.Time) {
	if c.State != StateActive && c.State != StateStale {
		return
	}
	if c.Pending != nil || p.reconnectOpen(c) {
		return // one at a time: judged again once it is confirmed or abandoned
	}
	if len(c.reconnectTarget()) == 0 {
		c.Reconnecting = true // so that reconnectFailed ends it
		p.reconnectFailed(c)
		return
	}
	if c.Reconnecting {
		p.reconnectIfIdle(c, now)
		return
	}
	p.beginReconnect(c, now)
}

// tickDemoted (housekeeping): while the current epoch is demoted and no
// handshake that would replace it is open, a new reconnect is started:
// the service sends nothing but handshake messages until an epoch is
// current again.
func (p *Peer) tickDemoted(c *Connection, now time.Time) {
	if c.State != StateActive || !c.currentDemoted() || c.Reconnecting {
		return
	}
	p.restartAfterDemotion(c, now)
}

// demotedMessage judges a message from the member, other than hs.fin, under
// an epoch §3.4.1 demoted: one deposited after the demotion's position is
// refused (ancestor_ik); one deposited before it is accepted and would set
// the received flag, which an honest member never does under such an
// epoch, so the connection is suspended ("The flag is judged whenever it is
// set", 0.88.2). It reports true: the message is dealt with.
func (p *Peer) demotedMessage(c *Connection, e *EpochMeta, now time.Time) bool {
	if posAfter(p.relayAt, p.msgID, e.DemotedAt, e.DemotedMsg) {
		p.audit("ancestor_ik", c.ID)
		return true
	}
	p.suspendFor(c, SuspendEpoch, now)
	return true
}

// abandonedMessage judges a message from the member, other than hs.fin,
// under a pending epoch of the service's that it abandoned: one ended by
// K9 is fork evidence (suspended); one abandoned by a link is demoted
// from the start (refused, ancestor_ik); otherwise its received flag is
// set and it is processed without confirming anything. It reports true
// when the message is dealt with.
func (p *Peer) abandonedMessage(c *Connection, a *AbandonedEpoch, now time.Time) bool {
	switch {
	case a.Ended:
		p.suspendFor(c, SuspendEpoch, now)
		return true
	case a.ByLink:
		p.audit("ancestor_ik", c.ID)
		return true
	}
	if !a.Received {
		a.Received = true
		p.markDirty(kindConn, c.ID)
	}
	return false
}

// k9 is "Epochs abandoned while pending, at P's identity.rotate" (R29-K9),
// in the write that follows or ignores an identity.rotate traveling under
// msgEpoch (E): for each of its links, every pending epoch of the
// service's that it abandoned, established after E, whose hs.resp was
// signed by the link's old key or an ancestor, was never activated by the
// member. One with its received flag set suspends; the others are ended
// (audited fork_suspected): a later message under one is fork evidence,
// and a reconnect naming one is refused.
func (p *Peer) k9(c *Connection, links []*handshake.Rotation, msgEpoch []byte, now time.Time) {
	if c.State == StateSuspended {
		return
	}
	var eAt time.Time
	var eMsg string
	if e := c.epochMeta(msgEpoch); e != nil {
		eAt, eMsg = e.EstAt, e.EstMsg
	} else if a := c.abandonedMeta(msgEpoch); a != nil {
		eAt, eMsg = a.EstAt, a.EstMsg
	} else {
		return
	}
	var judged []*AbandonedEpoch
	for i := range c.AbandonedMeta {
		a := &c.AbandonedMeta[i]
		if a.Ended || bytes.Equal(a.ID, msgEpoch) || a.EstMsg == "" ||
			eMsg != "" && !posAfter(a.EstAt, a.EstMsg, eAt, eMsg) {
			continue
		}
		if signedByLinks(c, a.Signer, links) {
			judged = append(judged, a)
		}
	}
	for _, a := range judged {
		if a.Received {
			p.suspendFor(c, SuspendEpoch, now)
			return
		}
	}
	for _, a := range judged {
		a.Ended, a.ByLink = true, false
		c.Abandoned = removeID(c.Abandoned, a.ID) // no longer kept for a reconnect's ctx
		p.markDirty(kindConn, c.ID)
		p.log().Warn("abandoned epoch ended", "reason", "fork_suspected", "ref", "epoch", "rule", "k9", "connection_id", c.ID)
	}
}

func removeID(ids [][]byte, id []byte) [][]byte {
	out := ids[:0]
	for _, x := range ids {
		if !bytes.Equal(x, id) {
			out = append(out, x)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// initEpochID is the id of the epoch a rekey hs.init traveled under.
func initEpochID(ep *handshake.Epoch) []byte {
	id := ep.ID()
	return bytes.Clone(id[:])
}

// refusedReconnectLinks is §6.6 "The links of a refused reconnect" (X4's
// second half, 0.88.2): a member's reconnect hs.init refused only because
// the service's own reconnect is pending still has its identity links
// applied, in the write that refuses it, as vettid-vault does. The caller
// made the replay, sender and second-successor checks; here the whole
// chain must resolve from the stored key to from.ik with from.kem its last
// new_kem, no link may be one Table B refuses (a new key that is the
// stored key, an ancestor or one the chain passed: then none is
// followed), and its ctx must be one that would otherwise be accepted and
// is not fork evidence. The links are followed as an identity.rotate's
// would be, strict F1's E being the epoch the ctx names; nothing is
// answered, nothing restarts beside our own reconnect, and neither K9 nor
// "Fork by ctx" is run. When following ended our pending reconnect, it is
// started again under the new key.
func (p *Peer) refusedReconnectLinks(c *Connection, body *handshake.Init, now time.Time) {
	pe := c.Pending
	if pe == nil || pe.Purpose != handshake.PurposeReconnect || len(body.Rotations) == 0 || c.State != StateActive {
		return
	}
	final, kem, n, err := handshake.ResolveChainKnown(c.Peer.IK, chainOf(c), body.Rotations)
	if err != nil || !suite.EqualPublic(final, body.From.IK) || kem == nil || body.From.KEM == nil || !kem.Equal(body.From.KEM) ||
		n >= len(body.Rotations) {
		return
	}
	links := body.Rotations[n:]
	if p.revisits(c, links) {
		// Table B would refuse a link (a new key that is the stored key, an
		// ancestor, or one these links passed): none is followed.
		p.audit("refused_reconnect_links_none", c.ID)
		return
	}
	c.Pending = nil
	named, _, forkEp, ok := p.classifyCtx(c, body.Ctx, links)
	c.Pending = pe
	if !ok || forkEp {
		return
	}
	var e []byte
	if c.epochMeta(named) != nil || c.abandonedMeta(named) != nil {
		e = named // strict F1's E: an epoch that was current, or one of our abandoned ones
	}
	p.followRotation(c, final, kem, links, e, false)
	p.audit("refused_reconnect_links", c.ID)
	if c.Pending == nil && c.State == StateActive {
		// Following ended our pending reconnect: it starts again, under the
		// new key (naming as reconnectTarget says).
		if c.Reconnecting {
			p.restartReconnect(c, now)
		} else {
			p.beginReconnect(c, now)
		}
	}
}
