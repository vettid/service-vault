package peer

import (
	"bytes"
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Release 29, the third change (RELEASE-29 §14): a member's rekey or
// reconnect naming the service's confirmed epoch, rule E and its fork
// evidence, fork by ctx, the rest of "Accepting ctx" (§6.6), and a stale
// reconnect answer ending at a later message (§6.3.1, 0.88.9).

// SuspendEpoch is connection.suspended's reason for fork evidence about
// an epoch (rule E, fork by ctx; RELEASE-29 §7).
const SuspendEpoch = "epoch"

// classifyCtx is §6.6 "Accepting ctx" for a member's reconnect: while the
// service's own reconnect is pending, only that pending epoch; otherwise
// its current epoch, its own pending (rekey) epoch, its confirmed epoch
// while not current (namedConf: rule E at hs.fin), or a pending epoch it
// abandoned, until a newer one is confirmed. An epoch older than the
// confirmed one is fork evidence when an epoch after it, up to the
// confirmed one, was signed by an ancestor of the ik the hs.init reaches
// (§3.4.1 "Fork by ctx": forkEp, judged at hs.fin). Anything else is
// refused (ok false). fresh are the hs.init's links not yet followed.
func (p *Peer) classifyCtx(c *Connection, ctx string, fresh []*handshake.Rotation) (named []byte, namedConf, forkEp, ok bool) {
	is := func(id []byte) bool {
		if len(id) != suite.EpochIDSize {
			return false
		}
		var eid [suite.EpochIDSize]byte
		copy(eid[:], id)
		return ctx == handshake.EpochCtx(eid)
	}
	if c.pendingReconnect() {
		return c.Pending.ID, false, false, is(c.Pending.ID)
	}
	switch {
	case is(c.LastEpochID):
		return c.LastEpochID, false, false, true
	case c.Pending != nil && is(c.Pending.ID):
		return c.Pending.ID, false, false, true
	case is(c.Confirmed):
		return c.Confirmed, true, false, true
	}
	for _, a := range c.Abandoned {
		if is(a) {
			return a, false, false, true
		}
	}
	for _, e := range c.Epochs {
		if is(e.ID) && p.forkEpoch(c, e.ID, fresh) {
			return e.ID, false, true, true
		}
	}
	return nil, false, false, false
}

// forkEpoch is §3.4.1 "Fork by ctx": a handshake naming epoch id, older
// than the confirmed one, after which an epoch up to the confirmed one was
// signed by an ancestor of the ik the handshake reaches (the chain
// followed, with its links not yet followed, fresh). A named epoch that
// was destroyed is no evidence (rule E judges messages under it); a later
// epoch's record without a signer is none either.
func (p *Peer) forkEpoch(c *Connection, id []byte, fresh []*handshake.Rotation) bool {
	ic, ci := c.epochIndex(id), c.epochIndex(c.Confirmed)
	if ic < 0 || ci <= ic || c.Epochs[ic].Destroyed {
		return false
	}
	anc := ancestors(c, fresh)
	for _, later := range c.Epochs[ic+1 : ci+1] {
		if later.Demoted && !later.Received {
			// (0.88.2, owner decision a) an epoch demoted with its received
			// flag clear is no evidence: the member may never have used it.
			continue
		}
		for _, k := range anc {
			if len(later.Signer) > 0 && suite.EqualPublic(later.Signer, k) {
				return true
			}
		}
	}
	return false
}

// rekeyPrecheck is a rekey hs.init's own checks, before a judgment that
// does not answer it (vettid-vault rekeyPrecheck): its body, purpose rekey
// and ctx naming the epoch it opened under, the ts window, the sender
// being the member's relay key and from.relay.pk, and from.ik the stored
// key or reached from it through the hs.init's links. It returns those
// links not yet followed.
func (p *Peer) rekeyPrecheck(c *Connection, in *envelope.Inner, ep *handshake.Epoch, sender ed25519.PublicKey, now time.Time) ([]*handshake.Rotation, error) {
	body, err := handshake.ParseInit(in.Body)
	if err != nil {
		return nil, err
	}
	if body.Purpose != handshake.PurposeRekey || body.Ctx != handshake.EpochCtx(ep.ID()) {
		return nil, handshake.ErrCtx
	}
	if err := in.CheckTime(now, true); err != nil {
		return nil, err
	}
	if !suite.EqualPublic(sender, c.Peer.Relay.PK) || !suite.EqualPublic(sender, body.From.Relay.PK) {
		return nil, handshake.ErrSender
	}
	if len(body.Rotations) == 0 {
		if !suite.EqualPublic(body.From.IK, c.Peer.IK) {
			return nil, handshake.ErrIdentity
		}
		return nil, nil
	}
	final, _, n, err := handshake.ResolveChainKnown(c.Peer.IK, chainOf(c), body.Rotations)
	if err != nil || !suite.EqualPublic(final, body.From.IK) {
		return nil, handshake.ErrIdentity
	}
	return body.Rotations[n:], nil
}

// ancestors are the member's identity keys the chain followed, with the
// hs.init's fresh links, has moved past (every link's old key).
func ancestors(c *Connection, fresh []*handshake.Rotation) []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, r := range chainOf(c) {
		out = append(out, r.OldIK)
	}
	for _, r := range fresh {
		if r.Verify() == nil { // only a valid link is evidence
			out = append(out, r.OldIK)
		}
	}
	return out
}

// ruleE is §6.3.1 rule E, in the write that establishes, at its verified
// hs.fin, the epoch of a handshake that named the confirmed epoch while it
// was not current: every epoch later than the confirmed one is destroyed,
// recorded with the accepted hs.init's inner ts. Their send keys and rk
// go; their receive keys are kept 16 days, only to judge a later message
// under one. An epoch the service began and abandoned while pending is not
// among them (it is not in the list); its own epochs in the list became
// current at their confirmation, so no hs.fin of ours for one is still
// waiting.
func (p *Peer) ruleE(c *Connection, initTS, now time.Time) {
	ci := c.epochIndex(c.Confirmed)
	if ci < 0 {
		return
	}
	for i := ci + 1; i < len(c.Epochs); i++ {
		e := &c.Epochs[i]
		if e.Destroyed {
			continue
		}
		e.Destroyed, e.DestroyTS = true, initTS
		if e.Superseded.IsZero() {
			e.Superseded = now
		}
		if c.kr != nil && !bytes.Equal(e.ID, c.LastEpochID) {
			var eid [suite.EpochIDSize]byte
			copy(eid[:], e.ID)
			c.kr.Release(eid, now.Add(handshake.ReceiveKeyRetention))
		}
		p.audit("epoch_destroyed", c.ID)
	}
	p.markDirty(kindConn, c.ID)
}

// destroyedEpochMessage judges an authenticated message under an epoch
// rule E destroyed: with a later inner ts it is fork evidence (the
// connection is suspended, reason epoch); an earlier one is refused
// (superseded_epoch).
func (p *Peer) destroyedEpochMessage(c *Connection, e *EpochMeta, in *envelope.Inner, now time.Time) {
	if !in.TS.After(e.DestroyTS) {
		p.audit("superseded_epoch", c.ID)
		return
	}
	p.suspendFor(c, SuspendEpoch, now)
}

// dropStaleReconnectAnswers is §6.3.1 "A stale reconnect answer ends at a
// later message" (0.88.9): a message from the member, other than hs.fin,
// under an epoch newer than the one an open reconnect answer's hs.init
// named, with a later inner ts than that hs.init, shows the member ended
// that reconnect; the answer is dropped (its tokens revoked, an hs.resp
// not yet deposited not sent). A fork sign's answer is kept, judged at
// its hs.fin.
func (p *Peer) dropStaleReconnectAnswers(c *Connection, msgEpoch []byte, ts time.Time, now time.Time) {
	mi := c.epochIndex(msgEpoch)
	if mi < 0 || c.Epochs[mi].Destroyed {
		return
	}
	for id, aw := range p.awaiting {
		if aw.ConnID != c.ID || aw.New != nil || aw.Reconnect == nil || aw.ForkEp || aw.InitTS.IsZero() {
			continue
		}
		ni := c.epochIndex(aw.Reconnect.Named)
		if ni < 0 || mi <= ni || !ts.After(aw.InitTS) {
			continue
		}
		p.audit("answer_ended_stale", c.ID)
		p.dropAwaiting(id, now)
	}
}
