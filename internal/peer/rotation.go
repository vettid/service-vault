package peer

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// A member's vault rotates its keys at a transfer to a new phone, a
// recovery and a credential.rotate (VAULT-MESSAGING §3.4, 0.68.0): its
// identity and KEM keys (identity.rotate, then a rekey) and its credential
// key (connection.authenticate.rotated, connauth.go), which the service
// follows, as the member vault follows a peer's. Its relay key
// (relay.address.update) is not followed: the update is refused
// (session.go) until §3.4.2's rules are built; release 29 rotates no relay
// key.

// Message types of §3.4 (VAULT-MESSAGING §10, "Sessions").
const (
	TypeIdentityRotate     = "identity.rotate"
	TypeRelayAddressUpdate = "relay.address.update"
)

// StateSuspended: two different successors of one identity key arrived
// (§3.4 "One successor per key"). Nothing is sent to or accepted from the
// connection. The member can resolve it only out of band, which a service
// cannot; a new invitation replaces the connection at activation.
const StateSuspended = "suspended"

// SuspendRotationConflict is connection.suspended's reason for a
// rotation conflict.
const SuspendRotationConflict = "rotation_conflict"

// SuspendRelayMoved is connection.suspended's reason for a connection a
// relay.address.update moved before such updates were refused
// (legacyRelayMove).
const SuspendRelayMoved = "relay_moved_unlinked"

// identityRotate is Table B's identity.rotate column (§3.4.1, R29-K1): the
// whole chain the member sent (S8), rule C on every link, then the links
// already followed are skipped (all of them: ignored); the first one not
// followed must start at the stored key (an ancestor: refused unexpected;
// any other key: unknown_ik); the rest must verify as a chain from it, and
// no new key may be the stored key or an ancestor (ik_rollback) or come
// back to a key already passed (bad_rotation). Following runs "Epochs
// after an ik link" and strict F1 with E the epoch the message traveled
// under (msgEpoch); R29-K9 is judged whether the links were followed or
// all already were. The member's vault rekeys next (§3.4 step 3), under
// the new key.
func (p *Peer) identityRotate(c *Connection, body []byte, msgEpoch []byte, now time.Time) {
	links, err := rotateLinks(body)
	if err != nil {
		p.audit("bad_rotation", c.ID)
		return
	}
	for _, r := range links {
		if p.rotationConflictRec(c, r, true, now) {
			return
		}
	}
	if c.State == StateSuspended {
		return
	}
	i := handshake.KnownPrefix(chainOf(c), links)
	if i == len(links) {
		p.k9(c, links, msgEpoch, now) // every link already followed: ignored, K9 still judged
		return
	}
	switch first := links[i].OldIK; {
	case suite.EqualPublic(first, c.Peer.IK):
	case isAncestor(c, first):
		p.audit("unexpected", c.ID) // Table B: an ancestor is only "all followed"
		return
	default:
		p.audit("unknown_ik", c.ID)
		return
	}
	app := links[i:]
	final, kem, err := handshake.ResolveChain(c.Peer.IK, app)
	if err != nil {
		p.audit("bad_rotation", c.ID)
		return
	}
	for _, r := range app {
		if suite.EqualPublic(r.NewIK, c.Peer.IK) || isAncestor(c, r.NewIK) {
			p.audit("ik_rollback", c.ID)
			return
		}
	}
	if p.revisits(c, app) {
		p.audit("bad_rotation", c.ID)
		return
	}
	p.followRotation(c, final, kem, app, msgEpoch, true)
	p.k9(c, links, msgEpoch, now)
}

// revisits reports whether following links would lead the connection's
// identity back to a key it already had (a cycle, such as A->B then
// B->A): one successor per key could then no longer be judged on the
// chain, so such links are never followed.
func (p *Peer) revisits(c *Connection, links []*handshake.Rotation) bool {
	seen := []ed25519.PublicKey{c.Peer.IK}
	for _, r := range chainOf(c) {
		seen = append(seen, r.OldIK, r.NewIK)
	}
	for _, r := range links {
		for _, k := range seen {
			if suite.EqualPublic(k, r.NewIK) {
				return true
			}
		}
		seen = append(seen, r.NewIK)
	}
	return false
}

// followRotation records links the connection's identity advanced through
// and its new keys, and applies §3.4.1's demotions at the position of the
// message being handled (demoteAt), f1 being strict F1's E (nil: none).
// restart is set when the links came in an identity.rotate: only then is
// an open reconnect of ours started again, or the reconnect after a
// demotion started (a handshake's own links make the change it
// completes).
func (p *Peer) followRotation(c *Connection, ik ed25519.PublicKey, kem *suite.PublicKey, links []*handshake.Rotation, f1 []byte, restart bool) {
	c.Peer.IK = ik
	if kem != nil {
		c.Peer.KEM = kem.Bytes()
	}
	for _, r := range links {
		c.Chain = append(c.Chain, r.Marshal())
	}
	// The whole chain is kept, as the member vault keeps it: ancestry
	// (Table B) and rule C read every link followed, so a link from a key
	// many rotations back is still judged (a member rotates at a phone
	// transfer, a recovery or a credential.rotate: rarely).
	pruneSeen(c) // a followed link is no longer only seen; irrelevant ones go
	// §3.4.1 H5: the service's open handshakes pinned to the member's
	// previous ik are abandoned: its rekeys and reconnect awaiting hs.resp,
	// and its pending epoch ("Pending epochs at a link", R29-K2). Its open
	// reconnect starts again under the new ik, spending a deposit but not a
	// try, at most once per change (RELEASE-29 §3 item 8); its rekeys
	// start again when the epoch next needs one. Then its answers whose
	// signer the links no longer reach are dropped.
	now := p.now()
	// Only a try of ours is restarted; a member's reconnect we yielded to
	// is not ours to start again.
	ownTry := restart && c.Reconnecting && (p.outgoingReconnect(c) || c.pendingReconnect())
	p.dropConnOutgoing(c)
	p.abandonPending(c, "link", false, now)
	p.markDirty(kindConn, c.ID)
	if !p.demoteAt(c, links, f1, restart, now) {
		return // suspended: every handshake and answer is gone
	}
	if ownTry && c.State != StateSuspended && !c.currentDemoted() && len(c.ReconnectNamed) == 0 &&
		!suite.EqualPublic(c.ReconnectRestartIK, ik) {
		c.ReconnectRestartIK = bytes.Clone(ik)
		p.restartReconnect(c, now)
	}
	p.dropStaleAnswers(c)
	p.log().Info("member identity rotated", "connection_id", c.ID)
}

// dropStaleAnswers drops the member's rekeys we answered whose signer
// the stored key and links no longer lead to (§3.4.1 H5): the stored key
// moved past it, so its hs.fin could only come from a copy holding an
// older key (checkSigner refuses it there too). An answer whose signer is
// still the stored key, or reached from it through the links it carries,
// stays. Their links are judged first: one that gives a key a second
// successor, now that more of the chain is followed, suspends the
// connection (§3.4). An answer stored before signers were kept (no
// Follow) is dropped: its signer is unknown.
func (p *Peer) dropStaleAnswers(c *Connection) {
	now := p.now()
	for id, aw := range p.awaiting {
		if aw.ConnID != c.ID || aw.New != nil {
			continue
		}
		if aw.Reconnect != nil {
			// A reconnect answer stored before signers were kept, without
			// links: its signer is unknown, so it is dropped. Others are
			// judged at their hs.fin (checkSigner).
			if aw.Reconnect.Signer == nil && len(aw.Reconnect.Links) == 0 {
				p.audit("reconnect_answer_dropped", c.ID)
				p.dropAwaiting(id, now)
			}
			continue
		}
		if aw.Purpose != handshake.PurposeRekey {
			continue
		}
		if aw.Follow != nil {
			ik, kem, links, err := aw.Follow.parse()
			if err == nil {
				for _, r := range links {
					if r.Verify() == nil && p.rotationConflict(c, r, now) {
						return // suspended: every answer is dropped
					}
				}
				final, fkem, _, err := handshake.ResolveChainKnown(c.Peer.IK, chainOf(c), links)
				if err == nil && suite.EqualPublic(final, ik) && (fkem == nil || fkem.Equal(kem)) {
					continue
				}
			}
		}
		p.audit("rekey_answer_dropped", c.ID)
		p.dropAwaiting(id, now)
	}
}

// errSignerMoved: a member's handshake answered under a key and links
// that what was followed since no longer leads to (checkSigner).
var errSignerMoved = errors.New("peer: the member's identity moved since its hs.init was answered")

// errSuspended: following a handshake's links suspended the connection
// (another answer's links gave a key a second successor); the handshake
// does not complete.
var errSuspended = errors.New("peer: the connection was suspended")

// newPendingFollow keeps what a member's rekey or reconnect hs.init
// named: its signer (from.ik and kem) and its whole chain, to be checked
// again at its hs.fin.
func newPendingFollow(body *handshake.Init) *pendingFollow {
	f := &pendingFollow{IK: body.From.IK, KEM: body.From.KEM.Bytes()}
	for _, r := range body.Rotations {
		f.Links = append(f.Links, r.Marshal())
	}
	return f
}

// followAtFin checks a member's handshake again at its verified hs.fin
// and follows its links not yet followed (checkSigner). It reports
// whether the handshake may complete; when not, the connection may be
// suspended (a second successor) or the handshake is audited and
// dropped.
func (p *Peer) followAtFin(c *Connection, f *pendingFollow, f1 []byte, now time.Time) bool {
	ik, kem, links, err := f.parse()
	if err != nil {
		p.audit("hs_record_bad", c.ID)
		return false
	}
	fresh, ok := p.checkSigner(c, ik, kem, links, now)
	if !ok {
		return false
	}
	if len(fresh) > 0 {
		p.followRotation(c, ik, kem, fresh, f1, false)
	}
	return c.State != StateSuspended // following judged another answer's links
}

// checkSigner checks, at a member's verified hs.fin, that the key its
// hs.init was signed with (from.ik, with its kem) is still the stored
// key, or reached from it through the links that hs.init carried after
// those followed since: identity.rotate statements, or another
// handshake's links, may have been followed while it awaited hs.fin
// (the relay keeps no order, S8). A valid link that gives a key a second
// successor suspends the connection first (§3.4). It returns the links
// not yet followed.
func (p *Peer) checkSigner(c *Connection, ik ed25519.PublicKey, kem *suite.PublicKey, links []*handshake.Rotation, now time.Time) ([]*handshake.Rotation, bool) {
	for _, r := range links {
		if r.Verify() == nil && p.rotationConflict(c, r, now) {
			return nil, false
		}
	}
	final, fkem, n, err := handshake.ResolveChainKnown(c.Peer.IK, chainOf(c), links)
	if err != nil || !suite.EqualPublic(final, ik) || fkem != nil && !fkem.Equal(kem) {
		p.audit("ancestor_ik", c.ID) // Table B, an hs.fin to our answer
		return nil, false
	}
	if p.revisits(c, links[n:]) {
		p.audit("bad_rotation", c.ID)
		return nil, false
	}
	return links[n:], true
}

// dropConnOutgoing abandons a rekey the service started on a connection:
// it named the member's previous keys, so its hs.resp can no longer be
// accepted. The member's own rekey under the new keys follows (§3.4), or
// the service starts another.
func (p *Peer) dropConnOutgoing(c *Connection) {
	for id, og := range p.outgoing {
		if og.ConnID == c.ID {
			p.dropOutgoing(id)
		}
	}
}

// knownSuccessor reports whether r is a link already accepted: the same
// old_ik, new_ik and new_kem (VAULT-MESSAGING 0.69.1 §6.6).
func (p *Peer) knownSuccessor(c *Connection, r *handshake.Rotation) bool {
	for _, raw := range c.Chain {
		prev, err := handshake.ParseRotation(raw)
		if err == nil && suite.EqualPublic(prev.OldIK, r.OldIK) && suite.EqualPublic(prev.NewIK, r.NewIK) && prev.NewKEM.Equal(r.NewKEM) {
			return true
		}
	}
	return false
}

// rotationConflict applies "One successor per key" (§3.4) with rule C's
// seen links (rotationConflictRec), recording a link not yet followed or
// seen as seen.
func (p *Peer) rotationConflict(c *Connection, r *handshake.Rotation, now time.Time) bool {
	return p.rotationConflictRec(c, r, true, now)
}

// suspend stops a connection after a rotation conflict: it is kept (the
// member may reconnect with a new invitation, which replaces it), but
// sends and accepts nothing, and its sign-ins and approvals cannot be
// answered.
func (p *Peer) suspend(c *Connection, now time.Time) {
	p.suspendFor(c, SuspendRotationConflict, now)
}

// suspendFor suspends a connection for a reason: rotation_conflict, or
// epoch for fork evidence (rule E, fork by ctx; RELEASE-29 §7).
func (p *Peer) suspendFor(c *Connection, reason string, now time.Time) {
	if c.State == StateSuspended {
		return
	}
	c.State = StateSuspended
	p.dropUndelivered(c, "undelivered_suspended", nil)
	p.dropConnOutgoing(c)
	p.abandonPending(c, "suspended", false, now)
	p.reconnectFailed(c) // ended by the suspension: no reconnect_failed
	for id, aw := range p.awaiting {
		if aw.ConnID == c.ID {
			p.dropAwaiting(id, now) // and revokes a pending reconnect's tokens
		}
	}
	p.markDirty(kindConn, c.ID)
	p.emit(&Event{Type: EventConnectionSuspended, ConnectionID: c.ID, Tag: c.Tag, Reason: reason}, now)
	switch reason {
	case SuspendEpoch:
		p.log().Error("fork evidence: connection suspended", "alarm", "fork_suspected", "connection_id", c.ID)
		return
	case SuspendRelayMoved:
		p.log().Error("a connection was moved by a relay.address.update before it was refused: suspended; the member must connect again",
			"alarm", "relay_moved_unlinked", "connection_id", c.ID)
		return
	}
	p.log().Error("member identity rotation conflict: connection suspended", "alarm", "rotate_conflict", "connection_id", c.ID)
}
