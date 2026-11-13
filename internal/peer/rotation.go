package peer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
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
// rotation conflict, the only one so far.
const SuspendRotationConflict = "rotation_conflict"

// identityRotate follows one link of the member's rotation chain (§3.4):
// both signatures, old_ik the stored key, and one successor per key. The
// member's vault rekeys next (§3.4 step 3), under the new key.
func (p *Peer) identityRotate(c *Connection, body []byte, now time.Time) {
	var b struct {
		Rotation json.RawMessage `json:"rotation"`
	}
	if json.Unmarshal(body, &b) != nil || len(b.Rotation) == 0 {
		p.audit("bad_rotation", c.ID)
		return
	}
	r, err := handshake.ParseRotation(b.Rotation)
	if err != nil || r.Verify() != nil {
		p.audit("bad_rotation", c.ID)
		return
	}
	if p.rotationConflict(c, r, now) {
		return
	}
	if p.knownSuccessor(c, r) {
		return // the same statement again
	}
	final, kem, err := handshake.ResolveChain(c.Peer.IK, []*handshake.Rotation{r})
	if err != nil || p.revisits(c, []*handshake.Rotation{r}) {
		p.audit("bad_rotation", c.ID)
		return
	}
	p.followRotation(c, final, kem, []*handshake.Rotation{r}, true)
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
// and its new keys. restart is set when the links came in an
// identity.rotate: only then is an open reconnect of ours started again
// (a handshake's own links make the change it completes).
func (p *Peer) followRotation(c *Connection, ik ed25519.PublicKey, kem *suite.PublicKey, links []*handshake.Rotation, restart bool) {
	c.Peer.IK = ik
	if kem != nil {
		c.Peer.KEM = kem.Bytes()
	}
	for _, r := range links {
		c.Chain = append(c.Chain, r.Marshal())
	}
	if len(c.Chain) > handshake.MaxRotations {
		// Only the last links matter for one-successor checks of keys
		// still in use; the chain a peer may send is at most this long.
		c.Chain = c.Chain[len(c.Chain)-handshake.MaxRotations:]
	}
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
	if ownTry && c.State != StateSuspended && !suite.EqualPublic(c.ReconnectRestartIK, ik) {
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
func (p *Peer) followAtFin(c *Connection, f *pendingFollow, now time.Time) bool {
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
		p.followRotation(c, ik, kem, fresh, false)
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

// rotationConflict applies "One successor per key" (§3.4): a valid link
// whose old_ik already has a different accepted successor suspends the
// connection.
func (p *Peer) rotationConflict(c *Connection, r *handshake.Rotation, now time.Time) bool {
	for _, raw := range c.Chain {
		prev, err := handshake.ParseRotation(raw)
		if err != nil || !suite.EqualPublic(prev.OldIK, r.OldIK) || suite.EqualPublic(prev.NewIK, r.NewIK) {
			continue
		}
		p.suspend(c, now)
		return true
	}
	return false
}

// suspend stops a connection after a rotation conflict: it is kept (the
// member may reconnect with a new invitation, which replaces it), but
// sends and accepts nothing, and its sign-ins and approvals cannot be
// answered.
func (p *Peer) suspend(c *Connection, now time.Time) {
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
	p.emit(&Event{Type: EventConnectionSuspended, ConnectionID: c.ID, Tag: c.Tag, Reason: SuspendRotationConflict}, now)
	p.log().Error("member identity rotation conflict: connection suspended", "alarm", "rotate_conflict", "connection_id", c.ID)
}
