package peer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// A member's vault rotates its keys at a transfer to a new phone, a
// recovery and a credential.rotate (VAULT-MESSAGING §3.4, 0.68.0): its
// relay key (relay.address.update), its identity and KEM keys
// (identity.rotate, then a rekey), and its credential key
// (connection.authenticate.rotated, connauth.go). The service follows
// each, as the member vault follows a peer's, so that a connection
// survives the member moving phones.

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

// PrevRelayGrace bounds how long the member's previous relay key is still
// recognized as the connection's after a relay.address.update: deposits
// made before the rotation, and resends of the update itself (§3.4 (b)),
// arrive with it. The grace ends earlier, at the first message from the
// new key: deposits to one mailbox stay in order (§8.3), so nothing from
// before the rotation is still to come; the tokens issued to the old key
// are then revoked. A second rotation within the grace replaces the
// previous key (the first one's late deposits are then dropped).
const PrevRelayGrace = 30 * 24 * time.Hour

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
	p.followRotation(c, final, kem, []*handshake.Rotation{r})
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
// and its new keys.
func (p *Peer) followRotation(c *Connection, ik ed25519.PublicKey, kem *suite.PublicKey, links []*handshake.Rotation) {
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
	p.dropConnOutgoing(c)
	p.dropStaleAnswers(c)
	p.markDirty(kindConn, c.ID)
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
		p.followRotation(c, ik, kem, fresh)
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
	for id, aw := range p.awaiting {
		if aw.ConnID == c.ID {
			p.dropAwaiting(id, now) // and revokes a pending reconnect's tokens
		}
	}
	p.markDirty(kindConn, c.ID)
	p.emit(&Event{Type: EventConnectionSuspended, ConnectionID: c.ID, Tag: c.Tag, Reason: SuspendRotationConflict}, now)
	p.log().Error("member identity rotation conflict: connection suspended", "alarm", "rotate_conflict", "connection_id", c.ID)
}

// relayAddressUpdate records the member's new relay address and the
// tokens for it after the member rotated its relay key (§3.4), and
// answers with fresh tokens for the new key (relay.token.issued), which
// is the member's signal that the service has the new address. The
// previous key stays recognized for PrevRelayGrace.
//
// Only the current key may move the connection: from the previous key,
// in its grace, a resend of the update already applied is ignored and
// anything else is refused, so an exposed old key can neither move the
// connection nor roll it back.
func (p *Peer) relayAddressUpdate(c *Connection, sender ed25519.PublicKey, body []byte, now time.Time) {
	var b struct {
		Relay struct {
			URL     string `json:"url"`
			Mailbox string `json:"mailbox"`
			PK      string `json:"pk"`
		} `json:"relay"`
		Token          string `json:"token"`
		ReconnectToken string `json:"reconnect_token"`
	}
	if json.Unmarshal(body, &b) != nil {
		p.audit("bad_address_update", c.ID)
		return
	}
	pk, err := base64.StdEncoding.DecodeString(b.Relay.PK)
	if err != nil || len(pk) != ed25519.PublicKeySize {
		p.audit("bad_address_update", c.ID)
		return
	}
	a := handshake.RelayAddr{URL: strings.TrimRight(b.Relay.URL, "/"), Mailbox: b.Relay.Mailbox, PK: pk}
	if handshake.ValidateRelayAddr(a) != nil {
		p.audit("bad_address_update", c.ID)
		return
	}
	if a.URL != p.cfg.RelayURL {
		// As at first contact: the service deposits only on its own relay
		// (chosen; not in the spec).
		p.audit("address_update_other_relay", c.ID)
		return
	}
	if suite.EqualPublic(pk, c.Peer.Relay.PK) {
		return // a resend of the update we have (§3.4 (b))
	}
	if !suite.EqualPublic(sender, c.Peer.Relay.PK) {
		p.audit("address_update_from_old_key", c.ID)
		return
	}
	if o := p.connByRelayKey(pk, now); o != nil && o != c {
		p.audit("address_update_key_in_use", c.ID)
		return
	}
	np := c.Peer
	np.Relay = RelayRef{URL: a.URL, Mailbox: a.Mailbox, PK: pk}
	st, err := p.heldToken(b.Token, &np)
	if err != nil {
		p.audit("bad_address_update", c.ID)
		return
	}
	var rt HeldToken
	if b.ReconnectToken != "" {
		if rt, err = p.heldToken(b.ReconnectToken, &np); err != nil {
			p.audit("bad_address_update", c.ID)
			return
		}
	}
	if len(c.PrevRelayPK) > 0 {
		p.endRelayGrace(c, now) // a second rotation: the first key's tokens go
	}
	c.PrevRelayPK, c.PrevRelayUntil = c.Peer.Relay.PK, now.Add(PrevRelayGrace)
	c.Peer.Relay = np.Relay
	c.Standing, c.RefreshID, c.RefreshAfter = st, "", time.Time{}
	if rt.Token != "" {
		c.Reconnect = rt
	}
	// Our queued deposits on the standing token still address the old
	// mailbox: retarget them (a deposit on a token of its own keeps it).
	for _, e := range p.outbox {
		if e.Op == opDeposit && e.ConnID == c.ID && e.Token == "" {
			e.Mailbox = a.Mailbox
			p.markDirty(kindOutbox, e.ID)
		}
	}
	p.markDirty(kindConn, c.ID)
	p.log().Info("member relay address updated", "connection_id", c.ID)
	// Tokens we issued for the old key stop at the relay's grace; issue
	// fresh ones for the new key, which also acknowledges the update.
	p.dropConnOutgoing(c)
	p.issueTo(c, tokStanding, now)
	p.issueTo(c, tokReconnect, now)
	p.retryConn(c.ID)
}

// endRelayGrace forgets the member's previous relay key and revokes the
// tokens issued to it (the member vault denylists the old sub the same
// way).
func (p *Peer) endRelayGrace(c *Connection, now time.Time) {
	if len(c.PrevRelayPK) == 0 {
		return
	}
	sub := relayauth.EncodeKey(c.PrevRelayPK)
	for _, t := range p.issued {
		if t.ConnID == c.ID && t.Sub == sub && !t.Denied {
			t.Denied = true
			p.markDirty(kindToken, t.JTI)
			p.queueRevoke(t.JTI, now)
		}
	}
	c.PrevRelayPK, c.PrevRelayUntil = nil, time.Time{}
	p.markDirty(kindConn, c.ID)
}

// noteSender ends the previous key's grace at the first message from the
// current key, and when it runs out.
func (p *Peer) noteSender(c *Connection, sender ed25519.PublicKey, now time.Time) {
	if len(c.PrevRelayPK) > 0 && (suite.EqualPublic(sender, c.Peer.Relay.PK) || !now.Before(c.PrevRelayUntil)) {
		p.endRelayGrace(c, now)
	}
}

// relayKeyIs reports whether pk is the connection's relay key, or its
// previous one within PrevRelayGrace.
func (c *Connection) relayKeyIs(pk ed25519.PublicKey, now time.Time) bool {
	return suite.EqualPublic(c.Peer.Relay.PK, pk) ||
		(len(c.PrevRelayPK) > 0 && now.Before(c.PrevRelayUntil) && suite.EqualPublic(c.PrevRelayPK, pk))
}
