package peer

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
	if err != nil {
		p.audit("bad_rotation", c.ID)
		return
	}
	p.followRotation(c, final, kem, []*handshake.Rotation{r})
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
	p.markDirty(kindConn, c.ID)
	p.log().Info("member identity rotated", "connection_id", c.ID)
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
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID })
	p.dropConnOutgoing(c)
	for id, aw := range p.awaiting {
		if aw.ConnID == c.ID {
			aw.r.Abort()
			delete(p.awaiting, id)
			p.markDirty(kindAwait, id)
		}
	}
	p.markDirty(kindConn, c.ID)
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
