package peer

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Connection requests after their handshake (VAULT-MESSAGING 0.10.3,
// §6.3, §6.4, §7.1). The handshake runs before anyone approves; its epoch
// is established but not active. The connection becomes active when the
// service holds both its own approval and the member's
// connection.approved, which carries the standing and reconnect tokens.

// newRequest records a first-contact handshake whose hs.fin checked out:
// the service approves its own side at once, since its invitations are
// in person only (§6.4 "In-person invites"; the member always approves),
// and the application learns the SAS to show the member.
func (p *Peer) newRequest(aw *awaiting, fr *handshake.FinResult, now time.Time) {
	r := &request{ID: aw.ConnID, InviteID: aw.InviteID, Peer: *aw.New, SAS: fr.SAS, HeldRequest: aw.Held,
		Created: aw.Created, Expires: aw.Expires, ep: fr.Epoch}
	p.requests[r.ID] = r
	p.markDirty(kindRequest, r.ID)
	inv := p.invites[r.InviteID]
	tag := ""
	if inv != nil {
		inv.Status, inv.SAS, inv.ConnID = InviteSAS, r.SAS, r.ID
		tag = inv.Tag
		p.markDirty(kindInvite, inv.ID)
	}
	p.emit(&Event{Type: EventConnectionPending, ConnectionID: r.ID, InviteID: r.InviteID, SAS: r.SAS,
		Name: joinName(r.Peer.FirstName, r.Peer.LastName), Tag: tag}, now)
	// Remote invitations are never made (InviteTTL is the in-person TTL);
	// the check stays so that a change there cannot skip an approval.
	if invite.AutoApproveAllowed(inv == nil || invite.IsRemote(InviteTTL), false, true) {
		p.approveRequest(r, now)
	}
}

// approveRequest is the service's approval (§6.4, 0.10.3): the member's
// vault gets connection.approved with its standing and reconnect tokens,
// under the handshake's epoch, on the request token it issued; the
// connection activates if the member approved already.
func (p *Peer) approveRequest(r *request, now time.Time) {
	if r.Approved {
		return
	}
	tok, err := p.mintStanding(r.ID, &r.Peer, now)
	if err != nil {
		p.log().Warn("mint standing token", "connection_id", r.ID, "err", errCode(err))
		return
	}
	rt, err := p.mintReconnect(r.ID, &r.Peer, now)
	if err != nil {
		p.log().Warn("mint reconnect token", "connection_id", r.ID, "err", errCode(err))
		return
	}
	raw, err := r.ep.Seal(&envelope.Inner{ID: p.newID(now), Type: peerwire.TypeConnectionApproved, TS: now,
		Body: peerwire.ConnectionApprovedBody(tok, rt)})
	if err != nil {
		return
	}
	p.queueDeposit(&outboxEntry{ConnID: r.ID, Mailbox: r.Peer.Relay.Mailbox, Token: r.HeldRequest.Token, Payload: raw}, now)
	r.Approved = true
	r.Expires = r.Created.Add(ApprovedRetention) // §6.4 retention after approval
	p.markDirty(kindRequest, r.ID)
	p.log().Info("connection approved by the service", "connection_id", r.ID)
	if r.PeerApproved {
		p.activateRequest(r, now)
	}
}

// requestByKids finds the request whose established epoch this message
// is for, from the peer's relay key.
func (p *Peer) requestByKids(env *envelope.Envelope, sender ed25519.PublicKey) string {
	for id, r := range p.requests {
		if suite.EqualPublic(r.Peer.Relay.PK, sender) && env.RecipientKid().Equal(r.ep.RecvKid()) {
			return id
		}
	}
	return ""
}

// handleRequestMessage handles a message under a request's epoch before
// activation (§6.4 "Before activation"): connection.approved and
// connection.declined are processed; anything else is dropped before the
// service's approval and left unacked after it (the member may be active
// already, and its messages may overtake its connection.approved).
func (p *Peer) handleRequestMessage(id string, env *envelope.Envelope, now time.Time) disposition {
	r := p.requests[id]
	in, err := r.ep.Open(env)
	if err != nil {
		p.audit("decrypt_failed", id)
		return ackAfterFlush
	}
	p.markDirty(kindRequest, id) // the epoch's receive count moved
	if in.Type == handshake.TypeFin {
		return ackAfterFlush // a redelivered hs.fin
	}
	if in.Re == "" && (in.Type == peerwire.TypeConnectionApproved || in.Type == peerwire.TypeConnectionDeclined) {
		if err := in.CheckTime(now, true); err != nil {
			p.audit("stale_or_future", id)
			return ackAfterFlush
		}
		if in.Type == peerwire.TypeConnectionApproved {
			p.peerApproved(r, in, now)
		} else {
			p.peerDeclined(r, now)
		}
		return ackAfterFlush
	}
	if r.Approved {
		return noAck
	}
	p.audit("unapproved_peer", id)
	return ackAfterFlush
}

// handleOnRequestToken handles a deposit made on a request token we
// issued (§7.1): only hs.fin, connection.approved and connection.declined
// (the last also once the connection is active, 0.10.5) are accepted;
// relay.token.refresh is answered forbidden once active; anything else is
// dropped.
func (p *Peer) handleOnRequestToken(env *envelope.Envelope, raw []byte, sender ed25519.PublicKey, c *Connection, now time.Time) disposition {
	if env.Mode() == envelope.ModeSealed {
		p.audit("request_token_misuse", connID(c))
		return ackAfterFlush // the service initiates no first contact: no hs.resp is due on one
	}
	if id := p.awaitingByKids(env, sender); id != "" {
		return p.handleFin(id, raw, sender, now)
	}
	if id := p.requestByKids(env, sender); id != "" {
		return p.handleRequestMessage(id, env, now)
	}
	if c != nil && c.kr != nil {
		if in, _, err := c.kr.Open(env, now); err == nil && in.Re == "" {
			p.markDirty(kindConn, c.ID)
			switch {
			case in.Type == peerwire.TypeTokenRefresh:
				p.respondError(c, in, "forbidden", now)
				return ackAfterFlush
			case in.Type == peerwire.TypeConnectionDeclined && c.State == StateActive:
				// §6.4 "After activation" (0.10.5).
				if err := in.CheckTime(now, true); err != nil {
					p.audit("stale_or_future", c.ID)
					return ackAfterFlush
				}
				p.removeConnection(c, "in", now)
				return ackAfterFlush
			}
		}
	}
	p.audit("request_token_misuse", connID(c))
	return ackAfterFlush
}

// peerApproved handles the member's connection.approved (§6.4, §10.4):
// the standing and reconnect tokens for its mailbox.
func (p *Peer) peerApproved(r *request, in *envelope.Inner, now time.Time) {
	if r.PeerApproved {
		return
	}
	tok, rtok, err := peerwire.ParseConnectionApproved(in.Body)
	if err != nil {
		p.audit("bad_connection_approved", r.ID)
		return
	}
	st, err1 := p.heldToken(tok, &r.Peer)
	rt, err2 := p.heldToken(rtok, &r.Peer)
	if err1 != nil || err2 != nil {
		p.audit("bad_connection_approved", r.ID)
		return
	}
	r.Standing, r.Reconnect, r.PeerApproved = st, rt, true
	p.markDirty(kindRequest, r.ID)
	p.log().Info("connection approved by the member", "connection_id", r.ID)
	if r.Approved {
		p.activateRequest(r, now)
	}
}

// activateRequest makes an approved request an active connection (§6.3):
// the epoch becomes its first, counted from now (§6.5); the member's
// vault gets the service's profile (§10.8), and the application learns
// connection.added.
func (p *Peer) activateRequest(r *request, now time.Time) {
	delete(p.requests, r.ID)
	p.markDirty(kindRequest, r.ID)
	r.ep.MarkActivated(now)
	c := &Connection{ID: r.ID, State: StateActive, Peer: r.Peer, InviteID: r.InviteID, Standing: r.Standing,
		Reconnect: r.Reconnect, Created: r.Created, Activated: now, kr: &handshake.Keyring{}}
	if inv := p.invites[r.InviteID]; inv != nil {
		c.Tag = inv.Tag
	}
	p.replaceOlderConnections(c, now)
	p.conns[c.ID] = c
	p.installEpoch(c, r.ep, now)
	p.sendTo(c, peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(1, p.cfg.Profile.FirstName, p.cfg.Profile.LastName,
		p.cfg.Keys.IKPublic(), nil), now)
	p.endInvite(r.InviteID, InviteConnected, now)
	p.emit(&Event{Type: EventConnectionAdded, ConnectionID: c.ID, InviteID: c.InviteID, Name: c.Name(), Tag: c.Tag}, now)
}

// replaceOlderConnections drops other records of the same peer (same
// identity or relay key) when a fresh connection with it activates
// (§7.4 "Connecting again after a removal"), without a notice.
func (p *Peer) replaceOlderConnections(n *Connection, now time.Time) {
	for _, o := range p.conns {
		if o.ID == n.ID || !(suite.EqualPublic(o.Peer.IK, n.Peer.IK) || suite.EqualPublic(o.Peer.Relay.PK, n.Peer.Relay.PK)) {
			continue
		}
		o.State = StateStale
		p.removeConnection(o, "replaced", now)
	}
}

// peerDeclined handles the member's connection.declined before
// activation (§6.4, 0.10.5): the request ends as a drop.
func (p *Peer) peerDeclined(r *request, now time.Time) {
	p.dropRequest(r, now)
	p.endInvite(r.InviteID, InviteDeclined, now)
	p.emit(&Event{Type: EventConnectionDeclined, ConnectionID: r.ID, InviteID: r.InviteID}, now)
}

// dropRequest ends a request without activation (§7.4): every token the
// service issued to the member is denylisted and the handshake state
// deleted.
func (p *Peer) dropRequest(r *request, now time.Time) {
	r.ep.Destroy()
	delete(p.requests, r.ID)
	p.markDirty(kindRequest, r.ID)
	p.denyConnTokens(r.ID, now)
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == r.ID && e.Op == opDeposit })
}

// endInvite records an invitation's outcome.
func (p *Peer) endInvite(id, status string, now time.Time) {
	inv := p.invites[id]
	if inv == nil || !inv.Ended.IsZero() {
		return
	}
	inv.Status, inv.Ended = status, now
	if status != InviteConnected {
		inv.SAS = ""
	}
	p.markDirty(kindInvite, id)
}

// expireRequests drops first-contact handshakes and requests past their
// expiry (§6.4 "Request expiry and retention").
func (p *Peer) expireRequests(now time.Time) {
	for id, aw := range p.awaiting {
		if !now.Before(aw.Expires) {
			p.dropAwaiting(id, now)
		}
	}
	for _, r := range p.requests {
		if now.Before(r.Expires) {
			continue
		}
		p.dropRequest(r, now)
		p.endInvite(r.InviteID, InviteExpired, now)
		p.emit(&Event{Type: EventConnectionExpired, ConnectionID: r.ID, InviteID: r.InviteID}, now)
	}
	for id, og := range p.outgoing {
		if now.Sub(og.Created) > HandshakeTTL {
			p.dropOutgoing(id)
		}
	}
}
