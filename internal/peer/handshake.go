package peer

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Handshake and request time limits (§6.4, 0.10.2, 0.10.3), as the
// member vault has them.
const (
	ConnectionPending = 7 * 24 * time.Hour  // an incoming request neither approved nor declined
	ApprovedRetention = 16 * 24 * time.Hour // an approved request awaiting the member's approval
	HandshakeTTL      = 16 * 24 * time.Hour // rekeys and reconnects awaiting hs.resp / hs.fin
	MaxRequests       = 256                 // incoming connection requests (§10.4)
)

func (p *Peer) lookupKEM(kid suite.Kid) *suite.PrivateKey {
	if kid.Equal(p.cfg.Keys.KEM.Public().Kid()) {
		return p.cfg.Keys.KEM
	}
	return nil
}

func infoFromPrincipal(pr handshake.Principal) *peerInfo {
	return &peerInfo{IK: pr.IK, KEM: pr.KEM.Bytes(),
		Relay: RelayRef{URL: strings.TrimRight(pr.Relay.URL, "/"), Mailbox: pr.Relay.Mailbox, PK: pr.Relay.PK}}
}

// handleInit processes a sealed hs.init addressed to the service's static
// KEM key (§6.1): first contact on an invitation's open token, or a
// reconnect (§6.6). It applies the member vault's checks for a
// connection inviter (§6.3, §6.4, §10.4).
func (p *Peer) handleInit(raw []byte, sender ed25519.PublicKey, c *Connection, onReconnectToken bool, now time.Time) disposition {
	pi, err := handshake.OpenInit(raw, p.lookupKEM, now)
	if err != nil {
		p.audit("hs_init_rejected", connID(c))
		return ackAfterFlush
	}
	body := pi.Init()
	if onReconnectToken {
		if err := handshake.CheckReconnectTokenUse(envelope.ModeSealed, pi); err != nil {
			p.audit("reconnect_token_misuse", connID(c))
			pi.Discard()
			return ackAfterFlush
		}
	}
	if !suite.EqualPublic(sender, body.From.Relay.PK) { // §6.3
		p.audit("hs_init_sender_mismatch", connID(c))
		pi.Discard()
		return ackAfterFlush
	}
	if body.Purpose == handshake.PurposeReconnect {
		if c == nil {
			p.audit("reconnect_unknown_peer", "")
			pi.Discard()
			return ackAfterFlush
		}
		p.respondReconnect(pi, c, sender, now)
		return ackAfterFlush
	}
	if body.Purpose != handshake.PurposeConnection {
		p.audit("hs_init_purpose", "")
		pi.Discard()
		return ackAfterFlush
	}
	if c != nil && c.State != StateStale {
		// A stale connection may be made afresh through a new invitation;
		// the new record replaces it at activation (§7.4).
		p.audit("hs_init_from_known_peer", c.ID)
		pi.Discard()
		return ackAfterFlush
	}
	if k := p.knownIdentity(body.From.IK); k != nil { // §6.4 "The inviter's drop"
		p.audit("hs_init_from_known_peer", k.ID)
		pi.Discard()
		return ackAfterFlush
	}
	if strings.TrimRight(body.From.Relay.URL, "/") != p.cfg.RelayURL {
		// The service deposits only on its own relay (chosen; not in the
		// spec): member vaults use the VettID relay.
		p.audit("hs_init_other_relay", "")
		pi.Discard()
		return ackAfterFlush
	}
	inv := p.invites[body.Ctx]
	if inv == nil || inv.Used || inv.Withdrew || !now.Before(inv.Exp) {
		p.audit("invite_invalid", "")
		pi.Discard()
		return ackAfterFlush // single use; expired, used or revoked invites are rejected (§6.4)
	}
	if !peerwire.ValidHandshakeProfile(body.Profile) { // §6.2 (0.18.0)
		p.audit("profile_malformed", "")
		pi.Discard()
		return ackAfterFlush
	}
	if p.countRequests() >= MaxRequests { // §10.4
		p.audit("request_limit", "")
		pi.Discard()
		return ackAfterFlush
	}
	inv.Used = true
	p.withdrawInvite(inv, now)
	p.respondFirst(pi, inv, sender, now)
	return ackAfterFlush
}

// knownIdentity returns the connection, not stale, whose identity key is
// ik (§6.4 "The inviter's drop").
func (p *Peer) knownIdentity(ik []byte) *Connection {
	for _, c := range p.conns {
		if c.State != StateStale && suite.EqualPublic(c.Peer.IK, ik) {
			return c
		}
	}
	return nil
}

// countRequests counts incoming connection requests, those whose
// handshake still runs included (§10.4).
func (p *Peer) countRequests() int {
	n := len(p.requests)
	for _, aw := range p.awaiting {
		if aw.New != nil {
			n++
		}
	}
	return n
}

// profileNames returns the core names of a connection hs.init's profile
// (§6.2), checked by peerwire.ValidHandshakeProfile.
func profileNames(raw json.RawMessage) (first, last string) {
	var n struct {
		First string `json:"first_name"`
		Last  string `json:"last_name"`
	}
	if json.Unmarshal(raw, &n) != nil {
		return "", ""
	}
	return n.First, n.Last
}

// respondFirst answers a first-contact hs.init at once (§6.4, 0.10.3):
// hs.resp carries a request token; the SAS exists after hs.fin.
func (p *Peer) respondFirst(pi *handshake.PendingInit, inv *InviteRecord, sender ed25519.PublicKey, now time.Time) {
	body := pi.Init()
	np := infoFromPrincipal(body.From)
	np.FirstName, np.LastName = profileNames(body.Profile)
	id := p.newID(now)
	held, err := p.heldToken(body.Token, np)
	if err != nil {
		p.audit("hs_init_bad_token", "")
		pi.Discard()
		return
	}
	tok, err := p.mintRequest(id, np, now)
	if err != nil {
		p.log().Warn("mint request token", "err", errCode(err))
		pi.Discard()
		return
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{Identity: p.cfg.Keys.IK, Token: tok,
		Policy: handshake.PolicyVaultToVault, CollectSender: sender, Now: now})
	if err != nil {
		p.audit("respond_failed", "")
		p.denyConnTokens(id, now)
		return
	}
	aw := &awaiting{ID: id, ConnID: id, New: np, Purpose: handshake.PurposeConnection, InviteID: inv.ID, Held: held,
		Created: now, Expires: now.Add(ConnectionPending), r: resp}
	p.awaiting[id] = aw
	p.markDirty(kindAwait, id)
	p.queueDeposit(&outboxEntry{ConnID: id, Mailbox: np.Relay.Mailbox, Token: body.Token, Payload: env}, now)
	p.log().Info("hs.resp", "connection_id", id, "invite_id", inv.ID)
}

// respondReconnect answers a reconnect hs.init (§6.6): no SAS or
// approval; the sender must be the relay key on record, from.ik the
// stored ik, and ctx the last epoch's id. The service has no identity
// rotations of its own, and follows none of the peer's (an hs.init with
// rotations is refused by Respond against the stored key unless it
// resolves; the record then keeps the stored key).
func (p *Peer) respondReconnect(pi *handshake.PendingInit, c *Connection, sender ed25519.PublicKey, now time.Time) {
	if len(c.LastEpochID) == 0 {
		pi.Discard()
		return
	}
	var eid [suite.EpochIDSize]byte
	copy(eid[:], c.LastEpochID)
	cfg := handshake.ResponderConfig{
		Identity: p.cfg.Keys.IK, Policy: handshake.PolicyVaultToVault, PinnedSuite: c.Suite,
		CollectSender: sender, RecordRelayKey: c.Peer.Relay.PK, KnownInitiatorIK: c.Peer.IK,
		ExpectedCtx: handshake.EpochCtx(eid), Now: now,
	}
	body := pi.Init()
	if len(body.Rotations) > 0 {
		p.audit("reconnect_rotation_unsupported", c.ID)
		pi.Discard()
		return
	}
	st, err1 := p.heldToken(body.Token, &c.Peer)
	rt, err2 := p.heldToken(body.ReconnectToken, &c.Peer)
	if err1 != nil || err2 != nil {
		p.audit("reconnect_bad_token", c.ID)
		pi.Discard()
		return
	}
	var err error
	if cfg.Token, err = p.mintStanding(c.ID, &c.Peer, now); err != nil {
		pi.Discard()
		return
	}
	if cfg.ReconnectToken, err = p.mintReconnect(c.ID, &c.Peer, now); err != nil {
		pi.Discard()
		return
	}
	resp, env, err := pi.Respond(cfg)
	if err != nil {
		p.audit("reconnect_refused", c.ID)
		return
	}
	c.Standing, c.Reconnect = st, rt
	c.State = StateActive
	p.markDirty(kindConn, c.ID)
	id := p.newID(now)
	p.awaiting[id] = &awaiting{ID: id, ConnID: c.ID, Purpose: handshake.PurposeReconnect, Created: now,
		Expires: now.Add(HandshakeTTL), r: resp}
	p.markDirty(kindAwait, id)
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: env}, now)
	p.retryConn(c.ID)
}

// handleRekeyInit handles a rekey hs.init that arrived in session mode
// (§6.2, §6.5).
func (p *Peer) handleRekeyInit(c *Connection, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	if c.kr == nil || c.kr.Current() != ep {
		p.audit("rekey_not_current_epoch", c.ID)
		return ackAfterFlush
	}
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		p.audit("rekey_rejected", c.ID)
		return ackAfterFlush
	}
	// Crossing rekeys: the lower th1 wins (§6.5).
	for id, og := range p.outgoing {
		if og.ConnID != c.ID {
			continue
		}
		var ours [32]byte
		copy(ours[:], og.Th1)
		if handshake.SimultaneousRekeyWinner(ours, pi.Th1()) {
			pi.Discard()
			return ackAfterFlush
		}
		p.dropOutgoing(id)
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{
		Identity: p.cfg.Keys.IK, Policy: handshake.PolicyVaultToVault, PinnedSuite: c.Suite,
		CollectSender: sender, RecordRelayKey: c.Peer.Relay.PK, KnownInitiatorIK: c.Peer.IK, Now: now,
	})
	if err != nil {
		p.audit("rekey_refused", c.ID)
		return ackAfterFlush
	}
	id := p.newID(now)
	p.awaiting[id] = &awaiting{ID: id, ConnID: c.ID, Purpose: handshake.PurposeRekey, Created: now,
		Expires: now.Add(HandshakeTTL), r: resp}
	p.markDirty(kindAwait, id)
	p.markDirty(kindConn, c.ID) // the epoch's receive count moved
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: env}, now)
	p.log().Info("rekey answered", "connection_id", c.ID)
	return ackAfterFlush
}

// awaitingByKids finds the handshake awaiting this hs.fin by its new
// epoch's kids and the expected sender.
func (p *Peer) awaitingByKids(env *envelope.Envelope, sender ed25519.PublicKey) string {
	for id, aw := range p.awaiting {
		rk, sk := aw.r.Kids()
		if !env.RecipientKid().Equal(rk) || !env.SenderKid().Equal(sk) {
			continue
		}
		var pk []byte
		if aw.New != nil {
			pk = aw.New.Relay.PK
		} else if c := p.conns[aw.ConnID]; c != nil {
			pk = c.Peer.Relay.PK
		}
		if suite.EqualPublic(pk, sender) {
			return id
		}
	}
	return ""
}

// handleFin completes a handshake the service answered (§6.3). A bad
// hs.fin is dropped and the handshake stays pending until it expires; a
// commitment mismatch aborts it. Rekeys and reconnects become active at
// once; a first contact becomes a request (0.10.3).
func (p *Peer) handleFin(id string, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	aw := p.awaiting[id]
	fr, err := aw.r.HandleFin(raw, sender, now)
	switch {
	case errors.Is(err, handshake.ErrType):
		// A message in the new epoch that arrived before hs.fin: leave it
		// for redelivery (§6.5).
		return noAck
	case errors.Is(err, handshake.ErrSASCommit):
		p.audit("sas_commit_mismatch", aw.ConnID)
		p.dropAwaiting(id, now)
		return ackAfterFlush
	case err != nil:
		p.audit("hs_fin_rejected", aw.ConnID)
		return ackAfterFlush
	}
	delete(p.awaiting, id)
	p.markDirty(kindAwait, id)
	if aw.New != nil {
		p.newRequest(aw, fr, now)
		return ackAfterFlush
	}
	c := p.conns[aw.ConnID]
	if c == nil {
		fr.Epoch.Destroy()
		return ackAfterFlush
	}
	p.installEpoch(c, fr.Epoch, now)
	p.log().Info("epoch installed", "connection_id", c.ID, "purpose", string(aw.Purpose))
	return ackAfterFlush
}

// installEpoch makes ep the connection's current epoch; the previous
// send key and rk are deleted at once, its receive key kept (§6.5).
func (p *Peer) installEpoch(c *Connection, ep *handshake.Epoch, now time.Time) {
	if c.kr == nil {
		c.kr = &handshake.Keyring{}
	}
	c.kr.Activate(ep, now)
	eid := ep.ID()
	c.LastEpochID = eid[:]
	if ep.Suite() > c.Suite {
		c.Suite = ep.Suite() // §13.4 pin
	}
	p.markDirty(kindConn, c.ID)
	p.retryConn(c.ID)
}

// dropAwaiting ends a first-contact handshake that has not completed:
// the tokens minted for it are denylisted (§7.4).
func (p *Peer) dropAwaiting(id string, now time.Time) {
	aw := p.awaiting[id]
	if aw == nil {
		return
	}
	if aw.New != nil {
		p.denyConnTokens(aw.ConnID, now)
		p.endInvite(aw.InviteID, InviteExpired, now)
	}
	aw.r.Abort()
	delete(p.awaiting, id)
	p.markDirty(kindAwait, id)
}

// startRekey initiates a rekey of a connection's session when its epoch
// reached the vault-to-vault limit (§6.5: the side that hits the limit
// initiates).
func (p *Peer) startRekey(c *Connection, now time.Time) {
	if c.kr == nil || c.kr.Current() == nil || c.Standing.Token == "" || c.State != StateActive {
		return
	}
	for _, og := range p.outgoing {
		if og.ConnID == c.ID {
			return
		}
	}
	for _, aw := range p.awaiting {
		if aw.ConnID == c.ID && aw.Purpose == handshake.PurposeRekey {
			return // the member's rekey is in flight
		}
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: p.cfg.Keys.IK, StaticKEM: p.cfg.Keys.KEM.Public(), Relay: p.ownAddr(),
		ResponderIK: c.Peer.IK, ResponderRelayKey: c.Peer.Relay.PK, Current: c.kr.Current(), PinnedSuite: c.Suite,
		Policy: handshake.PolicyVaultToVault, Now: now,
	})
	if err != nil {
		return
	}
	s, err := ini.Export()
	if err != nil {
		return
	}
	id := p.newID(now)
	kid, th1 := ini.EphKid(), ini.Th1()
	p.outgoing[id] = &outgoing{ID: id, ConnID: c.ID, EphKid: kid[:], Th1: th1[:], Init: s, Created: now, ini: ini}
	p.markDirty(kindOutgoing, id)
	p.markDirty(kindConn, c.ID) // the epoch's send count moved
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: ini.Envelope()}, now)
	p.log().Info("rekey started", "connection_id", c.ID)
}

// handleResp processes hs.resp for a rekey the service initiated: hs.fin
// goes out in the new epoch, which becomes current at once.
func (p *Peer) handleResp(id string, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	og := p.outgoing[id]
	res, err := og.ini.HandleResp(raw, sender, now)
	if err != nil {
		if _, xerr := og.ini.Export(); errors.Is(xerr, handshake.ErrDone) {
			p.audit("hs_resp_aborted", og.ConnID)
			p.dropOutgoing(id)
		} else {
			p.audit("hs_resp_dropped", og.ConnID)
		}
		return ackAfterFlush
	}
	delete(p.outgoing, id)
	p.markDirty(kindOutgoing, id)
	c := p.conns[og.ConnID]
	if c == nil {
		res.Epoch.Destroy()
		return ackAfterFlush
	}
	// hs.fin goes first; what follows is sealed in the new epoch.
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: res.Fin}, now)
	p.installEpoch(c, res.Epoch, now)
	p.log().Info("rekeyed", "connection_id", c.ID)
	return ackAfterFlush
}

func (p *Peer) dropOutgoing(id string) {
	if og := p.outgoing[id]; og != nil && og.ini != nil {
		og.ini.Abort()
	}
	delete(p.outgoing, id)
	p.markDirty(kindOutgoing, id)
}
