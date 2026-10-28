package peer

import (
	"bytes"
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
// jti is the collect jti: a first contact must come on its invitation's
// own open token.
func (p *Peer) handleInit(raw []byte, sender ed25519.PublicKey, c *Connection, onReconnectToken bool, jti string, now time.Time) disposition {
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
	if c != nil && c.State != StateStale && c.State != StateSuspended {
		// A stale or suspended connection may be made afresh through a new
		// invitation; the new record replaces it at activation (§7.4).
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
	if inv == nil || inv.Used || inv.Withdrew || !now.Before(inv.Exp) || jti == "" || jti != inv.OpenJTI {
		// The open token deposited with must be the invitation's own: an
		// invitation id with another invitation's token does not redeem it.
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

// knownIdentity returns the connection, not stale or suspended, whose
// identity key is ik (§6.4 "The inviter's drop").
func (p *Peer) knownIdentity(ik []byte) *Connection {
	for _, c := range p.conns {
		if c.State != StateStale && c.State != StateSuspended && suite.EqualPublic(c.Peer.IK, ik) {
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
// stored ik or reached from it by the hs.init's rotation chain (the
// member rotated while the session was down, §3.4), and ctx the last
// epoch's id: a service vault answering a member keeps the exact match
// (§6.6, 0.72.0). It changes nothing until sig_I verifies at hs.fin; the
// answer is all that is sent before. The service has no rotations of its
// own.
func (p *Peer) respondReconnect(pi *handshake.PendingInit, c *Connection, sender ed25519.PublicKey, now time.Time) {
	if len(c.LastEpochID) == 0 || c.State == StateSuspended {
		p.audit("reconnect_refused", c.ID)
		pi.Discard()
		return
	}
	if !suite.EqualPublic(sender, c.Peer.Relay.PK) {
		// Only the relay key on record may reconnect (§6.6); the previous
		// one's grace after a relay.address.update is for messages, and
		// must not let it suspend the connection below.
		p.audit("reconnect_sender", c.ID)
		pi.Discard()
		return
	}
	var eid [suite.EpochIDSize]byte
	copy(eid[:], c.LastEpochID)
	body := pi.Init()
	// A valid link that gives a key a second successor suspends the
	// connection (§3.4), whatever else the hs.init carries: such a chain
	// could never be accepted, and the conflict must not go unnoticed.
	for _, r := range body.Rotations {
		if r.Verify() == nil && p.rotationConflict(c, r, now) {
			pi.Discard()
			return
		}
	}
	// The member's vault sends every rotation since its last epoch: links
	// the service already followed (identity.rotate arrived, the rekey did
	// not) come first, and the chain is then checked from the first one's
	// old key, provided those links lead to the stored key.
	start, fresh := c.Peer.IK, body.Rotations
	known := 0
	for known < len(body.Rotations) && p.knownSuccessor(c, body.Rotations[known]) {
		known++
	}
	if known > 0 {
		if !suite.EqualPublic(body.Rotations[known-1].NewIK, c.Peer.IK) {
			p.audit("reconnect_rotation_behind", c.ID) // would roll the identity back
			pi.Discard()
			return
		}
		start, fresh = body.Rotations[0].OldIK, body.Rotations[known:]
	}
	cfg := handshake.ResponderConfig{
		Identity: p.cfg.Keys.IK, Policy: handshake.PolicyVaultToVault, PinnedSuite: c.Suite,
		CollectSender: sender, RecordRelayKey: c.Peer.Relay.PK, KnownInitiatorIK: start,
		ExpectedCtx: handshake.EpochCtx(eid), Now: now,
	}
	st, err1 := p.heldToken(body.Token, &c.Peer)
	rt, err2 := p.heldToken(body.ReconnectToken, &c.Peer)
	if err1 != nil || err2 != nil {
		p.audit("reconnect_bad_token", c.ID)
		pi.Discard()
		return
	}
	if !p.admitHandshake(c.ID, handshake.PurposeReconnect, pi.Th1()) {
		pi.Discard()
		return
	}
	var jtis []string
	var err error
	if cfg.Token, cfg.ReconnectToken, jtis, err = p.mintReconnectPair(c.ID, &c.Peer, now); err != nil {
		pi.Discard()
		return
	}
	resp, env, err := pi.Respond(cfg) // checks the sender, the ctx and the chain
	if err != nil {
		p.audit("reconnect_refused", c.ID)
		for _, j := range jtis {
			p.denyJTI(j, now)
		}
		return
	}
	p.mark(kindInner, reconnectKey(pi.Th1()), []byte{1}, now.Add(DedupeRetention+envelope.MaxClockSkewFuture))
	if c.Reconnecting {
		// Crossing reconnects (§6.6, 0.72.1): ours yields to the member's,
		// which names our last epoch. Ours is abandoned (no hs.fin; a
		// later hs.resp to it is dropped; an hs.init not yet deposited
		// is not), and the reconnect stays open until the member's
		// hs.fin, or YieldWait.
		for id, og := range p.outgoing {
			if og.ConnID == c.ID && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
				og.ini.Abort()
				for _, j := range og.Issued {
					p.denyJTI(j, now)
				}
				delete(p.outgoing, id)
				p.markDirty(kindOutgoing, id)
			}
		}
		p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID && e.Token != "" && e.Token == c.Reconnect.Token })
	}
	pend := &pendingReconnect{Standing: st, Reconnect: rt, Issued: jtis}
	if len(fresh) > 0 {
		pend.IK, pend.KEM = body.From.IK, body.From.KEM.Bytes()
		for _, r := range fresh {
			pend.Links = append(pend.Links, r.Marshal())
		}
	}
	id := p.newID(now)
	th1 := pi.Th1()
	exp := now.Add(HandshakeTTL)
	if c.Reconnecting {
		exp = now.Add(YieldWait)
	}
	p.awaiting[id] = &awaiting{ID: id, ConnID: c.ID, Purpose: handshake.PurposeReconnect, Th1: th1[:], Created: now,
		Expires: exp, Reconnect: pend, r: resp}
	p.markDirty(kindAwait, id)
	// On the standing token the hs.init brought: ours may have expired.
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Token: st.Token, Payload: env}, now)
}

// applyReconnect applies a member's reconnect once its hs.fin verified.
// A reconnect of ours still open is settled by it: the session is
// common again.
func (p *Peer) applyReconnect(c *Connection, pend *pendingReconnect) error {
	var links []*handshake.Rotation
	var kem *suite.PublicKey
	if len(pend.Links) > 0 {
		for _, raw := range pend.Links {
			r, err := handshake.ParseRotation(raw)
			if err != nil {
				return err
			}
			links = append(links, r)
		}
		var err error
		if kem, err = suite.ParsePublicKey(pend.KEM); err != nil {
			return err
		}
	}
	if c.Reconnecting {
		c.Reconnecting, c.ReconnectTries, c.ReconnectSlow, c.ReconnectSince = false, 0, false, time.Time{}
		p.dropConnOutgoing(c)
	}
	if len(links) > 0 {
		p.followRotation(c, pend.IK, kem, links)
	}
	c.Standing, c.Reconnect = pend.Standing, pend.Reconnect
	c.State = StateActive
	p.markDirty(kindConn, c.ID)
	return nil
}

// handleRekeyInit handles a rekey hs.init that arrived in session mode
// (§6.2, §6.5).
func (p *Peer) handleRekeyInit(c *Connection, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, now time.Time) disposition {
	if c.kr == nil || c.kr.Current() != ep {
		p.audit("rekey_not_current_epoch", c.ID)
		return ackAfterFlush
	}
	if c.Reconnecting {
		p.audit("rekey_while_reconnecting", c.ID) // the reconnect settles the session
		return ackAfterFlush
	}
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		p.audit("rekey_rejected", c.ID)
		return ackAfterFlush
	}
	if !p.admitHandshake(c.ID, handshake.PurposeRekey, pi.Th1()) {
		pi.Discard()
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
	th1 := pi.Th1()
	p.awaiting[id] = &awaiting{ID: id, ConnID: c.ID, Purpose: handshake.PurposeRekey, Th1: th1[:], Created: now,
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
	if aw.Reconnect != nil {
		if err := p.applyReconnect(c, aw.Reconnect); err != nil {
			p.audit("reconnect_record_bad", c.ID)
			fr.Epoch.Destroy()
			for _, j := range aw.Reconnect.Issued {
				p.denyJTI(j, now)
			}
			return ackAfterFlush
		}
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
	if aw.Reconnect != nil {
		for _, j := range aw.Reconnect.Issued {
			p.denyJTI(j, now)
		}
	}
	aw.r.Abort()
	delete(p.awaiting, id)
	p.markDirty(kindAwait, id)
	if c := p.conns[aw.ConnID]; aw.Reconnect != nil && c != nil && c.Reconnecting && c.State != StateSuspended {
		// We yielded to it, and its hs.fin did not come: a new try.
		p.retryReconnect(c, now)
	}
}

// MaxAwaitingPerConn bounds the handshakes of one purpose (rekey,
// reconnect) awaiting hs.fin for one connection (chosen; not in the
// spec): a member vault cannot pile them up, while a legitimate retry
// still has room.
const MaxAwaitingPerConn = 2

// admitHandshake reports whether a connection's hs.init of a purpose is
// to be answered: not a copy of one already answered (the same th1; an
// outbox retry re-deposits the same bytes), and within the bound. The
// handshakes already awaiting are left alone: the member may be using
// the tokens of one of them.
func (p *Peer) admitHandshake(connID string, purpose handshake.Purpose, th1 [32]byte) bool {
	n := 0
	for _, aw := range p.awaiting {
		if aw.ConnID != connID || aw.New != nil || aw.Purpose != purpose {
			continue
		}
		if bytes.Equal(aw.Th1, th1[:]) {
			return false // answered already; its hs.resp is on its way
		}
		n++
	}
	if n >= MaxAwaitingPerConn {
		p.audit("handshakes_awaiting", connID)
		return false
	}
	return true
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
	if og.ini.Purpose() == handshake.PurposeReconnect {
		return p.finishReconnect(c, og, res, now)
	}
	// hs.fin goes first; what follows is sealed in the new epoch.
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: res.Fin}, now)
	p.installEpoch(c, res.Epoch, now)
	p.log().Info("rekeyed", "connection_id", c.ID)
	return ackAfterFlush
}

func (p *Peer) dropOutgoing(id string) {
	if og := p.outgoing[id]; og != nil {
		reconnect := og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect
		if og.ini != nil {
			og.ini.Abort()
		}
		for _, j := range og.Issued {
			p.denyJTI(j, p.now())
		}
		if c := p.conns[og.ConnID]; reconnect && c != nil && c.Reconnecting {
			p.reconnectFailed(c)
		}
	}
	delete(p.outgoing, id)
	p.markDirty(kindOutgoing, id)
}
