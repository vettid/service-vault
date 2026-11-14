package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// dispatch handles a decrypted session-mode message from an active
// connection (§8.2, §8.3, §8.4, §7.3).
func (p *Peer) dispatch(ctx context.Context, c *Connection, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, msgID string, now time.Time) (disposition, error) {
	p.markDirty(kindConn, c.ID)                      // the epoch's receive count moved
	if !suite.EqualPublic(sender, c.Peer.Relay.PK) { // §6.3
		p.audit("sender_mismatch", c.ID)
		return ackAfterFlush, nil
	}
	if c.State == StateSuspended {
		p.audit("connection_suspended", c.ID) // §3.4: nothing is accepted
		return ackAfterFlush, nil
	}
	if in.Type == handshake.TypeFin {
		// An hs.fin whose answer is gone (a duplicate, or one for an
		// answer dropped or expired) opening under an epoch we hold: acked
		// and ignored. It moves no confirmed epoch and sets no flag
		// (R29-T3; RELEASE-29 §5).
		return ackAfterFlush, nil
	}
	// §3.4.1 acceptFrom step 3 (R29-K8): rule C on every link the message
	// carries, before anything may refuse it.
	if p.evidenceFirst(c, in, now) {
		return ackAfterFlush, nil
	}
	// §6.3.1 before anything else is done with the message (the rate
	// limit, the ts window, dedupe, its handler): the received flag and
	// the confirmed epoch (RELEASE-29 §13, change 1).
	if p.noteFromMember(c, ep, in, now) {
		return ackAfterFlush, nil
	}
	if in.Type == handshake.TypeInit {
		_, seen, err := p.cfg.Store.Get(ctx, kindInner, rekeyKey(handshake.Th1(raw)))
		if err != nil {
			return 0, err
		}
		if seen {
			p.audit("rekey_init_replayed", c.ID) // answered once (R29-T3, §6.5)
			return ackAfterFlush, nil
		}
		return p.handleRekeyInit(c, in, ep, raw, sender, now), nil
	}
	if err := in.CheckTime(now, true); err != nil {
		p.audit("stale_or_future", c.ID)
		return ackAfterFlush, nil
	}
	if !p.rateAllow(c.ID, now) {
		p.audit("rate_limited", c.ID) // §7.3: acked, dropped, audited
		return ackAfterFlush, nil
	}
	ikey := c.ID + "|" + in.ID
	_, seen, err := p.cfg.Store.Get(ctx, kindInner, ikey)
	if err != nil {
		return 0, err
	}
	if seen {
		// §8.2 layer 2: a retransmission; re-send a cached response,
		// never re-execute.
		if err := p.resendCached(ctx, c, ikey); err != nil {
			return 0, err
		}
		return ackAfterFlush, nil
	}
	p.mark(kindInner, ikey, []byte{1}, now.Add(DedupeRetention))
	if in.Re != "" {
		p.handleResponse(c, in, now)
		return ackAfterFlush, nil
	}
	p.log().Info("message", "connection_id", c.ID, "type", in.Type, "size", len(in.Body))
	switch in.Type {
	case peerwire.TypeConnectionApproved:
		// A copy after activation is ignored (§6.4, 0.10.4).
	case peerwire.TypeConnectionRemoved:
		if peerwire.ParseConnectionRemoved(in.Body) == nil {
			p.removeConnection(c, "in", now)
		}
	case peerwire.TypeTokenIssued:
		p.storeIssuedTo(c, in.Body)
	case peerwire.TypeTokenRefresh:
		body, err := p.answerTokenRefresh(c, now)
		var ts *errTooSoon
		switch {
		case errors.As(err, &ts):
			p.respondErrorBody(c, in, ikey, peerwire.CodeTooSoon, peerwire.TooSoonBody(ts.after), now)
		case err != nil:
			p.respondErrorBody(c, in, ikey, "relay_error", nil, now)
		default:
			p.respond(c, in, ikey, body, now)
		}
	case peerwire.TypeProfileUpdate:
		p.profileUpdate(c, in.Body)
	case peerwire.TypeConnAuthResponse:
		p.connAuthResponse(c, in.Body, now)
	case peerwire.TypeConnAuthRotated:
		p.connAuthRotated(c, in.Body)
	case TypeIdentityRotate:
		eid := ep.ID()
		p.identityRotate(c, in.Body, eid[:], now)
	case TypeRelayAddressUpdate:
		// Refused from every member, as vettid-vault #241 makes the member
		// vault do (the audit names differ: a service has no drop.peer_key
		// record). It moved the connection's mailbox and tokens on the
		// session's authentication alone, with no signed relay links and
		// none of rule U's checks (VAULT-MESSAGING §3.4.1), so an old copy
		// of a member's vault holding the session's keys could redirect
		// our deposits. Release 29 rotates no relay key (§3.4.1 A5);
		// §3.4.2's rules replace this (GC #9442). Acked, dropped, nothing
		// changes.
		p.audit("address_update_refused", c.ID)
	case peerwire.TypeConnAuthChallenge:
		// The service has no member credential to sign with (§10.4); a
		// challenge to it is never answered (chosen; not in the spec).
		p.audit("challenge_unsupported", c.ID)
	case handshake.TypeConfirm:
		// A member's vault confirms an epoch it activated as responder
		// (§6.3.1, R29-R1): noteFromMember has moved the confirmed epoch,
		// or confirmed the service's own pending epoch, already. Nothing
		// more: acked, without audit, never answered.
	default:
		if isVoteType(in.Type) && p.cfg.Votes != nil {
			if err := p.vote(ctx, c, in, ikey, msgID, now); errors.Is(err, ErrNoAnswer) {
				// Acknowledged, unanswered and not marked seen: a resend
				// with the same id is handled again, not taken for a
				// retransmission (§8.2).
				p.unmark(kindInner, ikey)
			} else if err != nil {
				return 0, err
			}
			break
		}
		p.respondErrorBody(c, in, ikey, "unsupported_type", nil, now)
	}
	return ackAfterFlush, nil
}

// profileUpdate keeps a member's profile.update core (§10.8
// "Receiving"): a newer version with a complete core and the
// connection's identity key; the extras are not kept.
func (p *Peer) profileUpdate(c *Connection, body []byte) {
	u, err := peerwire.ParseProfileUpdate(body)
	if err != nil {
		p.audit("profile_malformed", c.ID)
		return
	}
	if u.Version <= c.ProfileVersion {
		return
	}
	if u.Malformed {
		p.audit("profile_malformed", c.ID)
		return
	}
	if !suite.EqualPublic(u.IK, c.Peer.IK) {
		p.audit("profile_ik_mismatch", c.ID)
		return
	}
	c.Peer.FirstName, c.Peer.LastName, c.ProfileVersion = u.FirstName, u.LastName, u.Version
	// The last update's features replace the ones held: one that leaves a
	// name out removes it.
	var ok bool
	if c.Features, ok = parseFeatures(u.Members["features"]); !ok {
		p.memberIgnored(c.ID, "features")
	}
	// The contract it claims (0.90.10): an update without one, or with one
	// of another type or form, clears it, and is applied all the same.
	if c.PeerContract, ok = parseContract(u.Members["contract"]); !ok {
		p.memberIgnored(c.ID, "contract")
	}
	p.markDirty(kindConn, c.ID)
}

// memberIgnored logs a profile.update member of the wrong form. The
// member counts as absent and the update is applied (§10.8), so this is
// not a drop.
func (p *Peer) memberIgnored(connID, member string) {
	p.log().Warn("profile member ignored", "reason", "profile_member_malformed", "member", member, "connection_id", connID)
}

// parseFeatures reads a profile.update's features (§10.8, 0.81.0): absent,
// or a sorted array of distinct names matching [a-z0-9_]{1,32}. A
// malformed member counts as none (chosen; not in the spec): ok is false.
func parseFeatures(raw json.RawMessage) (features []string, ok bool) {
	if raw == nil {
		return nil, true
	}
	var names []string
	if json.Unmarshal(raw, &names) != nil || len(names) == 0 || len(names) > maxFeatures {
		return nil, false
	}
	for i, n := range names {
		if !validFeature(n) || i > 0 && names[i-1] >= n {
			return nil, false
		}
	}
	return names, true
}

// maxFeatures bounds the names kept from one profile.update (chosen).
const maxFeatures = 16

func validFeature(n string) bool {
	if len(n) == 0 || len(n) > 32 {
		return false
	}
	for _, ch := range []byte(n) {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_') {
			return false
		}
	}
	return true
}

// sendTo seals a durable message to a connection's current epoch and
// queues its deposit on the standing token. It returns the inner id, or
// "" when the connection has no session.
func (p *Peer) sendTo(c *Connection, typ string, body json.RawMessage, now time.Time) string {
	return p.sendInner(c, &envelope.Inner{ID: p.newID(now), Type: typ, TS: now, Body: body}, now)
}

// While a reconnect of the service's is open the message waits in the
// outbox (RELEASE-29 §3), and is sealed again under the reconnect's epoch
// at its confirmation.
func (p *Peer) sendInner(c *Connection, in *envelope.Inner, now time.Time) string {
	if p.sendEntry(c, in, now) == nil {
		return ""
	}
	return in.ID
}

// sendEntry is sendInner, returning the outbox entry queued (nil: none).
func (p *Peer) sendEntry(c *Connection, in *envelope.Inner, now time.Time) *outboxEntry {
	if c.kr == nil || c.kr.Current() == nil || c.State != StateActive {
		return nil
	}
	if in.Features == nil {
		in.Features = features() // §10.8, §6.3.1 Capability
	}
	if p.outboxFor(c.ID) >= MaxOutboxPerConn {
		// The member's mailbox has not taken our deposits for a while: what
		// would pile up is dropped, not kept without bound.
		p.audit("outbox_full", c.ID)
		return nil
	}
	raw, err := c.kr.Current().Seal(in)
	if err != nil {
		return nil
	}
	p.markDirty(kindConn, c.ID) // the epoch's send count moved
	e := &outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: raw}
	p.queueDeposit(e, now)
	return e
}

// MaxOutboxPerConn bounds the deposits waiting for one connection
// (chosen; not in the spec): a member vault that stops taking them while
// it keeps sending cannot grow the outbox without bound.
const MaxOutboxPerConn = 256

func (p *Peer) outboxFor(connID string) int {
	n := 0
	for _, e := range p.outbox {
		if e.ConnID == connID && e.Op == opDeposit && !e.Confirm && !e.Handshake { // exempt (RELEASE-29 §5)
			n++
		}
	}
	return n
}

// respond deposits a response and caches it for 24 h (§8.1, §8.2).
func (p *Peer) respond(c *Connection, req *envelope.Inner, ikey string, body json.RawMessage, now time.Time) {
	if body == nil {
		body = json.RawMessage(`{}`)
	}
	p.sendResponse(c, ikey, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusOK, Body: body}, now)
}

func (p *Peer) respondError(c *Connection, req *envelope.Inner, code string, now time.Time) {
	p.respondErrorBody(c, req, c.ID+"|"+req.ID, code, nil, now)
}

func (p *Peer) respondErrorBody(c *Connection, req *envelope.Inner, ikey, code string, body json.RawMessage, now time.Time) {
	p.sendResponse(c, ikey, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusError,
		Error: &envelope.Error{Code: code}, Body: body}, now)
}

func (p *Peer) sendResponse(c *Connection, ikey string, out *envelope.Inner, now time.Time) {
	if !envelope.ValidType(out.Type) {
		out.Type = "error"
	}
	out.ID, out.TS = p.newID(now), now
	if j, err := out.Marshal(envelope.ModeSealed); err == nil { // cached without seq
		if b, err := json.Marshal(cachedResponse{Inner: j}); err == nil {
			p.mark(kindResp, ikey, b, now.Add(ResponseRetention))
		}
	}
	p.sendInner(c, out, now)
}

// resendCached re-sends a cached response in a new envelope (§8.2).
func (p *Peer) resendCached(ctx context.Context, c *Connection, ikey string) error {
	recs, err := p.cachedResponse(ctx, ikey)
	if err != nil || recs == nil {
		return err
	}
	in, err := envelope.ParseInner(recs, envelope.ModeSealed)
	if err != nil {
		return nil
	}
	in.Seq = 0
	p.sendInner(c, in, p.now())
	return nil
}

// cachedResponse reads one cached response, or nil.
func (p *Peer) cachedResponse(ctx context.Context, ikey string) ([]byte, error) {
	b, ok, err := p.cfg.Store.Get(ctx, kindResp, ikey)
	if err != nil || !ok {
		return nil, err
	}
	var cr cachedResponse
	if json.Unmarshal(b, &cr) != nil {
		return nil, nil
	}
	return cr.Inner, nil
}

// handleResponse matches a response to one of the service's requests
// (§8.1); one matching none is dropped.
func (p *Peer) handleResponse(c *Connection, in *envelope.Inner, now time.Time) {
	if in.Type == peerwire.TypeTokenRefresh && c.RefreshID != "" && in.Re == c.RefreshID {
		p.handleRefreshAnswer(c, in, now)
	}
}

// removeConnection applies §7.4 "Connection removed": dir "out" sends
// connection.removed (best effort); "in" (the member's notice) and
// "replaced" (a newer connection with the same peer) send nothing. Every
// token issued to the member is denylisted by jti; the held tokens,
// session keys and outbox entries are deleted.
func (p *Peer) removeConnection(c *Connection, dir string, now time.Time) {
	p.removeConnectionFor(c, dir, "", now)
}

// removeConnectionFor is removeConnection with the reason connection.removed
// carries to the application ("": none; pre29, RELEASE-29 §11).
func (p *Peer) removeConnectionFor(c *Connection, dir, reason string, now time.Time) {
	if dir == "out" && c.kr != nil && c.kr.Current() != nil && c.Standing.Token != "" && c.State == StateActive && !c.Reconnecting &&
		!c.currentDemoted() && // nothing but handshake messages under a demoted epoch (§3.4.1 K5)
		len(c.LegacyPrevRelayPK) == 0 { // nor to an address a relay.address.update may have moved (legacyRelayMove)
		in := &envelope.Inner{ID: p.newID(now), Type: peerwire.TypeConnectionRemoved, TS: now, Body: peerwire.ConnectionRemovedBody(),
			Features: features()}
		if raw, err := c.kr.Current().Seal(in); err == nil {
			p.dropUndelivered(c, "undelivered_removed", nil)
			p.queueDeposit(&outboxEntry{Mailbox: c.Peer.Relay.Mailbox, Token: c.Standing.Token, Payload: raw, BestEffort: true}, now)
		}
	} else {
		p.dropUndelivered(c, "undelivered_removed", nil)
	}
	p.denyConnTokens(c.ID, now)
	c.Reconnecting = false // ended, not failed
	if c.kr != nil {
		c.kr.Destroy()
	}
	for id, og := range p.outgoing {
		if og.ConnID == c.ID {
			p.dropOutgoing(id)
		}
	}
	for id, aw := range p.awaiting {
		if aw.ConnID == c.ID {
			aw.r.Abort()
			delete(p.awaiting, id)
			p.markDirty(kindAwait, id)
		}
	}
	for id, ch := range p.challenges {
		if ch.ConnID == c.ID {
			delete(p.challenges, id)
			p.markDirty(kindAuth, id)
		}
	}
	delete(p.conns, c.ID)
	delete(p.rates, c.ID)
	delete(p.outboxFull, c.ID)
	p.markDirty(kindConn, c.ID)
	d := dir
	if d == "replaced" {
		d = "in"
	}
	p.emit(&Event{Type: EventConnectionRemoved, ConnectionID: c.ID, Direction: d, Tag: c.Tag, Reason: reason}, now)
}

// ErrNotFound is an unknown or inactive connection or invitation.
var ErrNotFound = errors.New("peer: not found")

// ErrBusy is a connection whose member mailbox is not taking deposits:
// MaxOutboxPerConn of them are waiting.
var ErrBusy = errors.New("peer: connection busy")

// ErrOutboxFull is SendMessage refused because the whole outbox is at
// MaxSendOutbox entries or MaxSendOutboxBytes of payload: the relay is
// not taking deposits from this service (an outage), not one member.
var ErrOutboxFull = errors.New("peer: outbox full")

// Remove ends a connection from the service's side (§7.4): the member's
// vault gets connection.removed, best effort.
func (p *Peer) Remove(ctx context.Context, connID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return ErrNotStarted
	}
	c := p.conns[connID]
	if c == nil {
		return ErrNotFound
	}
	p.removeConnection(c, "out", p.now())
	return p.flushAndDrain(ctx)
}

// ConnectionInfo is what the application may read about a connection.
type ConnectionInfo struct {
	ID        string
	State     string
	Name      string
	InviteID  string
	Tag       string
	Activated time.Time
	// IK is the member's identity key, as pinned at the handshake, and
	// AuthKey the credential key pinned at its first signed
	// connection.authenticate.response (empty before one).
	IK      []byte
	AuthKey []byte
	// GovKey is the credential key the connection's governance approvals
	// must be signed with (empty: none pinned). See Connection.GovKey.
	GovKey []byte
	// AuthKeyChangedAt: when AuthKey last changed to a key no rotation
	// chain reached (zero: never).
	AuthKeyChangedAt time.Time
}

// Connection returns a connection by id.
func (p *Peer) Connection(id string) (ConnectionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.conns[id]
	if c == nil {
		return ConnectionInfo{}, false
	}
	return ConnectionInfo{ID: c.ID, State: c.State, Name: c.Name(), InviteID: c.InviteID, Tag: c.Tag, Activated: c.Activated,
		IK: append([]byte(nil), c.Peer.IK...), AuthKey: append([]byte(nil), c.AuthKey...),
		GovKey: append([]byte(nil), c.GovKey...), AuthKeyChangedAt: c.AuthKeyChangedAt}, true
}

// errPinNotStarted is PinGov's and RepinGov's answer before the peer has
// started: ErrNotFound as before (their callers take it for a peer not
// yet loaded), and ErrNotStarted.
var errPinNotStarted = fmt.Errorf("%w (%w)", ErrNotStarted, ErrNotFound)

// PinGov pins the connection's governance key: to key, or to its
// credential key as it is now when key is empty. With onlyIfEmpty it does
// so only when none is pinned. It reports whether it pinned, and
// ErrNotFound for a connection it does not know (the peer may not have
// loaded its state yet). Before the peer has started it pins nothing, and
// answers an error that is both ErrNotStarted and ErrNotFound.
func (p *Peer) PinGov(ctx context.Context, connID string, key []byte, onlyIfEmpty bool) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return false, errPinNotStarted
	}
	c := p.conns[connID]
	if c == nil {
		return false, ErrNotFound
	}
	if len(key) == 0 {
		key = c.AuthKey
	}
	if len(key) == 0 || onlyIfEmpty && len(c.GovKey) > 0 {
		return false, nil
	}
	c.GovKey = append([]byte(nil), key...)
	p.markDirty(kindConn, c.ID)
	return true, p.flushAndDrain(ctx)
}

// RepinGov moves the connection's governance key to key, but only while
// key is still its credential key; it reports whether it did, and
// ErrNotFound for a connection it does not know. Before the peer has
// started it moves nothing, and answers as PinGov does.
func (p *Peer) RepinGov(ctx context.Context, connID string, key []byte) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return false, errPinNotStarted
	}
	c := p.conns[connID]
	if c == nil {
		return false, ErrNotFound
	}
	if len(key) == 0 || !bytes.Equal(c.AuthKey, key) {
		return false, nil
	}
	c.GovKey = append([]byte(nil), key...)
	p.markDirty(kindConn, c.ID)
	return true, p.flushAndDrain(ctx)
}

// housekeeping runs before each batch and every minute: invitations,
// requests and challenges past their expiry, rekeys due, tokens to
// re-mint or refresh (§6.4, §6.5, §7.2, §7.4).
func (p *Peer) housekeeping(now time.Time) {
	if p.mintWait(now) {
		// A lost mailbox's wait (mailbox.go): rekeys, reconnects and
		// re-mints would mint tokens the relay refuses. A few minutes late.
		return
	}
	for id, inv := range p.invites {
		if !inv.Used && !inv.Withdrew && !now.Before(inv.Exp) {
			p.withdrawInvite(inv, now)
			p.endInvite(id, InviteExpired, now)
		}
		if !inv.Ended.IsZero() && now.Sub(inv.Ended) >= InviteRetention {
			delete(p.invites, id)
			p.markDirty(kindInvite, id)
		}
	}
	p.expireRequests(now)
	p.expireChallenges(now)
	for id, og := range p.outgoing {
		c := p.conns[og.ConnID]
		reconnect := og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect
		life := HandshakeTTL
		if reconnect && c != nil && c.ReconnectRestore {
			life = ReconnectTimeout // a restore's try (RELEASE-29 §4)
		}
		if now.Sub(og.Created) < life {
			continue
		}
		p.rekeyFailed(og, now)
		p.dropOutgoing(id) // an hs.resp that never came (or can no longer be accepted)
		if reconnect && c != nil {
			// A failed try: the next one, or stale after the last (§3.4.1
			// "The reconnect bound").
			p.audit("reconnect_try_expired", c.ID) // checkReconnect starts the next
		}
	}
	for _, c := range p.conns {
		if c.kr != nil {
			c.kr.Prune(now)
		}
		p.sweepCarried(c, now)
		p.pruneAbandoned(c, now)
		if c.Reconnecting {
			p.checkReconnect(c, now)
			continue
		}
		if c.State != StateActive {
			continue
		}
		if p.remintOwed(c) {
			// A lost mailbox's re-mint not yet done for this member: what
			// would ask it for an answer (a rekey, a refresh) waits, since
			// it could only answer on a token the relay refuses.
			continue
		}
		if c.currentDemoted() {
			p.tickDemoted(c, now) // §3.4.1 K5: only the reconnect goes
			continue
		}
		if !c.standingValid(now) && p.standingWaiting(c) {
			// tickPendings reconnects, after the batch, unless carried
			// tokens wait; hs.confirm still goes again meanwhile.
			p.tickConfirm(c, now)
			continue
		}
		if c.kr != nil && c.kr.Current() != nil && c.kr.Current().NeedsRekey(now) {
			p.startRekey(c, now)
		}
		p.tickConfirm(c, now)
		p.sendContract(c, now) // §10.8 "Sending" (0.90.10)
		if c.RefreshID != "" && !now.Before(c.RefreshAfter) {
			c.RefreshID = "" // unanswered: ask again
			p.markDirty(kindConn, c.ID)
		}
		force := p.refreshOwed[c.ID]
		// Cleared before: a refresh held again marks it anew. (Not reached
		// while held today: housekeeping stops while mintWait holds, and
		// skips a member whose re-mint is owed.)
		delete(p.refreshOwed, c.ID)
		p.refreshHeld(c, now, force)
	}
	p.remintIssued(now)
	p.pruneIssued(now)
	for id, w := range p.rates {
		if now.Sub(w.start) >= time.Minute {
			delete(p.rates, id)
		}
	}
}

// withdrawInvite denylists an invitation's open token and deletes its
// claim (§7.4).
func (p *Peer) withdrawInvite(inv *InviteRecord, now time.Time) {
	inv.Withdrew = true
	p.markDirty(kindInvite, inv.ID)
	p.denyJTI(inv.OpenJTI, now)
	p.queueDeleteClaim(inv.ClaimID, now)
}

// String is for logs: ids only.
func (c *Connection) String() string { return fmt.Sprintf("connection %s (%s)", c.ID, c.State) }

func newInner(id, typ string, body []byte, now time.Time) *envelope.Inner {
	return &envelope.Inner{ID: id, Type: typ, TS: now, Body: body}
}
