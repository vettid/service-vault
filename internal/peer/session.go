package peer

import (
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
func (p *Peer) dispatch(ctx context.Context, c *Connection, in *envelope.Inner, ep *handshake.Epoch, raw []byte, sender ed25519.PublicKey, now time.Time) (disposition, error) {
	p.markDirty(kindConn, c.ID) // the epoch's receive count moved
	if err := handshake.CheckSender(sender, c.Peer.Relay.PK); err != nil {
		p.audit("sender_mismatch", c.ID)
		return ackAfterFlush, nil
	}
	if in.Type == handshake.TypeInit {
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
	case peerwire.TypeConnAuthChallenge:
		// The service has no member credential to sign with (§10.4); a
		// challenge to it is never answered (chosen; not in the spec).
		p.audit("challenge_unsupported", c.ID)
	default:
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
	p.markDirty(kindConn, c.ID)
}

// sendTo seals a durable message to a connection's current epoch and
// queues its deposit on the standing token. It returns the inner id, or
// "" when the connection has no session.
func (p *Peer) sendTo(c *Connection, typ string, body json.RawMessage, now time.Time) string {
	return p.sendInner(c, &envelope.Inner{ID: p.newID(now), Type: typ, TS: now, Body: body}, now)
}

func (p *Peer) sendInner(c *Connection, in *envelope.Inner, now time.Time) string {
	if c.kr == nil || c.kr.Current() == nil || c.State != StateActive {
		return ""
	}
	raw, err := c.kr.Current().Seal(in)
	if err != nil {
		return ""
	}
	p.markDirty(kindConn, c.ID) // the epoch's send count moved
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Payload: raw}, now)
	return in.ID
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
	if dir == "out" && c.kr != nil && c.kr.Current() != nil && c.Standing.Token != "" && c.State == StateActive {
		in := &envelope.Inner{ID: p.newID(now), Type: peerwire.TypeConnectionRemoved, TS: now, Body: peerwire.ConnectionRemovedBody()}
		if raw, err := c.kr.Current().Seal(in); err == nil {
			p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID })
			p.queueDeposit(&outboxEntry{Mailbox: c.Peer.Relay.Mailbox, Token: c.Standing.Token, Payload: raw, BestEffort: true}, now)
		}
	} else {
		p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID })
	}
	p.denyConnTokens(c.ID, now)
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
	p.markDirty(kindConn, c.ID)
	d := dir
	if d == "replaced" {
		d = "in"
	}
	p.emit(&Event{Type: EventConnectionRemoved, ConnectionID: c.ID, Direction: d, Tag: c.Tag}, now)
}

// ErrNotFound is an unknown or inactive connection or invitation.
var ErrNotFound = errors.New("peer: not found")

// Remove ends a connection from the service's side (§7.4): the member's
// vault gets connection.removed, best effort.
func (p *Peer) Remove(ctx context.Context, connID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
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
}

// Connection returns a connection by id.
func (p *Peer) Connection(id string) (ConnectionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.conns[id]
	if c == nil {
		return ConnectionInfo{}, false
	}
	return ConnectionInfo{ID: c.ID, State: c.State, Name: c.Name(), InviteID: c.InviteID, Tag: c.Tag, Activated: c.Activated}, true
}

// housekeeping runs before each batch and every minute: invitations,
// requests and challenges past their expiry, rekeys due, tokens to
// re-mint or refresh (§6.4, §6.5, §7.2, §7.4).
func (p *Peer) housekeeping(now time.Time) {
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
	for _, c := range p.conns {
		if c.State != StateActive {
			continue
		}
		if c.kr != nil && c.kr.Current() != nil && c.kr.Current().NeedsRekey(now) {
			p.startRekey(c, now)
		}
		if c.RefreshID != "" && !now.Before(c.RefreshAfter) {
			c.RefreshID = "" // unanswered: ask again
			p.markDirty(kindConn, c.ID)
		}
		p.refreshHeld(c, now, false)
		if c.kr != nil {
			c.kr.Prune(now)
		}
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
