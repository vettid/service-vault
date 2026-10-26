package peer

import (
	"context"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Member authentication (VAULT-MESSAGING §10.4), the challenger's side as
// the member vault's connauth feature has it: the service asks a
// connection's member to prove presence; the member approves on the
// phone and their vault signs the challenge with the credential key. The
// key is pinned at the first success.

// MaxPendingChallenges bounds the challenges outstanding per connection
// (the member vault's MaxPendingOut).
const MaxPendingChallenges = 8

// Errors of Authenticate.
var (
	ErrNotStarted = errors.New("peer: not started")
	ErrLimit      = errors.New("peer: too many pending challenges")
	ErrContext    = errors.New("peer: challenge context too long")
)

// Authenticate sends a connection.authenticate.challenge with context
// ctxt to an active connection, answerable for ttl (at most
// peerwire.ConnAuthChallengeTTL; the inner exp, §10.4). The outcome
// arrives as an event with the returned request id: signin.approved,
// signin.denied or signin.expired.
func (p *Peer) Authenticate(ctx context.Context, connID, ctxt string, ttl time.Duration) (string, error) {
	if len(ctxt) > peerwire.ConnAuthMaxContext {
		return "", ErrContext
	}
	if ttl <= 0 || ttl > peerwire.ConnAuthChallengeTTL {
		ttl = peerwire.ConnAuthChallengeTTL
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return "", ErrNotStarted
	}
	c := p.conns[connID]
	if c == nil || c.State != StateActive {
		return "", ErrNotFound
	}
	n := 0
	for _, ch := range p.challenges {
		if ch.ConnID == connID {
			n++
		}
	}
	if n >= MaxPendingChallenges {
		return "", ErrLimit
	}
	now := p.now()
	wc, err := peerwire.NewConnAuthChallenge(p.newID(now), ctxt)
	if err != nil {
		return "", err
	}
	exp := now.Add(ttl).UTC().Truncate(time.Millisecond)
	if p.sendInnerExp(c, peerwire.TypeConnAuthChallenge, wc.Marshal(), exp, now) == "" {
		return "", ErrNotFound
	}
	p.challenges[wc.RequestID] = &challenge{ID: wc.RequestID, ConnID: connID, Nonce: wc.Nonce, Context: ctxt, Exp: exp}
	p.markDirty(kindAuth, wc.RequestID)
	if err := p.flushAndDrain(ctx); err != nil {
		return "", err
	}
	p.log().Info("challenge sent", "connection_id", connID, "request_id", wc.RequestID)
	return wc.RequestID, nil
}

func (p *Peer) sendInnerExp(c *Connection, typ string, body []byte, exp, now time.Time) string {
	in := newInner(p.newID(now), typ, body, now)
	in.Exp = exp
	return p.sendInner(c, in, now)
}

func (ch *challenge) wire() *peerwire.ConnAuthChallenge {
	return &peerwire.ConnAuthChallenge{RequestID: ch.ID, Nonce: ch.Nonce, Context: ch.Context}
}

// connAuthResponse handles a connection's answer to a challenge: the
// signature must verify over the challenge under the key it names; the
// key is pinned at the first success and a change is reported (§10.4).
func (p *Peer) connAuthResponse(c *Connection, body []byte, now time.Time) {
	r, err := peerwire.ParseConnAuthResponse(body)
	if err != nil {
		p.audit("bad_auth_response", c.ID)
		return
	}
	ch := p.challenges[r.RequestID]
	if ch == nil || ch.ConnID != c.ID {
		return // §8.1: matches no pending request
	}
	delete(p.challenges, ch.ID)
	p.markDirty(kindAuth, ch.ID)
	ev := &Event{ConnectionID: c.ID, RequestID: ch.ID, Tag: c.Tag}
	switch {
	case r.Status == peerwire.ConnAuthDenied:
		ev.Type, ev.Reason = EventSignInDenied, "denied"
	case peerwire.VerifyConnAuthResponse(r, p.cfg.Keys.IKPublic(), c.Peer.IK, ch.wire()) != nil:
		ev.Type, ev.Reason = EventSignInDenied, "bad_signature"
	default:
		ev.Type = EventSignInApproved
		ev.KeyChanged = peerwire.PinnedKeyChanged(c.AuthKey, r.Key, r.Rotations)
		c.AuthKey, c.AuthAt = append([]byte(nil), r.Key...), now.UTC().Truncate(time.Millisecond)
		p.markDirty(kindConn, c.ID)
	}
	p.emit(ev, now)
}

// connAuthRotated follows the member's credential-key rotations from the
// pinned key; a chain that does not verify leaves the pin unchanged.
func (p *Peer) connAuthRotated(c *Connection, body []byte) {
	chain, err := peerwire.ParseConnAuthRotated(body)
	if err != nil {
		p.audit("bad_auth_rotated", c.ID)
		return
	}
	if len(c.AuthKey) == 0 {
		return // nothing pinned
	}
	end, err := credwire.FollowChain(c.AuthKey, chain)
	if err != nil {
		p.audit("auth_rotation_rejected", c.ID)
		return
	}
	c.AuthKey = end
	p.markDirty(kindConn, c.ID)
}

// expireChallenges ends the challenges past their exp: signin.expired.
func (p *Peer) expireChallenges(now time.Time) {
	for id, ch := range p.challenges {
		if now.Before(ch.Exp) {
			continue
		}
		delete(p.challenges, id)
		p.markDirty(kindAuth, id)
		tag := ""
		if c := p.conns[ch.ConnID]; c != nil {
			tag = c.Tag
		}
		p.emit(&Event{Type: EventSignInExpired, ConnectionID: ch.ConnID, RequestID: id, Tag: tag}, now)
	}
}
