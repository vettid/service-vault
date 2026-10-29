package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Votes (BALLOT-PROTOCOL §4.2): a member vault's vote.* requests go to the
// application's ballot box, with what it needs to answer them that only
// the connection knows.

// VoteRequest is a vote.* request from a member's vault.
type VoteRequest struct {
	ConnectionID string
	// PeerIK is the member vault's identity key on this connection.
	PeerIK ed25519.PublicKey
	// CredentialKey is the member's credential key pinned at the first
	// signed connection.authenticate.response, or nil.
	CredentialKey []byte
	// Active is false once the connection is no longer active.
	Active bool
	Type   string
	Body   []byte
	// MsgMS is the relay's time of the message, from its msg_id
	// (RELAY-PROTOCOL §6.2), in Unix milliseconds.
	MsgMS uint64
}

// VoteAnswer is the response: Body with Code "" for ok, or an error code
// with its body.
type VoteAnswer struct {
	Body json.RawMessage
	Code string
}

// Votes answers vote.* requests. An error is a storage failure: the
// message is not acknowledged, and the relay delivers it again.
type Votes interface {
	Vote(ctx context.Context, r *VoteRequest) (VoteAnswer, error)
}

// isVoteType reports whether typ is one of the vote family (§4.2).
func isVoteType(typ string) bool { return strings.HasPrefix(typ, "vote.") }

func (p *Peer) vote(ctx context.Context, c *Connection, in *envelope.Inner, ikey, msgID string, now time.Time) error {
	ms, err := ulidMS(msgID)
	if err != nil {
		p.audit("bad_msg_id", c.ID)
		return nil
	}
	a, err := p.cfg.Votes.Vote(ctx, &VoteRequest{ConnectionID: c.ID, PeerIK: c.Peer.IK, CredentialKey: c.AuthKey,
		Active: c.State == StateActive, Type: in.Type, Body: in.Body, MsgMS: ms})
	if err != nil {
		return err
	}
	if a.Code == "" {
		p.respond(c, in, ikey, a.Body, now)
	} else {
		p.respondErrorBody(c, in, ikey, a.Code, a.Body, now)
	}
	return nil
}

// ulidMS is the millisecond time of a ULID's first ten characters.
func ulidMS(id string) (uint64, error) {
	if !envelope.ValidULID(id) {
		return 0, errors.New("peer: not a ULID")
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var ms uint64
	for _, ch := range id[:10] {
		ms = ms<<5 | uint64(strings.IndexRune(alphabet, ch))
	}
	return ms, nil
}

// Eligible lists the active connections (ballot.Roster). Every active
// connection counts until VAULT-MESSAGING says how a vault advertises the
// vote feature (BALLOT-PROTOCOL §3.2, plan item 5.1).
func (p *Peer) Eligible() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.conns))
	for id, c := range p.conns {
		if c.State == StateActive {
			out = append(out, id)
		}
	}
	return out
}

// SendMessage sends a message the application asks for (a vote.proposal,
// for one) to an active connection, and returns its inner id.
func (p *Peer) SendMessage(ctx context.Context, connID, typ string, body json.RawMessage) (string, error) {
	if !envelope.ValidType(typ) {
		return "", errors.New("peer: invalid message type")
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
	now := p.now()
	id := p.sendTo(c, typ, body, now)
	if id == "" {
		if p.outboxFor(c.ID) >= MaxOutboxPerConn {
			return "", ErrBusy
		}
		return "", ErrNotFound
	}
	if err := p.flushAndDrain(ctx); err != nil {
		return "", err
	}
	return id, nil
}

// Caught reports whether every message the relay received before t has
// been handled: the relay hands out a mailbox's unleased messages in
// msg_id order (RELAY-PROTOCOL §6.2, §6.3), so it holds once a later
// message was handled, or a collect that started after t found nothing,
// in a collect that started when no earlier message could still be
// leased (BALLOT-PROTOCOL §7).
//
// A message this process left unacked holds it false while it is before
// t (until it is handled, or the relay's TTL drops it); one after t
// doesn't. Another process's leases (the lease marker) hold it false
// until one visibility timeout after that process last leased messages,
// and the evidence must come from a collect started after that.
func (p *Peer) Caught(ctx context.Context, t time.Time) (bool, error) {
	data, ok, err := p.cfg.Store.Get(ctx, kindLease, leaseMarkID)
	if err != nil {
		return false, err
	}
	var mark leaseMark
	if ok {
		if err := json.Unmarshal(data, &mark); err != nil {
			return false, fmt.Errorf("peer: lease marker: %w", err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	since := p.leaseFree
	if ok && mark.Instance != p.instance {
		if end := mark.At.Add(p.visibility() + leaseMargin); end.After(since) {
			since = end
		}
	}
	now, tms := p.now(), uint64(t.UnixMilli())
	for id, u := range p.unacked {
		switch {
		case !now.Before(u.exp):
			delete(p.unacked, id)
		case u.ms < tms:
			return false, nil
		}
	}
	return p.lastMsgMS >= tms && !p.lastMsgAt.Before(since) || !p.emptyAt.Before(t) && !p.emptyAt.Before(since), nil
}
