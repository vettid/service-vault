package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
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
// batch is not acknowledged, and the relay delivers it again. An error
// that wraps ErrNoAnswer acknowledges the request without answering it.
type Votes interface {
	Vote(ctx context.Context, r *VoteRequest) (VoteAnswer, error)
}

// ErrNoAnswer, wrapped by a Votes error, acknowledges the request and
// sends no answer, without failing the batch. Its inner id is not marked
// seen, so a resend with the same id is handled again (§8.2); the member's
// vault sends again on its own when it gets no answer.
var ErrNoAnswer = errors.New("peer: not answered")

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

// FeatureVote is the profile feature of a vault that can vote
// (VAULT-MESSAGING §10.19.1).
const FeatureVote = "vote"

// Eligible lists the active connections whose last profile.update
// advertised the vote feature (ballot.Roster; BALLOT-PROTOCOL §3.2,
// VAULT-MESSAGING §10.19.1).
func (p *Peer) Eligible() []string {
	return p.activeIf(func(c *Connection) bool { return slices.Contains(c.Features, FeatureVote) })
}

// Active lists the active connections (ballot.Roster).
func (p *Peer) Active() []string {
	return p.activeIf(func(*Connection) bool { return true })
}

func (p *Peer) activeIf(keep func(*Connection) bool) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.conns))
	for id, c := range p.conns {
		if c.State == StateActive && keep(c) {
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
	if n, size := p.outboxLoad(); n >= sendOutboxLimit.n || size >= sendOutboxLimit.bytes {
		return "", ErrOutboxFull
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

// MaxSendOutbox and MaxSendOutboxBytes bound the outbox SendMessage adds
// to (chosen; not in the spec). A relay that refuses deposits at once
// doesn't fail a send: the message stays in the outbox, sealed, in
// memory and in the store, and a restart loads it back. One vote's sends
// to 15,000 members during an outage would otherwise hold about 200 MB
// against the task's 512 MiB (#6946). Past either bound SendMessage
// answers ErrOutboxFull, and the vote's send gives up after
// ballot.MaxFailuresInARow of them; members not sent learn of the vote
// as BALLOT-PROTOCOL §4.2 says. The other messages (responses, sign-in
// and approval challenges) are bounded per connection only
// (MaxOutboxPerConn), so a vote's sends can't crowd them out.
const (
	MaxSendOutbox      = 8192
	MaxSendOutboxBytes = 64 << 20
)

// sendOutboxLimit is the bounds in force (tests lower them).
var sendOutboxLimit = struct{ n, bytes int }{MaxSendOutbox, MaxSendOutboxBytes}

// outboxLoad is the outbox's entries and their payload bytes.
func (p *Peer) outboxLoad() (n, size int) {
	for _, e := range p.outbox {
		n++
		size += len(e.Payload)
	}
	return n, size
}

// Caught reports whether every message the relay received before t has
// been handled: the relay hands out a mailbox's unleased messages in
// msg_id order (RELAY-PROTOCOL §6.2, §6.3), so it holds once a later
// message was handled, or a collect that started after t found nothing,
// in a collect that started when no earlier message could still be
// leased (BALLOT-PROTOCOL §7).
//
// A message left unacked (by this process or another, stored: unacked.go)
// holds it false while it is before t, until it is handled, the relay's
// TTL drops it, or MaxUnackedWait passes. unhandled counts the messages it stopped waiting for (at the
// cap or the TTL) whose relay time is in [from, until): the results
// report those of the voting window (§7). Another process's leases (its
// lease marker) hold it false until one visibility timeout after it last
// leased messages, and the evidence must come from a collect started
// after.
//
// t is in relay time for a handled message (its msg_ms), but an empty
// collect is timed by this process's clock, which may run fast: that
// evidence counts only from a collect that started at or after
// emptyAfter, a time on this clock known to follow the real close (the
// passing timestamp-authority probe plus the margin, BALLOT-PROTOCOL §7,
// 0.13.12).
func (p *Peer) Caught(ctx context.Context, t, emptyAfter, from, until time.Time) (caught bool, unhandled int64, err error) {
	marks, err := p.cfg.Store.Load(ctx, kindLease)
	if err != nil {
		return false, 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// The stored set is every process's, across restarts (unacked.go).
	p.writeUnacked(ctx)
	if err := p.loadUnacked(ctx); err != nil {
		return false, 0, err
	}
	since := p.leaseFree
	for _, r := range marks {
		if r.ID == p.instance {
			continue
		}
		var mark leaseMark
		if err := json.Unmarshal(r.Data, &mark); err != nil {
			return false, 0, fmt.Errorf("peer: lease marker: %w", err)
		}
		// Another process's lease marker is compared by wall time: that
		// relies on one task running at a time (the stack's desiredCount 1,
		// maxHealthyPercent 100), so two tasks' clocks never meet here.
		if end := mark.At.Add(p.visibility() + leaseMargin); end.After(since) {
			since = end
		}
	}
	now, tms := p.now(), uint64(t.UnixMilli())
	held := false
	for id, u := range p.unacked {
		switch {
		case !now.Before(u.exp):
			// Past the cap, or dropped by the relay unhandled: either
			// way the count goes ahead without it.
			if u.capped {
				p.log().Warn("a message left unacked over the cap no longer holds the count", "msg_id", id)
			} else {
				p.log().Warn("a message left unacked was dropped by the relay unhandled", "msg_id", id)
			}
			changed, err := p.storeGaveUp(ctx, id, u)
			if err != nil {
				return false, 0, err
			}
			if changed {
				// Handled or given up on elsewhere since the load: not
				// counted here; the next call's load says which.
				delete(p.unacked, id)
				held = held || u.ms < tms
				continue
			}
			if p.gaveUp == nil {
				p.gaveUp = map[string]unacked{}
			}
			u.exp = gaveUpUntil(u)
			p.gaveUp[id] = u
			delete(p.unacked, id)
		case u.ms < tms:
			held = true
		}
	}
	fms, ums := uint64(from.UnixMilli()), uint64(until.UnixMilli())
	for id, u := range p.gaveUp {
		switch {
		case !now.Before(u.exp):
			delete(p.gaveUp, id)
		case fms <= u.ms && u.ms < ums:
			unhandled++
		}
	}
	if held {
		return false, unhandled, nil
	}
	// These must stay time.Time Before comparisons: emptyAt (Step's start)
	// and emptyAfter (the probe's time) carry this process's monotonic
	// reading, which a wall-clock step doesn't move (BALLOT-PROTOCOL §7,
	// 0.13.12). Never compare them by Unix time or after Round(0).
	caught = p.lastMsgMS >= tms && !p.lastMsgAt.Before(since) ||
		!p.emptyAt.Before(t) && !p.emptyAt.Before(emptyAfter) && !p.emptyAt.Before(since)
	return caught, unhandled, nil
}

// EligibleUnsigned lists the eligible connections (Eligible) that have
// no pinned credential key: their member's vault has not yet signed a
// connection.authenticate.response on the connection, and refuses
// vote.cast with not_signed_in until it has (VAULT-MESSAGING §10.19.5;
// the key is pinned at the first success, §10.4).
func (p *Peer) EligibleUnsigned() []string {
	return p.activeIf(func(c *Connection) bool { return slices.Contains(c.Features, FeatureVote) && len(c.AuthKey) == 0 })
}

// HasPendingSignIn reports whether a sign-in challenge sent to the
// connection awaits its answer or may still be held at the member vault
// (until its exp plus ClockSkew, also after a cancel whose withdraw was
// not sent). It reads the challenges alone: the
// member vault bounds the pending challenges it holds per connection
// (VAULT-MESSAGING §10.4.1), so a caller that sends at most one while
// none is pending stays within the bound.
func (p *Peer) HasPendingSignIn(connID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for _, ch := range p.challenges {
		// A Gone sign-in (cancelled without a withdraw, or just expired) still
		// counts until exp plus the skew: the member vault may still hold it.
		if ch.ConnID == connID && ch.Purpose == peerwire.PurposeSignIn && ch.holds(now) {
			return true
		}
	}
	return false
}
