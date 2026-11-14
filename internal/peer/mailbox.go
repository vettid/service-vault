package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// kindRelayReg holds one record: what the service knows of its own relay
// mailbox's registration (GC #10525).
const (
	kindRelayReg = "relayreg"
	relayRegID   = "mailbox"
)

// FreshMailboxWait is how long after a fresh mailbox's answer the service
// waits before it mints tokens for it: the relay refuses tokens issued
// before the deletion plus 90 s (RELAY-PROTOCOL §6.10), and the service
// can't know when the deletion was, so it counts from the answer, adding
// the clock skew RELAY-PROTOCOL §4.1 allows and the tokens' 60-second
// backdating (VAULT-MESSAGING §3.4 "After the grace": 241 s as built).
const FreshMailboxWait = 241 * time.Second

// relayReg is the record.
type relayReg struct {
	// Registered: the mailbox was registered before (a 200 or a 201).
	Registered bool `json:"registered,omitempty"`
	// Attempted is set before each registration and cleared when its
	// answer is recorded: set at a start, the last one got no answer (or
	// a 5xx), and may have made the mailbox afresh unseen.
	Attempted bool `json:"attempted,omitempty"`
	// RemintAfter, when set, is a lost mailbox's re-mint owed: from then
	// on every member's standing and reconnect tokens are minted again
	// and sent; each connection records the value it was done for
	// (Connection.MailboxRemint), and the mark clears when all are.
	RemintAfter time.Time `json:"remint_after,omitzero"`
}

func (p *Peer) readRelayReg(ctx context.Context) (relayReg, error) {
	var r relayReg
	b, ok, err := p.cfg.Store.Get(ctx, kindRelayReg, relayRegID)
	if err != nil || !ok {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("peer: %s record: %w", kindRelayReg, err)
	}
	return r, nil
}

func (p *Peer) writeRelayReg(ctx context.Context, r relayReg) error {
	b, _ := json.Marshal(r)
	return p.cfg.Store.Apply(ctx, []Change{{Kind: kindRelayReg, ID: relayRegID, Data: b}})
}

// register registers the service's mailbox (RELAY-PROTOCOL §6.1) and
// tells a lost mailbox from a first registration. It runs at a start,
// after the load. A mailbox the service had registered before (or, for a
// table from before this record, one with connections) that the relay
// answers 201 was deleted and made again empty: every token it issued
// before is refused from now on (§6.10), and what members deposited since
// the service's last collect is gone. A 200 after an attempt whose answer
// was never recorded may hide such a 201, and counts as one. Then the
// alarm relay_mailbox_lost is raised once and a re-mint is owed,
// FreshMailboxWait after the answer.
func (p *Peer) register(ctx context.Context) error {
	r, err := p.readRelayReg(ctx)
	if err != nil {
		return err
	}
	prev := r.Attempted
	r.Attempted = true
	if err := p.writeRelayReg(ctx, r); err != nil {
		return fmt.Errorf("peer: register: %w", err)
	}
	reg, err := p.cfg.Relay.Register(ctx)
	if err != nil {
		if registerMadeNothing(err) {
			// This attempt made nothing: the mark goes back to what an
			// earlier attempt left (which may have made the mailbox).
			r.Attempted = prev
			_ = p.writeRelayReg(ctx, r)
		}
		return fmt.Errorf("peer: register: %w", err)
	}
	p.limits = reg.Limits
	before := r.Registered || len(p.conns) > 0
	if before && (reg.Created || prev) {
		r.RemintAfter = p.now().Add(FreshMailboxWait)
		p.log().Error("the service's relay mailbox was lost and made again empty: messages members deposited since the last collect are gone, and every member's tokens for it are minted again",
			"alarm", "relay_mailbox_lost", "created", reg.Created, "connections", len(p.conns))
	}
	r.Registered, r.Attempted = true, false
	if err := p.writeRelayReg(ctx, r); err != nil {
		return fmt.Errorf("peer: register: %w", err)
	}
	p.remintAt = r.RemintAfter
	return nil
}

// registerMadeNothing reports whether a failed registration certainly
// made nothing at the relay: the relay's own refusal (a 4xx, 429
// included, but not replay_detected, which shows an earlier copy of the
// request did reach it), or a request that never left (a dial or DNS
// failure). Anything else (no answer, a 5xx) may hide a fresh mailbox.
func registerMadeNothing(err error) bool {
	var re *relayclient.Error
	if errors.As(err, &re) {
		return re.Status >= 400 && re.Status < 500 && re.Code != codeReplayDetected
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return true
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "dial"
}

// remintLost re-mints, once FreshMailboxWait has passed, every active
// connection's standing and reconnect tokens after a lost mailbox, and
// sends them (relay.token.issued). A connection reconnecting, or whose
// outbox is full, is done at a later housekeeping; the mark clears once
// every active connection is done.
func (p *Peer) remintLost(now time.Time) {
	if p.remintAt.IsZero() || now.Before(p.remintAt) {
		return
	}
	done := true
	for _, c := range p.conns {
		if c.State != StateActive || c.MailboxRemint.Equal(p.remintAt) {
			continue
		}
		if !p.issue(c, tokStanding, false, now) || !p.issue(c, tokReconnect, false, now) {
			done = false
			continue
		}
		c.MailboxRemint = p.remintAt
		p.markDirty(kindConn, c.ID)
	}
	if done {
		p.remintAt = time.Time{}
		b, _ := json.Marshal(relayReg{Registered: true})
		p.extra = append(p.extra, Change{Kind: kindRelayReg, ID: relayRegID, Data: b})
	}
}
