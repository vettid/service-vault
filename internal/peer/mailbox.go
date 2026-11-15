package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
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

// TombstoneSkew is how long after a relay's reported tokens-not-before
// the service waits before it mints a token for the mailbox: the clock
// skew RELAY-PROTOCOL §4.1 allows, so that a token's iat (backdated 60 s,
// §5.2) is at or after it and not ahead of the relay's clock (§6.1).
const TombstoneSkew = 90 * time.Second

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
	// Tombstone is the latest tokens-not-before a relay that reports
	// tombstones gave (RELAY-PROTOCOL §6.1) that the service has judged:
	// the same time again (a relay keeps it for as long as it keeps the
	// tombstone, some for good) is nothing new.
	Tombstone time.Time `json:"tombstone,omitzero"`
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
// alarm relay_mailbox_lost is raised and a re-mint is owed,
// FreshMailboxWait after the answer. A start that finds a re-mint owed
// that no connection has been done for raises the alarm again: its first
// raising may have been lost to a crash after the record's write.
//
// A relay that reports tombstones (RELAY-PROTOCOL 0.12.0 §6.1) says
// instead (tombstone):
//   - tokens_not_before T: tokens with iat before T are refused. A loss
//     only if a token the service relies on is older than T (a T it
//     judged before is nothing new: relays may report it for good); the
//     re-mint is then owed at T + TombstoneSkew, not FreshMailboxWait
//     from the answer. Either way nothing is minted before T +
//     TombstoneSkew.
//   - no T: no token is refused because of a deletion, whatever the
//     attempted mark says. A 201 for a mailbox registered before means
//     the relay lost what it held: the messages since the last collect,
//     and its denylist, so revocations are sent again (dataLost).
//
// While running (after a collect's mailbox_unknown), the relay call gets
// registerRunningTimeout: it runs under p.mu, and the loss is proven, so
// an answer cut short costs nothing a full one wouldn't.
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
	rctx := ctx
	if p.started {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, registerRunningTimeout)
		defer cancel()
	}
	reg, err := p.cfg.Relay.Register(rctx)
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
	now := p.now()
	before := r.Registered || len(p.conns) > 0
	lost, dataLost := false, false
	nb, reported := reg.Tombstone()
	p.mintFloor = nb
	switch {
	case !reported: // a relay before 0.12.0: the answer says nothing of tombstones
		lost = before && (reg.Created || prev)
		if lost {
			r.RemintAfter = now.Add(FreshMailboxWait)
		}
	case !nb.IsZero():
		if nb.After(r.Tombstone) {
			if lost = p.reliesBefore(nb, now); lost {
				r.RemintAfter = maxTime(now, nb.Add(TombstoneSkew))
			}
			r.Tombstone = nb
		}
	default:
		dataLost = before && reg.Created
	}
	r.Registered, r.Attempted = true, false
	if err := p.writeRelayReg(ctx, r); err != nil {
		return fmt.Errorf("peer: register: %w", err)
	}
	p.remintAt = r.RemintAfter
	if !lost && !p.started && !r.RemintAfter.IsZero() && !p.remintBegun(r.RemintAfter) {
		lost = true // raised again: see above
	}
	if lost {
		// After the write, so that a crash before it raises the alarm again
		// at the next start rather than never.
		attrs := []any{"alarm", "relay_mailbox_lost", "created", reg.Created, "connections", len(p.conns)}
		if !nb.IsZero() {
			attrs = append(attrs, "tokens_not_before", nb)
		}
		p.log().Error("the service's relay mailbox was lost and made again empty: messages members deposited since the last collect are gone, and every member's tokens for it are minted again", attrs...)
	}
	if dataLost {
		n := p.denyAgain(now)
		p.log().Error("the relay holds no record of the service's mailbox (its data was lost, or it was rebuilt): messages members deposited since the last collect are gone; the members' tokens still work, and revocations are sent again",
			"alarm", "relay_mailbox_lost", "created", true, "tokens_kept", true, "revocations", n, "connections", len(p.conns))
	}
	return nil
}

// reliesBefore reports whether a token the service issued and still
// relies on (not revoked, not expired) has an iat before nb, or an
// unknown one (a record from before Iat was kept): the relay refuses it.
func (p *Peer) reliesBefore(nb, now time.Time) bool {
	for _, t := range p.issued {
		if t.Denied || !now.Before(t.Exp) {
			continue
		}
		if t.Iat.Before(nb) { // a zero (unknown) iat is before any nb
			return true
		}
	}
	return false
}

// denyAgain sends again every revocation still in force, after a relay
// lost its denylist and its record of used one-shot tokens (RELAY-PROTOCOL
// §6.1): every unexpired token revoked. That covers the used ones: an
// invitation is withdrawn, its open token revoked, in the handling that
// marks it used (handshake.go). It returns how many it queued.
func (p *Peer) denyAgain(now time.Time) int {
	jtis := make([]string, 0, len(p.issued))
	for jti, t := range p.issued {
		if t.Denied && now.Before(t.Exp) {
			jtis = append(jtis, jti)
		}
	}
	sort.Strings(jtis)
	for _, jti := range jtis {
		p.denyJTI(jti, now)
	}
	return len(jtis)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// errMintWait is a token mint refused during a lost mailbox's wait: the
// relay would refuse a token issued then (RELAY-PROTOCOL §6.10).
var errMintWait = errors.New("peer: the relay mailbox was made again: tokens can be minted again in a few minutes")

// ErrMailboxRenewing is what CreateInvite answers during that wait.
var ErrMailboxRenewing = errMintWait

// remintOwed reports whether a lost mailbox's re-mint is owed and not yet
// done for c.
func (p *Peer) remintOwed(c *Connection) bool {
	return !p.remintAt.IsZero() && !c.MailboxRemint.Equal(p.remintAt)
}

// registerRunningTimeout bounds a registration while running.
const registerRunningTimeout = 5 * time.Second

// remintBegun reports whether any connection has been done for the
// re-mint owed at t.
func (p *Peer) remintBegun(t time.Time) bool {
	for _, c := range p.conns {
		if c.MailboxRemint.Equal(t) {
			return true
		}
	}
	return false
}

// mintWait reports whether no token may be minted now: a lost mailbox's
// FreshMailboxWait has not passed, a registration after a collect's
// mailbox_unknown (which proves the loss) is still owed, or the relay's
// tokens-not-before plus TombstoneSkew has not passed (a token minted now
// would be refused).
func (p *Peer) mintWait(now time.Time) bool {
	return p.registerOwed || now.Before(p.mintWaitUntil())
}

// mintWaitUntil is when the wait mintWait reports ends, if no
// registration is owed: the later of the re-mint owed and the relay's
// tokens-not-before plus TombstoneSkew (zero when neither).
func (p *Peer) mintWaitUntil() time.Time {
	var floor time.Time
	if !p.mintFloor.IsZero() {
		floor = p.mintFloor.Add(TombstoneSkew)
	}
	return maxTime(p.remintAt, floor)
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

// remintChunk is how many connections one re-mint step covers: each
// gives about five changes (two tokens, two outbox entries, its record),
// so a step's write stays one transaction of the store (at most 100).
const remintChunk = 15

// remintLost re-mints, once FreshMailboxWait has passed, every active
// connection's standing and reconnect tokens after a lost mailbox, and
// sends them (relay.token.issued). It goes by chunks of remintChunk
// connections, each in two writes, as endInTwoWrites does: first the
// tokens, the outbox entries and the records they move, then each done
// connection's mark (Connection.MailboxRemint). A write that fails leaves
// the marks unset, so those connections are minted again later (a second
// token is harmless: the later exp wins). A connection reconnecting, or
// whose outbox is full, is left for a later call. Once every active
// connection is done, the owed mark is cleared in a write of its own,
// only if the stored one is still the one done.
func (p *Peer) remintLost(ctx context.Context, now time.Time) error {
	if p.remintAt.IsZero() || p.mintWait(now) {
		return nil
	}
	if err := p.flush(ctx); err != nil { // nothing else rides on the steps' writes
		return err
	}
	var todo []*Connection
	for _, c := range p.conns {
		if c.State == StateActive && !c.MailboxRemint.Equal(p.remintAt) {
			todo = append(todo, c)
		}
	}
	sort.Slice(todo, func(i, j int) bool { return todo[i].ID < todo[j].ID })
	left := false
	for len(todo) > 0 {
		n := min(remintChunk, len(todo))
		var done []*Connection
		for _, c := range todo[:n] {
			if p.issue(c, tokStanding, false, now) && p.issue(c, tokReconnect, false, now) {
				done = append(done, c)
			} else {
				left = true
			}
		}
		todo = todo[n:]
		if err := p.flush(ctx); err != nil {
			return err
		}
		for _, c := range done {
			c.MailboxRemint = p.remintAt
			p.markDirty(kindConn, c.ID)
		}
		if err := p.flush(ctx); err != nil {
			return err
		}
	}
	if left {
		return nil
	}
	r, err := p.readRelayReg(ctx)
	if err != nil {
		return err
	}
	if !r.RemintAfter.Equal(p.remintAt) {
		p.remintAt = r.RemintAfter // a newer loss: its own re-mint goes on
		return nil
	}
	r.RemintAfter = time.Time{}
	if err := p.writeRelayReg(ctx, r); err != nil {
		return err
	}
	p.remintAt = time.Time{}
	return nil
}
