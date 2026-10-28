package peer

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
)

// Relay error codes the outbox acts on (§8.6, RELAY-PROTOCOL §7.1).
const (
	codeTokenExpired   = "token_expired"
	codeTokenRevoked   = "token_revoked"
	codeTokenUsed      = "token_used"
	codeMailboxUnknown = "mailbox_unknown"
	codeClaimUnknown   = "claim_unknown"
	codeQuotaExceeded  = "quota_exceeded"
)

// outboxMaxBackoff caps the outbox retry backoff (§8.6: 0.25 s × 2ⁿ,
// capped at 30 s; relayclient retries within one attempt).
const outboxMaxBackoff = 30 * time.Second

func (p *Peer) queue(e *outboxEntry, now time.Time) {
	e.ID = p.newID(now)
	p.seq++
	e.Seq = p.seq
	p.outbox = append(p.outbox, e)
	p.markDirty(kindOutbox, e.ID)
}

func (p *Peer) queueDeposit(e *outboxEntry, now time.Time) {
	e.Op = opDeposit
	p.queue(e, now)
}

func (p *Peer) queueRevoke(jti string, now time.Time) {
	p.queue(&outboxEntry{Op: opRevoke, Value: jti}, now)
}

func (p *Peer) queueDeleteClaim(id string, now time.Time) {
	p.queue(&outboxEntry{Op: opDeleteClaim, Value: id}, now)
}

func (p *Peer) outboxByID(id string) *outboxEntry {
	for _, e := range p.outbox {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// dropOutbox removes the entries for which drop is true.
func (p *Peer) dropOutbox(drop func(*outboxEntry) bool) {
	kept := p.outbox[:0]
	for _, e := range p.outbox {
		if drop(e) {
			e.dropped = true
			p.markDirty(kindOutbox, e.ID)
			continue
		}
		kept = append(kept, e)
	}
	p.outbox = kept
}

// retryConn makes a connection's waiting entries eligible again (after a
// fresh token).
func (p *Peer) retryConn(id string) {
	for _, e := range p.outbox {
		if e.ConnID == id && (!e.NotBefore.IsZero() || e.AwaitToken) {
			e.NotBefore, e.AwaitToken = time.Time{}, false
			p.markDirty(kindOutbox, e.ID)
		}
	}
}

// drainOutbox performs the due entries in queue order (§8.3 step 5).
// Deposits to one mailbox stay in order: once one is not delivered, the
// later ones to that mailbox wait too, so a message never overtakes an
// earlier one (an hs.fin or hs.resp must precede traffic in its epoch).
// A deposit waiting for a fresh standing token holds back only the later
// deposits on the standing token.
func (p *Peer) drainOutbox(ctx context.Context) {
	now := p.now()
	blocked := map[string]bool{}
	awaiting := map[string]bool{}
	done := map[*outboxEntry]bool{}
	// A deposit can change the outbox (a failed one ends a handshake,
	// which may start a reconnect): the drain runs over a copy, skips what
	// was removed meanwhile, and leaves what was added to the next one.
	for _, e := range slices.Clone(p.outbox) {
		if ctx.Err() != nil {
			break
		}
		if e.dropped {
			continue
		}
		if e.Op == opDeposit && (blocked[e.Mailbox] || awaiting[e.Mailbox] && e.Token == "") {
			continue
		}
		if c := p.conns[e.ConnID]; e.Op == opDeposit && e.Token == "" && c != nil && c.Reconnecting {
			continue // nothing in the session while a reconnect is open (§6.6)
		}
		if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) {
			done[e] = true
			continue
		}
		if now.Before(e.NotBefore) {
			if e.Op == opDeposit && e.AwaitToken {
				awaiting[e.Mailbox] = true
			} else if e.Op == opDeposit {
				blocked[e.Mailbox] = true
			}
			continue
		}
		var err error
		finished := false
		switch e.Op {
		case opDeposit:
			finished, err = p.deposit(ctx, e, now)
		case opRevoke:
			err = p.cfg.Relay.Revoke(ctx, relayclient.Revocation{Kind: "jti", Value: e.Value})
		case opDeleteClaim:
			err = p.cfg.Relay.DeleteClaim(ctx, e.Value)
			if relayclient.IsCode(err, codeClaimUnknown) {
				err = nil
			}
		}
		p.markDirty(kindOutbox, e.ID)
		if err == nil || finished || e.BestEffort {
			done[e] = true
			continue
		}
		if e.Op == opDeposit && e.AwaitToken {
			awaiting[e.Mailbox] = true
		} else if e.Op == opDeposit {
			blocked[e.Mailbox] = true
		}
		if e.NotBefore.After(now) || ctx.Err() != nil {
			continue
		}
		e.Attempts++
		d := time.Duration(250*(1<<min(e.Attempts, 7))) * time.Millisecond
		e.NotBefore = now.Add(min(d, outboxMaxBackoff))
		p.log().Warn("deposit retry", "op", e.Op, "connection_id", e.ConnID, "attempts", e.Attempts, "err", errCode(err))
	}
	if len(done) > 0 {
		p.dropOutbox(func(e *outboxEntry) bool { return done[e] })
	}
}

// deposit performs one deposit and applies the §8.6 error table. finished
// reports an entry that is done although the deposit failed. A reconnect
// hs.init the relay refuses for good ends the reconnect (reconnect.go).
func (p *Peer) deposit(ctx context.Context, e *outboxEntry, now time.Time) (finished bool, err error) {
	finished, err = p.depositOnce(ctx, e, now)
	if !finished || err == nil || e.Token == "" {
		return finished, err
	}
	if c := p.conns[e.ConnID]; c != nil && c.Reconnecting && e.Token == c.Reconnect.Token {
		// Our hs.init, refused for good: dropping it ends the reconnect
		// (dropOutgoing: reconnect_failed, the connection stale), as the
		// reconnect token is spent and a new try on it cannot succeed.
		p.dropConnOutgoing(c)
	}
	// The hs.resp to a member's reconnect, on the token its hs.init
	// brought: that reconnect cannot complete.
	for id, aw := range p.awaiting {
		if aw.ConnID == e.ConnID && aw.Reconnect != nil && aw.Reconnect.Standing.Token == e.Token {
			p.dropAwaiting(id, now)
		}
	}
	return finished, err
}

func (p *Peer) depositOnce(ctx context.Context, e *outboxEntry, now time.Time) (finished bool, err error) {
	tok := e.Token
	c := p.conns[e.ConnID]
	if tok == "" {
		if c == nil || c.Standing.Token == "" {
			return true, nil // the connection is gone (§7.4: its entries are deleted)
		}
		tok = c.Standing.Token
	}
	_, err = p.cfg.Relay.Deposit(ctx, e.Mailbox, tok, e.Payload)
	if err == nil {
		return false, nil
	}
	var re *relayclient.Error
	if !errors.As(err, &re) {
		return false, err // transport, after relayclient's own retries
	}
	switch re.Code {
	case codeTokenExpired:
		if c != nil && e.Token == "" {
			// §7.2: ask for a fresh standing token; the entry waits for it.
			// (A reconnect, §6.6, is the member vault's to start: it holds
			// our reconnect token.)
			p.refreshHeld(c, now, true)
			e.NotBefore = now.Add(time.Hour)
			e.AwaitToken = true
			e.Attempts++
			return false, err
		}
		return true, err
	case codeTokenRevoked, codeMailboxUnknown:
		// Terminal: stop sending to that mailbox (§8.6).
		if c != nil && e.Token == "" && c.State == StateActive {
			c.State = StateStale
			p.markDirty(kindConn, c.ID)
			p.audit("peer_stale", c.ID)
			p.dropOutbox(func(o *outboxEntry) bool { return o != e && o.ConnID == c.ID })
		}
		return true, err
	case codeQuotaExceeded:
		// §8.6: a quota_exceeded without its quota member (an older relay)
		// is taken for the token's.
		if c != nil && e.Token == "" && (re.Quota == relayclient.QuotaToken || re.Quota == "") {
			// §8.6: the standing token's quota is spent; a fresh token
			// cures it. Other quotas are the member mailbox's: retry later.
			p.refreshHeld(c, now, true)
			e.NotBefore = now.Add(time.Hour)
			e.AwaitToken = true
			e.Attempts++
			return false, err
		}
		return false, err
	case codeTokenUsed:
		p.audit("open_token_used", e.ConnID)
		return true, err
	}
	if re.Status < 500 && re.Status != 429 {
		p.audit("deposit_refused", e.ConnID)
		return true, err
	}
	return false, err
}

// kickEvents wakes the event loop.
func (p *Peer) kickEvents() {
	select {
	case p.evWake <- struct{}{}:
	default:
	}
}

func (p *Peer) eventLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.evWake:
		case <-t.C:
		}
		p.DeliverEvents(ctx)
	}
}

// DeliverEvents hands the persisted events to Config.Events in order,
// deleting each once delivered; it stops at the first failure.
func (p *Peer) DeliverEvents(ctx context.Context) {
	if p.cfg.Events == nil {
		return
	}
	for ctx.Err() == nil {
		p.mu.Lock()
		var e *Event
		if len(p.events) > 0 {
			c := *p.events[0]
			e = &c
		}
		p.mu.Unlock()
		if e == nil {
			return
		}
		if err := p.cfg.Events.Deliver(ctx, e); err != nil {
			p.log().Warn("event delivery", "event_id", e.ID, "type", e.Type, "err", errCode(err))
			return
		}
		p.mu.Lock()
		if len(p.events) > 0 && p.events[0].ID == e.ID {
			p.events = p.events[1:]
			p.markDirty(kindEvent, e.ID)
		}
		err := p.flush(ctx)
		p.mu.Unlock()
		if err != nil {
			p.log().Warn("event delivery", "event_id", e.ID, "err", errCode(err))
			return
		}
	}
}
