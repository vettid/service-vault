package peer

import (
	"bytes"
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
	codeReplayDetected = "replay_detected"
	codeTimestampStale = "timestamp_stale"
)

// OneDepositAttempt wraps a relay client so that each deposit and each
// registration is one attempt, its other calls keeping the client's
// retries (§8.3, a deposit is one client attempt; RELEASE-29 §13). A
// registration retried inside the client could hide a 201 behind the
// next attempt's 200 (mailbox.go).
func OneDepositAttempt(c *relayclient.Client) Relay {
	d := *c
	d.MaxAttempts = 1
	return oneDeposit{Client: c, dep: &d}
}

type oneDeposit struct {
	*relayclient.Client
	dep *relayclient.Client
}

func (o oneDeposit) Deposit(ctx context.Context, mailboxID, token string, payload []byte) (string, error) {
	return o.dep.Deposit(ctx, mailboxID, token, payload)
}

func (o oneDeposit) Register(ctx context.Context) (relayclient.Registration, error) {
	return o.dep.Register(ctx)
}

// outboxMaxBackoff caps the outbox retry backoff (§8.6: 0.25 s × 2ⁿ,
// capped at 30 s). A deposit is one client attempt (OneDepositAttempt),
// so that the tried mark covers every copy that can reach the relay
// (§8.3; RELEASE-29 §13).
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
	restamping := map[string]bool{}
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
		if e.Op == opDeposit && restamping[e.Mailbox] {
			// The mailbox waits for a write; what else comes due to it is
			// re-stamped in this pass too, and goes after that write.
			if !now.Before(e.NotBefore) && p.checkAtDeposit(e, now) == atDepositDrop {
				done[e] = true
			}
			continue
		}
		if e.Op == opDeposit && (blocked[e.Mailbox] || awaiting[e.Mailbox] && e.Token == "" && !e.Refresh) {
			continue // a refresh passes the deposits awaiting a token (§8.4)
		}
		if c := p.conns[e.ConnID]; e.Op == opDeposit && !e.Handshake && c != nil &&
			(e.Token == "" && (c.Reconnecting || c.State == StateStale) || c.currentDemoted()) {
			// Nothing but the handshake while a reconnect is open (RELEASE-29
			// §3); a stale connection's entries wait for a new epoch, which
			// seals them again (§3.4.1: stale is not final). A held entry
			// still ends at its exp or past its window (§8.3 cases 1, 2).
			if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) || p.heldDrop(e, now) {
				done[e] = true
			}
			continue
		}
		if !e.NotAfter.IsZero() && !now.Before(e.NotAfter) {
			done[e] = true
			continue
		}
		if e.Op == opDeposit && !now.Before(e.NotBefore) {
			switch p.checkAtDeposit(e, now) {
			case atDepositDrop:
				done[e] = true
				continue
			case atDepositWait:
				restamping[e.Mailbox] = true // re-sealed: deposited once written, in order
				continue
			}
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
		d := min(time.Duration(250*(1<<min(e.Attempts, 7)))*time.Millisecond, outboxMaxBackoff)
		var re *relayclient.Error
		if errors.As(err, &re) && re.Status == 429 && re.RetryAfter > 0 {
			d = max(d, time.Duration(re.RetryAfter)*time.Second) // §8.6: not before a 429's retry_after
		}
		e.NotBefore = now.Add(d)
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
		// Our hs.init, refused for good (token_revoked: a failed try at
		// once; quota_exceeded; a token or mailbox the relay no longer
		// knows): no try can be deposited on that token, so the reconnect
		// ends, the connection stale (§3.4.1 "The reconnect bound").
		if relayclient.IsCode(err, codeTokenRevoked) || relayclient.IsCode(err, "token_invalid") {
			if relayclient.IsCode(err, codeTokenRevoked) {
				p.recordRevokedHeld(c, e.Token, now)
			}
			c.Reconnect = HeldToken{} // dropped: a bad token cannot pin
			p.markDirty(kindConn, c.ID)
		}
		p.dropConnOutgoing(c)
		p.reconnectFailed(c)
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
		if c == nil {
			return true, nil // the connection is gone (§7.4: its entries are deleted)
		}
		if c.Standing.Token == "" {
			// No standing token held (one was revoked): the entry waits
			// for a valid one (§8.6), which a reconnect brings.
			e.NotBefore, e.AwaitToken = now.Add(time.Hour), true
			return false, errNoStanding
		}
		tok = c.Standing.Token
	}
	_, err = p.cfg.Relay.Deposit(ctx, e.Mailbox, tok, e.Payload)
	if err == nil {
		return false, nil
	}
	var re *relayclient.Error
	if !errors.As(err, &re) {
		e.Tried = true // no answer: it may have reached the relay
		return false, err
	}
	if re.Status >= 500 || re.Code == codeReplayDetected {
		e.Tried = true // §8.3: possibly stored
	}
	if re.Code == codeTimestampStale {
		// About the attempt, not the message: retried. A third refusal
		// is logged once, so that a stuck clock shows (§8.3 case 8).
		if e.StaleTS++; e.StaleTS == 3 {
			p.log().Warn("relay refuses our timestamps", "reason", "relay_clock_stale", "connection_id", e.ConnID)
		}
	}
	switch re.Code {
	case codeTokenExpired:
		if c != nil && e.Token == "" {
			// The entry waits for a fresh standing token. Expired on our
			// clock too, no refresh could be deposited: the service
			// reconnects (§7.2, §8.6; RELEASE-29 §3 item 2), which abandons
			// a pending rekey. Otherwise it asks for a fresh token (§7.2).
			e.NotBefore = now.Add(time.Hour)
			e.AwaitToken = true
			e.Attempts++
			if !now.Before(c.Standing.Exp) {
				p.noTokenReconnect(c, now)
			} else {
				p.refreshHeld(c, now, true)
			}
			return false, err
		}
		return true, err
	case codeTokenRevoked:
		if c != nil && e.Token == "" {
			// §8.6 (0.88.2; RELEASE-29 §3 item 4): the held standing token
			// is revoked. That token ends, not the connection: this entry
			// and the others wait for a valid one, which the reconnect the
			// service starts brings. Its pending epoch's hs.fin refused so
			// shows that the member dropped its answer: that epoch is
			// abandoned, and the reconnect starts at once (§6.3.1 "A
			// carried token refused").
			if c.Standing.Token == tok {
				p.recordRevokedHeld(c, tok, now)
				c.Standing, c.RefreshID = HeldToken{}, ""
				p.markDirty(kindConn, c.ID)
			}
			p.audit("standing_token_revoked", c.ID)
			e.NotBefore = now.Add(time.Hour)
			e.AwaitToken = true
			e.Attempts++
			if c.Pending != nil && bytes.Equal(e.FinEpoch, c.Pending.ID) {
				p.abandonPending(c, "fin_revoked", true, now)
			} else {
				p.noTokenReconnect(c, now)
			}
			return false, err
		}
		if c != nil && e.CarriedTok && !(c.Pending != nil && bytes.Equal(e.FinEpoch, c.Pending.ID)) {
			// An hs.confirm or hs.resp on a member's carried token: that
			// handshake was abandoned there (§6.3.1 "A carried token
			// refused"); for an hs.resp, deposit drops our answer.
			p.carriedRevoked(c, e.Token, now)
		}
		if c != nil && c.Pending != nil && len(e.FinEpoch) > 0 && bytes.Equal(e.FinEpoch, c.Pending.ID) {
			// A reconnect's hs.fin on the hs.resp's carried token, refused:
			// the member dropped its answer. The epoch is abandoned (its
			// carried tokens with it) and a new try goes on the held
			// reconnect token, not counted as failed (§6.3.1 "A carried
			// token refused").
			p.recordRevokedHeld(c, e.Token, now)
			p.abandonPending(c, "fin_revoked", true, now)
		}
		return true, err
	case codeMailboxUnknown:
		// Terminal: stop sending to that mailbox (§8.6).
		if c != nil && e.Token == "" && c.State == StateActive {
			c.State = StateStale
			p.markDirty(kindConn, c.ID)
			p.audit("peer_stale", c.ID)
			p.dropUndelivered(c, "undelivered_mailbox_unknown", e)
			p.auditRefused(e, "undelivered_mailbox_unknown")
		}
		return true, err
	case codeQuotaExceeded:
		if c != nil && e.Token != "" && c.Reconnecting && e.Token == c.Reconnect.Token {
			return true, err // a try's hs.init refused for quota: the bound ends the reconnect (§3.4.1)
		}
		// §8.6: a quota_exceeded without its quota member (an older relay)
		// is taken for the token's.
		if c != nil && e.Token == "" && (re.Quota == relayclient.QuotaToken || re.Quota == "") {
			// §8.6 (0.88.6): the standing token's quota is spent. Before its
			// exp a fresh token cures it: the entry waits and a refresh is
			// asked. The refresh itself refused for the quota is not sent
			// again, and the service reconnects at once, as it does for a
			// deposit refused after the exp (RELEASE-29 §3 item 5); before
			// the exp, not without a valid reconnect token (the reconnect
			// could not start: it goes on asking). Other quotas are the
			// member mailbox's: retry later.
			past := !now.Before(c.Standing.Exp)
			if e.Refresh && (past || c.reconnectValid(now)) {
				c.RefreshID = ""
				p.markDirty(kindConn, c.ID)
				p.noTokenReconnect(c, now)
				return true, err
			}
			e.NotBefore = now.Add(time.Hour)
			e.AwaitToken = true
			e.Attempts++
			if past {
				p.noTokenReconnect(c, now)
			} else if !e.Refresh {
				p.refreshHeld(c, now, true)
			}
			return false, err
		}
		return false, err
	case codeTokenUsed:
		p.audit("open_token_used", e.ConnID)
		return true, err
	case codeTimestampStale, codeReplayDetected:
		// About the attempt, not the message (§8.3 case 8): retried
		// with the backoff, freshly signed, never ended.
		return false, err
	}
	if re.Status < 500 && re.Status != 429 {
		// §8.3 case 8: not delivered, audited.
		p.auditRefused(e, "undelivered_refused")
		return true, err
	}
	return false, err
}

// errNoStanding: a deposit on the standing token waits, none being held.
var errNoStanding = errors.New("peer: no standing token held")

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
