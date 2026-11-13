package peer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Release 29, the responder half (VAULT-MESSAGING 0.89.2 §6.3.1;
// docs/RELEASE-29.md). The service activates a member's rekey or reconnect
// at its verified hs.fin and sends hs.confirm under the new epoch. Its
// confirmed epoch with a member is the newest, in the order epochs became
// current, in which the member sent it anything but hs.fin, or the
// member's first epoch; it never moves back. While it is not current it
// keeps its rk and receive keys (up to ConfirmedKeysFor), and hs.confirm
// goes out again for each collected batch holding a message under it, and
// every ConfirmResend while the current epoch, one the service activated
// as responder, is not confirmed.

// ConfirmedKeysFor is how long a responder's confirmed epoch keeps its
// keys while not current, from the activation that superseded it
// (§6.3.1 Lifetimes).
const ConfirmedKeysFor = 48 * 24 * time.Hour

// ConfirmResend is how long after the last hs.confirm the service queues
// one again while the current epoch it activated as responder is
// unconfirmed (§6.3.1 "hs.confirm again"): 12 days, not scaled.
const ConfirmResend = 12 * 24 * time.Hour

// serviceFeatures are the capabilities the service advertises, in every
// message's inner features and in its profile.update (§10.8, §6.3.1
// Capability; RELEASE-29 §6): sorted, each once. relay_follow is not
// advertised: a vault advertises it only once it implements both §3.4.1
// and §3.4.2 (VAULT-MESSAGING 0.90.0), and the service's §3.4.2 is not
// built yet.
var serviceFeatures = []string{handshake.CapConfirm}

// features returns a copy of serviceFeatures for one message.
func features() []string { return slices.Clone(serviceFeatures) }

// EpochMeta records one of a connection's epochs, in the order they
// became current (§6.3.1).
type EpochMeta struct {
	ID []byte `json:"id"`
	// Mine is set for an epoch the service began (its own rekey or
	// reconnect).
	Mine bool `json:"mine,omitempty"`
	// Superseded is when a later epoch became current.
	Superseded time.Time `json:"superseded,omitzero"`
	// Received is §6.3.1's received flag (R29-F3): a message from the
	// member other than hs.fin opened under the epoch and was accepted.
	Received bool `json:"received,omitempty"`
	// Destroyed by rule E (§6.3.1), with the accepted hs.init's inner ts:
	// a later message under it is fork evidence.
	Destroyed bool      `json:"destroyed,omitempty"`
	DestroyTS time.Time `json:"destroy_ts,omitzero"`
	// Signer is the member's identity key when the epoch became current
	// (§3.4.1 "Fork by ctx" judges by it); empty on older records.
	Signer []byte `json:"signer,omitempty"`
}

func (c *Connection) epochIndex(id []byte) int {
	for i := range c.Epochs {
		if bytes.Equal(c.Epochs[i].ID, id) {
			return i
		}
	}
	return -1
}

func (c *Connection) epochMeta(id []byte) *EpochMeta {
	if i := c.epochIndex(id); i >= 0 {
		return &c.Epochs[i]
	}
	return nil
}

// initEpochs gives a connection stored before the epoch list one: its
// current epoch, confirmed.
func (c *Connection) initEpochs() {
	if c.Epochs == nil && len(c.LastEpochID) > 0 {
		c.Epochs = []EpochMeta{{ID: bytes.Clone(c.LastEpochID)}}
		c.Confirmed = bytes.Clone(c.LastEpochID)
	}
	// A record from before signers were kept: with no link followed, the
	// member's key never changed, so it signed them all.
	if len(c.Chain) == 0 {
		for i := range c.Epochs {
			if len(c.Epochs[i].Signer) == 0 {
				c.Epochs[i].Signer = bytes.Clone(c.Peer.IK)
			}
		}
	}
}

// recordActivated records id as the connection's current epoch: the
// previous ones are superseded now. A connection's first epoch is its
// confirmed epoch.
func (p *Peer) recordActivated(c *Connection, id []byte, mine bool, now time.Time) {
	for i := range c.Epochs {
		if e := &c.Epochs[i]; e.Superseded.IsZero() && !bytes.Equal(e.ID, id) {
			e.Superseded = now
		}
	}
	if e := c.epochMeta(id); e != nil {
		e.Superseded = time.Time{}
	} else {
		c.Epochs = append(c.Epochs, EpochMeta{ID: bytes.Clone(id), Mine: mine, Signer: bytes.Clone(c.Peer.IK)})
	}
	if c.Confirmed == nil {
		c.Confirmed = bytes.Clone(id)
	}
	p.pruneEpochs(c, now)
}

// setConfirmed moves the confirmed epoch to id if id became current after
// it (it never moves back). The epoch it leaves, if not current, keeps its
// keys 16 days from now, as any previous epoch's.
func (p *Peer) setConfirmed(c *Connection, id []byte, now time.Time) {
	old := c.Confirmed
	if bytes.Equal(old, id) || c.epochIndex(id) <= c.epochIndex(old) {
		return
	}
	c.Confirmed = bytes.Clone(id)
	c.Abandoned = nil // a newer epoch is confirmed (§6.3.1 Initiator)
	p.markDirty(kindConn, c.ID)
	p.adoptReached(c, id, now) // before the handler of the message that moved it
	if old != nil && !bytes.Equal(old, c.LastEpochID) && c.kr != nil {
		var eid [suite.EpochIDSize]byte
		copy(eid[:], old)
		c.kr.Release(eid, now.Add(handshake.ReceiveKeyRetention))
	}
}

// pruneEpochs drops the records nothing needs any more: superseded more
// than ConfirmedKeysFor plus 16 days ago, neither current nor confirmed.
func (p *Peer) pruneEpochs(c *Connection, now time.Time) {
	keep := c.Epochs[:0]
	for _, e := range c.Epochs {
		if e.Superseded.IsZero() || bytes.Equal(e.ID, c.Confirmed) || bytes.Equal(e.ID, c.LastEpochID) ||
			now.Sub(e.Superseded) < ConfirmedKeysFor+handshake.ReceiveKeyRetention {
			keep = append(keep, e)
		}
	}
	c.Epochs = keep
}

// noteFromMember applies §6.3.1 to a message from the member, other than
// hs.fin, that opened under ep and passed the sender and suspension
// checks, before anything else is done with it: a destroyed epoch's
// refusal or fork evidence (it reports true: the message is dealt with),
// the confirmation of the service's pending epoch, the received flag, the
// confirmed epoch, and hs.confirm again for a message under a confirmed
// epoch that is not current, while the current one is a member's the
// service activated as responder (queued once per batch, reconfirmAll),
// and a stale reconnect answer's end.
func (p *Peer) noteFromMember(c *Connection, ep *handshake.Epoch, in *envelope.Inner, now time.Time) bool {
	if ep == nil {
		return false
	}
	eid := ep.ID()
	id := eid[:]
	if e := c.epochMeta(id); e != nil && e.Destroyed {
		p.destroyedEpochMessage(c, e, in, now) // rule E: refused, or fork evidence
		return true
	}
	if pe := c.Pending; pe != nil && bytes.Equal(pe.ID, id) {
		p.confirmPending(c, now) // §6.3.1 Initiator: first, in this write
	}
	if e := c.epochMeta(id); e != nil && !e.Received {
		e.Received = true
		p.markDirty(kindConn, c.ID)
	}
	p.setConfirmed(c, id, now)
	cur := c.epochMeta(c.LastEpochID)
	if cur != nil && !cur.Mine && bytes.Equal(c.Confirmed, id) && !bytes.Equal(c.Confirmed, c.LastEpochID) {
		if p.reconfirm == nil {
			p.reconfirm = map[string]bool{}
		}
		p.reconfirm[c.ID] = true
	}
	p.dropStaleReconnectAnswers(c, id, in.TS, now)
	return false
}

// reconfirmAll queues hs.confirm for each connection the batch marked;
// none once the current epoch's carried tokens were discarded (intended:
// "hs.confirm again" stops for it, the per-batch one too).
func (p *Peer) reconfirmAll(now time.Time) {
	for id := range p.reconfirm {
		if c := p.conns[id]; c != nil && !c.confirmStopped() {
			p.replaceStaleConfirm(c, now)
			if !p.confirmQueued(c) {
				p.queueConfirm(c, now)
			}
		}
	}
	p.reconfirm = nil
}

// replaceStaleConfirm drops a waiting hs.confirm queued more than
// RestampAfter ago (it waited for a token or behind a quota, and keeps
// its ts: the member would drop it past its 16-day window), so that a
// fresh one takes its place.
func (p *Peer) replaceStaleConfirm(c *Connection, now time.Time) {
	if now.Sub(c.ConfirmAt) <= RestampAfter {
		return
	}
	p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == c.ID && e.Confirm })
}

// queueConfirm queues hs.confirm (body {}, durable, never answered) to a
// connection under its current epoch. It is exempt from MaxOutboxPerConn,
// and waits, not queued, while a reconnect of the service's is open
// (ConfirmAt then keeps the last one's time, so tickConfirm sends it
// later).
func (p *Peer) queueConfirm(c *Connection, now time.Time) bool {
	if c.kr == nil || c.kr.Current() == nil || c.State != StateActive || c.Reconnecting {
		return false
	}
	in := &envelope.Inner{ID: p.newID(now), Type: handshake.TypeConfirm, TS: now, Body: json.RawMessage(`{}`), Features: features()}
	raw, err := c.kr.Current().Seal(in)
	if err != nil {
		return false
	}
	tok := c.confirmToken(now) // the epoch's carried standing token while it waits
	p.queueDeposit(&outboxEntry{ConnID: c.ID, Mailbox: c.Peer.Relay.Mailbox, Token: tok, Payload: raw, Confirm: true, CarriedTok: tok != ""}, now)
	c.ConfirmAt = now
	p.markDirty(kindConn, c.ID)
	return true
}

// confirmQueued reports whether an hs.confirm to c is still in the outbox.
func (p *Peer) confirmQueued(c *Connection) bool {
	for _, e := range p.outbox {
		if e.ConnID == c.ID && e.Confirm {
			return true
		}
	}
	return false
}

// tickConfirm (housekeeping): while c's current epoch is one the service
// activated as responder and the confirmed epoch has not reached it,
// hs.confirm is queued again ConfirmResend after the last one, unless one
// is still in the outbox.
func (p *Peer) tickConfirm(c *Connection, now time.Time) {
	cur := c.epochMeta(c.LastEpochID)
	if cur == nil || cur.Mine || c.epochIndex(c.Confirmed) >= c.epochIndex(c.LastEpochID) || c.confirmStopped() {
		return
	}
	if p.confirmQueued(c) {
		p.replaceStaleConfirm(c, now)
		if p.confirmQueued(c) {
			return
		}
		p.queueConfirm(c, now)
		return
	}
	if now.Sub(c.ConfirmAt) < ConfirmResend {
		return
	}
	p.queueConfirm(c, now)
}

// resealAtKeyChange is §8.3 "Re-sealed at a key change" (0.88.7;
// RELEASE-29 §13): just before c's current epoch is replaced by next,
// every durable entry to c still waiting in the outbox under the current
// epoch is sealed again under next, in its place, with the same inner id
// and a fresh ts; one that may already have reached the relay (a deposit
// tried) keeps its ts, and is not delivered once that is past the durable
// window. A waiting hs.confirm for the replaced epoch is dropped (the new
// epoch gets its own); an expired entry is dropped (drop.held_expired).
// Handshake messages, and entries sealed under another epoch, are left as
// they are.
func (p *Peer) resealAtKeyChange(c *Connection, next *handshake.Epoch, now time.Time) {
	if c.kr == nil || c.kr.Current() == nil {
		return
	}
	cur := c.kr.Current()
	keep := p.outbox[:0]
	for _, e := range p.outbox {
		if e.ConnID != c.ID || e.Op != opDeposit || e.BestEffort || len(e.Payload) == 0 {
			keep = append(keep, e)
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil {
			keep = append(keep, e)
			continue
		}
		if e.Handshake {
			keep = append(keep, e) // a handshake message is never sealed again
			continue
		}
		in, err := cur.OpenSent(env)
		if err != nil || in.Type == handshake.TypeInit || in.Type == handshake.TypeFin {
			keep = append(keep, e) // not ours under this epoch, or a handshake message
			continue
		}
		drop := ""
		switch {
		case e.Confirm:
			drop = "-" // superseded, without audit
		case !in.Exp.IsZero() && !now.Before(in.Exp):
			drop = "held_expired"
		case e.Tried && now.Sub(in.TS) >= DedupeRetention:
			drop = "undelivered_window"
		}
		if drop == "" {
			if !e.Tried {
				in.TS = now
			}
			in.Seq = 0
			raw, err := next.Seal(in)
			if err != nil {
				drop = "held_unsealable"
			} else {
				e.Payload = raw
				p.markDirty(kindOutbox, e.ID)
				keep = append(keep, e)
				continue
			}
		}
		if drop != "-" {
			p.logDrop(c, drop, in)
		}
		e.dropped = true
		p.markDirty(kindOutbox, e.ID)
	}
	p.outbox = keep
}

// rekeyKey is the dedupe key (kindInner) of a member's rekey hs.init we
// answered, by its th1 (R29-T3): it is answered once.
func rekeyKey(th1 [32]byte) string { return "rekey|" + hex.EncodeToString(th1[:]) }

// profileExtras are the members the service adds to its profile.update
// after the core (§10.8): no items, and its features.
var profileExtras = func() []byte {
	b, _ := json.Marshal(map[string]any{"items": []any{}, "features": serviceFeatures})
	return b
}()

// RestampAfter is how old an untried waiting message may be before it is
// sealed again with a fresh ts at deposit: §8.4's 16 days less the
// relay's 14-day hold (§8.3 "At deposit").
const RestampAfter = 2 * 24 * time.Hour

const (
	atDepositGo = iota
	atDepositWait
	atDepositDrop
)

// checkAtDeposit is §8.3 "At deposit" for a waiting durable message to a
// connection, sealed under its current epoch (not a handshake message,
// an hs.confirm or a best-effort notice): an untried one older than
// RestampAfter is sealed again with a fresh ts and a new seq and waits
// for the write, the mailbox's later deposits behind it (one that cannot
// be sealed again goes as it is within the 16-day window, and is not
// delivered past it, held_unsealable); a
// tried one past the 16-day window is not delivered; a tried one older
// than RestampAfter goes as it is, noted once (unconfirmed_late).
func (p *Peer) checkAtDeposit(e *outboxEntry, now time.Time) int {
	c := p.conns[e.ConnID]
	if c == nil || e.Confirm || e.Handshake || e.BestEffort || e.Token != "" || len(e.Payload) == 0 || c.kr == nil || c.kr.Current() == nil {
		return atDepositGo
	}
	env, err := envelope.Parse(e.Payload)
	if err != nil {
		return atDepositGo
	}
	in, err := c.kr.Current().OpenSent(env)
	if err != nil || in.Type == handshake.TypeInit || in.Type == handshake.TypeFin {
		return atDepositGo // another epoch's, or a handshake message
	}
	age := now.Sub(in.TS)
	switch {
	case !e.Tried && age > RestampAfter:
		in.TS, in.Seq = now, 0
		raw, err := c.kr.Current().Seal(in)
		if err != nil && age < DedupeRetention {
			return atDepositGo // as it is, while within the window
		}
		if err != nil {
			p.logDrop(c, "held_unsealable", in)
			return atDepositDrop
		}
		e.Payload = raw
		p.markDirty(kindOutbox, e.ID)
		p.markDirty(kindConn, c.ID) // the epoch's send count moved
		return atDepositWait
	case e.Tried && age >= DedupeRetention:
		p.logDrop(c, "undelivered_window", in)
		return atDepositDrop
	case e.Tried && age > RestampAfter && !e.Late:
		e.Late = true
		p.markDirty(kindOutbox, e.ID)
		p.log().Warn("deposited late: it may not be delivered", "reason", "unconfirmed_late", "connection_id", c.ID, "ref", in.ID, "type", in.Type)
	}
	return atDepositGo
}

// heldDrop reports whether a held durable entry (behind an open reconnect,
// or to a stale connection) ends while it waits: its exp passed
// (held_expired), or it was tried and is past the 16-day window
// (undelivered_window), each audited (§8.3 cases 1, 2).
func (p *Peer) heldDrop(e *outboxEntry, now time.Time) bool {
	c := p.conns[e.ConnID]
	if c == nil || e.Confirm || e.BestEffort || len(e.Payload) == 0 || c.kr == nil || c.kr.Current() == nil {
		return false
	}
	env, err := envelope.Parse(e.Payload)
	if err != nil {
		return false
	}
	in, err := c.kr.Current().OpenSent(env)
	if err != nil || in.Type == handshake.TypeInit || in.Type == handshake.TypeFin {
		return false
	}
	switch {
	case !in.Exp.IsZero() && !now.Before(in.Exp):
		p.logDrop(c, "held_expired", in)
		return true
	case e.Tried && now.Sub(in.TS) >= DedupeRetention:
		p.logDrop(c, "undelivered_window", in)
		return true
	}
	return false
}

// logDrop audits one waiting message that is not delivered (§8.3 "Not
// delivered"): drop.<reason>, with the inner id as ref.
func (p *Peer) logDrop(c *Connection, reason string, in *envelope.Inner) {
	p.log().Warn("drop", "reason", reason, "connection_id", c.ID, "ref", in.ID, "type", in.Type)
}

// dropUndelivered ends every waiting durable message to c, each with its
// own audit entry (drop.<reason>; §8.3 cases 4, 5 and 7): the connection
// is removed or replaced, its mailbox is unknown, or it is suspended.
// Handshake messages, hs.confirm and best-effort notices end without one.
// keep spares an entry (the one being refused).
func (p *Peer) dropUndelivered(c *Connection, reason string, keep *outboxEntry) {
	var cur *handshake.Epoch
	if c.kr != nil {
		cur = c.kr.Current()
	}
	p.dropOutbox(func(e *outboxEntry) bool {
		if e.ConnID != c.ID || e == keep {
			return false
		}
		if cur != nil && e.Op == opDeposit && e.Token == "" && !e.BestEffort && !e.Confirm {
			if env, err := envelope.Parse(e.Payload); err == nil {
				if in, err := cur.OpenSent(env); err == nil && in.Type != handshake.TypeInit && in.Type != handshake.TypeFin {
					p.logDrop(c, reason, in)
				}
			}
		}
		return true
	})
}

// auditRefused audits an entry the relay refused for good (§8.3 cases 5
// and 8): a durable message to a connection with its inner id as ref, any
// other entry by its reason alone. Every waiting durable message is
// sealed under the current epoch: the service's own new epoch is pending
// until its confirmation, which seals them again (confirmPending).
func (p *Peer) auditRefused(e *outboxEntry, reason string) {
	if c := p.conns[e.ConnID]; c != nil && c.kr != nil && c.kr.Current() != nil && !e.Handshake && !e.BestEffort && !e.Confirm {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := c.kr.Current().OpenSent(env); err == nil {
				p.logDrop(c, reason, in)
				return
			}
		}
	}
	p.audit(reason, e.ConnID)
}
