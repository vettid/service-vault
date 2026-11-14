package peer

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Send tallies: what became of the messages an application send put in
// the outbox (SendMessageRef). Accepted is not sent: a message to a
// connection mid-reconnect, or stale, waits in the outbox, and may be
// deposited days later or end there undelivered (§8.3).

// kindSend is a send's tally, by its ref.
const kindSend = "send"

// SendTallyRetention keeps a send's tally this long after the latest
// notAfter of its messages, the last time one could still be deposited
// (chosen; not in the spec).
const SendTallyRetention = 14 * 24 * time.Hour

// sendTally counts a send's messages that left the outbox. The ones still
// in it are counted from the outbox itself (SendCounts).
type sendTally struct {
	Ref       string    `json:"ref"`
	Deposited int       `json:"deposited"`
	Dropped   int       `json:"dropped"`
	Until     time.Time `json:"until"` // the latest notAfter of its messages
}

// SendCounts is where one send's messages stand: deposited with the
// relay (Sent), waiting in the outbox (Queued), or ended there
// undelivered (Dropped).
type SendCounts struct {
	Ref     string
	Sent    int
	Queued  int
	Dropped int
}

// SendMessageRef is SendMessage, with the message counted under ref
// (SendCounts). Give a notAfter: a message with none keeps its ref's
// tally only SendTallyRetention from its send (or from the last start),
// and may outlive it, uncounted.
func (p *Peer) SendMessageRef(ctx context.Context, connID, typ string, body json.RawMessage, notAfter time.Time, ref string) (string, error) {
	return p.sendMessage(ctx, connID, typ, body, notAfter, ref)
}

// tallyUntil is how long a message with notAfter keeps its send's tally:
// until its notAfter, or from now with none.
func tallyUntil(notAfter, now time.Time) time.Time {
	if notAfter.IsZero() {
		return now
	}
	return notAfter
}

// tally returns ref's tally, made if new, kept at least until until.
func (p *Peer) tally(ref string, until time.Time) *sendTally {
	t := p.sends[ref]
	if t == nil {
		t = &sendTally{Ref: ref}
		p.sends[ref] = t
	}
	// Compared as stored, so that a send whose notAfter carries
	// sub-millisecond time doesn't write its tally at every message.
	if u := until.UTC().Truncate(time.Millisecond); u.After(t.Until) {
		t.Until = u
		p.markDirty(kindSend, ref)
	}
	return t
}

// sendLeft counts e, a message of a send, as it leaves the outbox.
// Dropped means not confirmed deposited: one tried without an answer (a
// timeout, a 5xx) may have reached the relay. The counts may fall short
// after a crash: a flush split across writes stores the outbox entries'
// removal before the tally (records go by kind), and a crash between the
// two loses those messages from every count. Short, not double: the
// other order would count a message re-deposited after the crash twice.
// And they may exceed what the sender saw accepted: a send whose first
// flush failed is still in the outbox, counted.
func (p *Peer) sendLeft(e *outboxEntry) {
	if e.Ref == "" {
		return
	}
	t := p.sends[e.Ref]
	if t == nil {
		return // its tally is past its retention
	}
	if e.deposited {
		t.Deposited++
	} else {
		t.Dropped++
	}
	p.markDirty(kindSend, e.Ref)
}

// SendCounts reports the sends whose ref starts with prefix, by ref, as of
// the peer's load or its last flush that wrote the outbox or a tally
// (whether or not the write went through): it takes no lock, so it never
// waits behind a drain (which holds the peer's lock while it calls the
// relay), and may lag one.
func (p *Peer) SendCounts(prefix string) []SendCounts {
	v := p.sendView.Load()
	if v == nil {
		return nil
	}
	var out []SendCounts
	for _, c := range *v {
		if strings.HasPrefix(c.Ref, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// viewSends makes what SendCounts reports from the tallies and the outbox
// (under p.mu): at load, and at each flush that wrote either.
func (p *Peer) viewSends() {
	if len(p.sends) == 0 {
		p.sendView.Store(&[]SendCounts{})
		return
	}
	queued := map[string]int{}
	for _, e := range p.outbox {
		if e.Ref != "" {
			queued[e.Ref]++
		}
	}
	out := make([]SendCounts, 0, len(p.sends))
	for ref, t := range p.sends {
		out = append(out, SendCounts{Ref: ref, Sent: t.Deposited, Queued: queued[ref], Dropped: t.Dropped})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	p.sendView.Store(&out)
}

// pruneSends (housekeeping) forgets the tallies past their retention.
func (p *Peer) pruneSends(now time.Time) {
	for ref, t := range p.sends {
		if now.After(t.Until.Add(SendTallyRetention)) {
			delete(p.sends, ref)
			p.markDirty(kindSend, ref)
		}
	}
}
