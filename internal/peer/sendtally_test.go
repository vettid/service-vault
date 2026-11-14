package peer

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// A send's messages are counted where they stand: queued while the
// service's reconnect is open, deposited at its confirmation, dropped when
// one waits past its notAfter. The counts survive a restart, and go once
// past their retention.
func TestSendCounts(t *testing.T) {
	f := newFixture(t)
	m1, m2 := f.member(10), f.member(11)
	c1, c2 := f.connect(m1, ""), f.connect(m2, "")
	ctx := context.Background()
	body := json.RawMessage(`{"proposal":"x"}`)
	until := f.clk.Now().Add(time.Hour)
	if _, err := f.p.SendMessageRef(ctx, c1, "vote.proposal", body, until, "p1/proposal/p1"); err != nil {
		t.Fatal(err)
	}
	f.beginReconnectNow(c2)
	if _, err := f.p.SendMessageRef(ctx, c2, "vote.proposal", body, until, "p1/proposal/p1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.SendMessageRef(ctx, c2, "vote.closed", body, until, "p2/closed/p2"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.SendMessage(ctx, c1, "vote.proposal", body, until); err != nil {
		t.Fatal(err) // not counted
	}
	counts := func(prefix string) string { return fmt.Sprint(f.p.SendCounts(prefix)) }
	if got := counts("p1/"); got != "[{p1/proposal/p1 1 1 0}]" {
		t.Fatalf("while the reconnect is open: %s", got)
	}
	if got := counts(""); got != "[{p1/proposal/p1 1 1 0} {p2/closed/p2 0 1 0}]" {
		t.Fatalf("all: %s", got)
	}
	f.start() // reloaded from the store
	if got := counts(""); got != "[{p1/proposal/p1 1 1 0} {p2/closed/p2 0 1 0}]" {
		t.Fatalf("after a restart: %s", got)
	}
	f.pump()
	if f.p.conns[c2].Reconnecting {
		t.Fatal("not confirmed")
	}
	if got := counts(""); got != "[{p1/proposal/p1 2 0 0} {p2/closed/p2 1 0 0}]" {
		t.Fatalf("after the confirmation: %s", got)
	}
	// Held past its notAfter: dropped.
	f.beginReconnectNow(c1)
	if _, err := f.p.SendMessageRef(ctx, c1, "vote.closed", body, f.clk.Now().Add(time.Minute), "p2/closed/p2"); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(2 * time.Minute)
	f.step()
	if got := counts("p2/"); got != "[{p2/closed/p2 1 0 1}]" {
		t.Fatalf("past its notAfter: %s", got)
	}
	// A notAfter with sub-millisecond time, as stored: the tally isn't
	// written again for each message.
	f.p.mu.Lock()
	u := f.p.sends["p2/closed/p2"].Until.Add(500 * time.Microsecond)
	f.p.tally("p2/closed/p2", u)
	f.p.markDirty(kindSend, "p2/closed/p2") // written with the first, below
	if err := f.p.flush(context.Background()); err != nil {
		f.p.mu.Unlock()
		t.Fatal(err)
	}
	f.p.tally("p2/closed/p2", u)
	_, dirty := f.p.dirty[key{kindSend, "p2/closed/p2"}]
	f.p.mu.Unlock()
	if dirty {
		t.Fatal("the tally is written again for the same notAfter")
	}
	f.clk.Advance(SendTallyRetention + time.Hour)
	f.tick()
	if got := counts(""); got != "[]" {
		t.Fatalf("past the retention: %s", got)
	}
	if err := f.p.flush(ctx); err != nil {
		t.Fatal(err)
	}
	f.start()
	if got := counts(""); got != "[]" {
		t.Fatalf("past the retention, after a restart: %s", got)
	}
}
