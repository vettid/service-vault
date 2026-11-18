package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// A message whose send's tally a split flush lost (the outbox written, the
// tally not) is counted again from the next start.
func TestSendTallyRecreatedAtLoad(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	c := f.connect(m, "")
	ctx := context.Background()
	f.beginReconnectNow(c)
	if _, err := f.p.SendMessageRef(ctx, c, "vote.proposal", json.RawMessage(`{}`), f.clk.Now().Add(time.Hour), "p1/proposal/p1"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Apply(ctx, []Change{{Kind: kindSend, ID: "p1/proposal/p1"}}); err != nil {
		t.Fatal(err)
	}
	f.start()
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p1/proposal/p1 0 1 0}]" {
		t.Fatalf("after the start: %s", got)
	}
	f.pump()
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p1/proposal/p1 1 0 0}]" {
		t.Fatalf("after the confirmation: %s", got)
	}
	f.start() // the tally made again was stored
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p1/proposal/p1 1 0 0}]" {
		t.Fatalf("after a second start: %s", got)
	}
}

// failApply is a store whose writes all fail.
type failApply struct{ *MemStore }

func (failApply) Apply(context.Context, []Change) error { return errors.New("store down") }

// A send whose flush fails is still counted as it stands in memory: its
// records stay dirty, for the next flush.
func TestSendCountsFlushFails(t *testing.T) {
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	f.beginReconnectNow(c)
	f.p.cfg.Store = failApply{f.store}
	if _, err := f.p.SendMessageRef(context.Background(), c, "vote.proposal", json.RawMessage(`{}`), f.clk.Now().Add(time.Hour), "p1/proposal/p1"); err == nil {
		t.Fatal("sent with the store down")
	}
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p1/proposal/p1 0 1 0}]" {
		t.Fatalf("%s", got)
	}
}

// SendCounts doesn't wait for the peer's lock, which a drain holds while
// it calls the relay.
func TestSendCountsWithoutLock(t *testing.T) {
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	if _, err := f.p.SendMessageRef(context.Background(), c, "vote.proposal", json.RawMessage(`{}`), f.clk.Now().Add(time.Hour), "p1/proposal/p1"); err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	done := make(chan string, 1)
	go func() { done <- fmt.Sprint(f.p.SendCounts("p1/")) }()
	select {
	case got := <-done:
		if got != "[{p1/proposal/p1 1 0 0}]" {
			t.Fatal(got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendCounts waits for the peer's lock")
	}
}

// A counted message the key change's re-sealing drops (tried, past the
// dedupe window) is counted dropped.
func TestSendCountsResealDrop(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "")
	c := f.p.conns[cid]
	f.failDeposit = func(string, string) error { return errUnavailable }
	far := f.clk.Now().Add(DedupeRetention + time.Hour)
	if _, err := f.p.SendMessageRef(context.Background(), cid, "vote.closed", json.RawMessage(`{}`), far, "p2/closed/p2"); err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	for _, e := range f.p.outbox {
		e.Tried = true
	}
	f.p.resealAtKeyChange(c, c.kr.Current(), f.clk.Now().Add(DedupeRetention))
	err := f.p.flush(context.Background())
	f.p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p2/closed/p2 0 0 1}]" {
		t.Fatalf("%s", got)
	}
}

// A second message queued for a send, with the same notAfter (its tally
// not written again), is counted as it is queued.
func TestSendCountsQueuedSameNotAfter(t *testing.T) {
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	f.beginReconnectNow(c)
	until := f.clk.Now().Add(time.Hour)
	for i, want := range []string{"[{p1/proposal/p1 0 1 0}]", "[{p1/proposal/p1 0 2 0}]"} {
		if _, err := f.p.SendMessageRef(context.Background(), c, "vote.proposal", json.RawMessage(`{}`), until, "p1/proposal/p1"); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(f.p.SendCounts("")); got != want {
			t.Fatalf("message %d: %s", i+1, got)
		}
	}
}

// Tallies are stored (Kinds), and written after the outbox in a flush
// (records go by kind, so a store that splits a flush writes the outbox's
// first): the counts fall short after a crash between the two, never
// double.
func TestSendKindOrder(t *testing.T) {
	if !slices.Contains(Kinds(), kindSend) {
		t.Fatal("kindSend is not in Kinds")
	}
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	rec := &kindOrder{MemStore: f.store}
	f.p.cfg.Store = rec
	if _, err := f.p.SendMessageRef(context.Background(), c, "vote.proposal", json.RawMessage(`{}`), f.clk.Now().Add(time.Hour), "p1/proposal/p1"); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p1/proposal/p1 1 0 0}]" {
		t.Fatalf("%s", got)
	}
	both := 0
	for _, kinds := range rec.applies {
		lastOutbox, firstSend := -1, len(kinds)
		for i, k := range kinds {
			if k == kindOutbox {
				lastOutbox = i
			}
			if k == kindSend && i < firstSend {
				firstSend = i
			}
		}
		if lastOutbox >= 0 && firstSend < len(kinds) {
			both++
			if lastOutbox > firstSend {
				t.Fatalf("a tally is written before an outbox record: %v", kinds)
			}
		}
	}
	if both == 0 {
		t.Fatalf("no flush wrote both: %v", rec.applies)
	}
}

// kindOrder records the kinds of each write, in order.
type kindOrder struct {
	*MemStore
	applies [][]string
}

func (s *kindOrder) Apply(ctx context.Context, cs []Change) error {
	var kinds []string
	for _, c := range cs {
		kinds = append(kinds, c.Kind)
	}
	s.applies = append(s.applies, kinds)
	return s.MemStore.Apply(ctx, cs)
}

// A tally made again at load is kept until the latest notAfter of its
// messages, whichever comes first in the outbox; a stored tally whose
// longer Until was lost is extended too.
func TestSendTallyUntilAtLoad(t *testing.T) {
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	ctx := context.Background()
	f.beginReconnectNow(c)
	late, early := f.clk.Now().Add(2*time.Hour), f.clk.Now().Add(time.Hour)
	for _, at := range []time.Time{late, early} {
		if _, err := f.p.SendMessageRef(ctx, c, "vote.proposal", json.RawMessage(`{}`), at, "p1/proposal/p1"); err != nil {
			t.Fatal(err)
		}
	}
	until := func() time.Time {
		f.p.mu.Lock()
		defer f.p.mu.Unlock()
		return f.p.sends["p1/proposal/p1"].Until
	}
	want := late.UTC().Truncate(time.Millisecond)
	if got := until(); !got.Equal(want) {
		t.Fatalf("sent: %v", got)
	}
	// The tally lost: made again from both messages.
	if err := f.store.Apply(ctx, []Change{{Kind: kindSend, ID: "p1/proposal/p1"}}); err != nil {
		t.Fatal(err)
	}
	f.start()
	if got := until(); !got.Equal(want) {
		t.Fatalf("made again: %v", got)
	}
	// Its longer Until lost: extended again.
	data, _ := json.Marshal(&sendTally{Ref: "p1/proposal/p1", Until: early.UTC().Truncate(time.Millisecond)})
	rec, _, _ := f.store.GetRecord(ctx, kindSend, "p1/proposal/p1")
	if err := f.store.Apply(ctx, []Change{{Kind: kindSend, ID: "p1/proposal/p1", Data: data, IfVersion: rec.Version}}); err != nil {
		t.Fatal(err)
	}
	f.start()
	if got := until(); !got.Equal(want) {
		t.Fatalf("extended: %v", got)
	}
}

// SendCounts read while sends flush: for -race.
func TestSendCountsConcurrent(t *testing.T) {
	f := newFixture(t)
	c := f.connect(f.member(10), "")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				_ = f.p.SendCounts("")
			}
		}
	}()
	for i := range 20 {
		if _, err := f.p.SendMessageRef(context.Background(), c, "vote.proposal", json.RawMessage(`{}`), f.clk.Now().Add(time.Hour), fmt.Sprintf("p%d/proposal", i%3)); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	<-done
	if got := fmt.Sprint(f.p.SendCounts("")); got != "[{p0/proposal 7 0 0} {p1/proposal 7 0 0} {p2/proposal 6 0 0}]" {
		t.Fatalf("%s", got)
	}
}
