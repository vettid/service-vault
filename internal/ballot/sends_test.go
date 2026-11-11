package ballot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// Sends run after the request: Publish answers while every send is still
// held, a request's context ending doesn't stop them, a second Publish
// while they run doesn't send twice, and the Background context ending
// stops them.
func TestSendsInBackground(t *testing.T) {
	m, s, pub := newManager(t)
	pub.fail = true
	ctx, cancel := context.WithCancel(context.Background())
	c, _ := m.Create(ctx, "apv", input())
	pub.fail = false
	s.block = make(chan struct{})
	done := make(chan int, 1)
	go func() {
		n, err := m.Publish(ctx, c.ProposalID)
		if err != nil {
			t.Error(err)
		}
		done <- n
	}()
	select {
	case n := <-done:
		if n != 3 {
			t.Fatalf("sending %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Publish waited for the sends")
	}
	cancel() // the request ends
	// Already being sent: nothing more is, and the answer says so.
	if n, err := m.Publish(context.Background(), c.ProposalID); err != nil || n != 0 {
		t.Fatalf("Publish again: %d, %v", n, err)
	}
	close(s.block)
	m.Wait()
	if len(s.sent) != 3 {
		t.Fatalf("sent %d, want 3 (once each)", len(s.sent))
	}
	for i := 1; i < len(s.sent); i++ {
		if s.sent[i-1].conn >= s.sent[i].conn {
			t.Fatal("not in connection order")
		}
	}

	// The daemon's context ending stops the sends.
	m2, s2, _ := newManager(t)
	bg, stop := context.WithCancel(context.Background())
	m2.Background = bg
	s2.block = make(chan struct{})
	if _, err := m2.Create(context.Background(), "apv", input()); err != nil {
		t.Fatal(err)
	}
	stop()
	m2.Wait()
	if len(s2.sent) != 0 {
		t.Fatalf("sent %d after the daemon stopped", len(s2.sent))
	}
}

// A Publish after the first sender ended sends again (the retry /publish
// is for); a Background already done sends nothing and calls no send.
func TestSendsAgainAndStopped(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if _, err := m.Publish(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if len(s.sent) != 6 {
		t.Fatalf("sent %d, want 3 and 3 again", len(s.sent))
	}
	m2, s2, _ := newManager(t)
	bg, stop := context.WithCancel(context.Background())
	stop()
	m2.Background = bg
	if _, err := m2.Create(ctx, "apv", input()); err != nil {
		t.Fatal(err)
	}
	m2.Wait()
	if len(s2.sent) != 0 || s2.cancelled != 0 {
		t.Fatalf("sent %d, %d calls after the stop", len(s2.sent), s2.cancelled)
	}
}

// A proposal's sends go in the order they were started, each whole before
// the next; another proposal's run beside them; a key queued but not yet
// running isn't queued twice.
func TestSendsOrderPerProposal(t *testing.T) {
	m, s, _ := newManager(t)
	s.block = make(chan struct{})
	conns := []string{"a", "b"}
	body := func(string) (json.RawMessage, error) { return json.RawMessage(`{}`), nil }
	m.sendInBackground("p1", "proposal/p1", TypeProposal, conns, time.Time{}, body)
	m.sendInBackground("p1", "extended/p1/1", TypeExtended, conns, time.Time{}, body)
	if m.sendInBackground("p1", "extended/p1/1", TypeExtended, conns, time.Time{}, body) {
		t.Fatal("a queued key queued twice")
	}
	m.sendInBackground("p1", "closed/p1", TypeClosed, conns, time.Time{}, body)
	close(s.block)
	m.Wait()
	want := []string{TypeProposal, TypeProposal, TypeExtended, TypeExtended, TypeClosed, TypeClosed}
	if len(s.sent) != len(want) {
		t.Fatalf("sent %d", len(s.sent))
	}
	for i, w := range want {
		if s.sent[i].typ != w {
			t.Fatalf("send %d: %s, want %s", i, s.sent[i].typ, w)
		}
	}
	// One runner per proposal: its second message waits for the first,
	// whatever member each goes to.
	m3, s3, _ := newManager(t)
	h := make(chan struct{})
	s3.hold = map[string]chan struct{}{"a": h}
	m3.sendInBackground("p1", "proposal/p1", TypeProposal, []string{"a"}, time.Time{}, body)
	m3.sendInBackground("p1", "extended/p1/1", TypeExtended, []string{"b"}, time.Time{}, body)
	time.Sleep(100 * time.Millisecond)
	s3.mu.Lock()
	early := len(s3.sent)
	s3.mu.Unlock()
	close(h)
	m3.Wait()
	if early != 0 || len(s3.sent) != 2 || s3.sent[0].typ != TypeProposal {
		t.Fatalf("the second message went first: %d early, %+v", early, s3.sent)
	}
	// After StopSends nothing is queued.
	m3.StopSends()
	if m3.sendInBackground("p1", "closed/p1", TypeClosed, []string{"a"}, time.Time{}, body) {
		t.Fatal("queued after StopSends")
	}

	// Another proposal isn't held behind p1's.
	m2, s2, _ := newManager(t)
	held := make(chan struct{})
	s2.hold = map[string]chan struct{}{"a": held}
	m2.sendInBackground("p1", "proposal/p1", TypeProposal, []string{"a"}, time.Time{}, body)
	m2.sendInBackground("p2", "proposal/p2", TypeProposal, []string{"b"}, time.Time{}, body)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s2.mu.Lock()
		n := len(s2.sent)
		s2.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("p2 waited behind p1")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(held)
	m2.Wait()
	if len(s2.sent) != 2 || s2.sent[0].conn != "b" {
		t.Fatalf("sent %+v", s2.sent)
	}
}

// A job whose sends keep failing (the relay hanging, the store failing) stops after
// MaxFailuresInARow in a row, rather than holding the peer and its
// proposal's later sends for every member; a success resets the count.
func TestSendsGiveUpAfterFailuresInARow(t *testing.T) {
	m, s, _ := newManager(t)
	relayDown := errors.New("relay: 503")
	s.failWith = map[string]error{}
	var conns []string
	for i := 0; i < 3*MaxFailuresInARow; i++ {
		c := fmt.Sprintf("m%03d", i)
		conns = append(conns, c)
		s.failWith[c] = relayDown
	}
	// One member in the middle of the first run is up: the count starts
	// again after it.
	delete(s.failWith, conns[MaxFailuresInARow-2])
	tried := 0
	m.runJob(&sendJob{key: "k", typ: TypeProposal, conns: conns, body: func(string) (json.RawMessage, error) {
		tried++
		return json.RawMessage(`{}`), nil
	}})
	if want := MaxFailuresInARow - 1 + MaxFailuresInARow; tried != want {
		t.Fatalf("tried %d members, want %d", tried, want)
	}
	if len(s.sent) != 1 {
		t.Fatalf("sent %d, want 1", len(s.sent))
	}
}

// Members whose connection is gone (peer.ErrNotFound) or whose outbox is
// full (peer.ErrBusy) are about that member, not the relay: however many
// sit together in connection order, the job goes on to the members after
// them.
func TestSendsMemberErrorsDontGiveUp(t *testing.T) {
	m, s, _ := newManager(t)
	s.failWith = map[string]error{}
	var conns []string
	n := 3 * MaxFailuresInARow
	for i := 0; i < n; i++ {
		c := fmt.Sprintf("m%03d", i)
		conns = append(conns, c)
		switch {
		case i < MaxFailuresInARow+5:
			s.down[c] = true // peer.ErrNotFound
		case i < 2*MaxFailuresInARow+10:
			s.failWith[c] = peer.ErrBusy
		}
	}
	m.runJob(&sendJob{key: "k", typ: TypeClosed, conns: conns, body: func(string) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}})
	if want := n - (2*MaxFailuresInARow + 10); len(s.sent) != want {
		t.Fatalf("sent %d, want %d (the members after the gone and busy ones)", len(s.sent), want)
	}
}

// A relay that refuses deposits at once, at 15,000 members: the peer's
// outbox fills to its bound and then answers peer.ErrOutboxFull, which
// counts toward giving up, so the job stops MaxFailuresInARow sends past
// the bound instead of filling memory.
func TestSendsStopAtAFullOutbox(t *testing.T) {
	m, _, _ := newManager(t)
	const bound = 100
	out := &boundedOutbox{bound: bound}
	m.Sender = out
	conns := make([]string, MaxEligible)
	for i := range conns {
		conns[i] = fmt.Sprintf("m%05d", i)
	}
	m.runJob(&sendJob{key: "k", typ: TypeProposal, conns: conns, body: func(string) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}})
	if out.queued != bound || out.calls != bound+MaxFailuresInARow {
		t.Fatalf("queued %d, %d calls; want %d and %d", out.queued, out.calls, bound, bound+MaxFailuresInARow)
	}
}

// boundedOutbox is a peer whose relay refuses every deposit at once: each
// send is queued, as the peer does, until bound are, then refused.
type boundedOutbox struct {
	bound, queued, calls int
}

func (b *boundedOutbox) SendMessage(_ context.Context, _, _ string, _ json.RawMessage, _ time.Time) (string, error) {
	b.calls++
	if b.queued >= b.bound {
		return "", peer.ErrOutboxFull
	}
	b.queued++
	return "id", nil
}

// Each member's send gets SendTimeout, and no more: 30 s, the time a
// relay deposit may take before the drain gives up on it.
func TestSendTimeoutPerSend(t *testing.T) {
	if SendTimeout != 30*time.Second {
		t.Fatalf("SendTimeout %v", SendTimeout)
	}
	m, s, _ := newManager(t)
	m.runJob(&sendJob{key: "k", typ: TypeProposal, conns: []string{"a"}, body: func(string) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}})
	if s.left <= SendTimeout-5*time.Second || s.left > SendTimeout {
		t.Fatalf("a send had %v, want SendTimeout (%v)", s.left, SendTimeout)
	}
}

// A Publish once the results are published sends nothing (members are
// sent vote.closed); one while the service is stopping answers that
// nothing is being sent.
func TestPublishSendsNothingAfterResultsOrStop(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	before := len(s.sent)
	if err := m.Store.Records.Apply(ctx, []peer.Change{{Kind: KindResults, ID: c.ProposalID, Data: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	if n, err := m.Publish(ctx, c.ProposalID); err != nil || n != 0 {
		t.Fatalf("after the results: %d, %v", n, err)
	}
	m.Wait()
	if len(s.sent) != before {
		t.Fatalf("sent %d after the results", len(s.sent)-before)
	}

	m2, s2, _ := newManager(t)
	c2, err := m2.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m2.Wait()
	before = len(s2.sent)
	m2.StopSends()
	if n, err := m2.Publish(ctx, c2.ProposalID); err != nil || n != 0 {
		t.Fatalf("while stopping: %d, %v", n, err)
	}
	m2.Wait()
	if len(s2.sent) != before {
		t.Fatal("sent while stopping")
	}
}

// Each message's deposits stop being worth making at the close in force
// plus what extensions may add (proposal, extended), or ClosedSendLife
// after the count (closed).
func TestSendsNotAfter(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if want := time.Unix(input().ClosesAt, 0).Add(24 * time.Hour); !s.notAfter.Equal(want) {
		t.Fatalf("vote.proposal not after %v, want %v", s.notAfter, want)
	}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	m.announce(o, &PublishedResults{})
	m.Wait()
	if want := m.Now().Add(ClosedSendLife); !s.notAfter.Equal(want) {
		t.Fatalf("vote.closed not after %v, want %v", s.notAfter, want)
	}
}
