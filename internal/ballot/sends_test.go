package ballot

import (
	"context"
	"encoding/json"
	"testing"
	"time"
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
	if n, err := m.Publish(context.Background(), c.ProposalID); err != nil || n != 3 {
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
	m.sendInBackground("p1", "proposal/p1", TypeProposal, conns, body)
	m.sendInBackground("p1", "extended/p1/1", TypeExtended, conns, body)
	if m.sendInBackground("p1", "extended/p1/1", TypeExtended, conns, body) {
		t.Fatal("a queued key queued twice")
	}
	m.sendInBackground("p1", "closed/p1", TypeClosed, conns, body)
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
	m3.sendInBackground("p1", "proposal/p1", TypeProposal, []string{"a"}, body)
	m3.sendInBackground("p1", "extended/p1/1", TypeExtended, []string{"b"}, body)
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
	if m3.sendInBackground("p1", "closed/p1", TypeClosed, []string{"a"}, body) {
		t.Fatal("queued after StopSends")
	}

	// Another proposal isn't held behind p1's.
	m2, s2, _ := newManager(t)
	held := make(chan struct{})
	s2.hold = map[string]chan struct{}{"a": held}
	m2.sendInBackground("p1", "proposal/p1", TypeProposal, []string{"a"}, body)
	m2.sendInBackground("p2", "proposal/p2", TypeProposal, []string{"b"}, body)
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
