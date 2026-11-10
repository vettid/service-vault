package ballot

import (
	"context"
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
