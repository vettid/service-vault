package peer

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
)

// discardSetup connects a signed-in member whose next vote request fails
// with a store error, after the step has changed state (so its discard
// drops something).
func discardSetup(t *testing.T) (*fixture, *peertest.Member, string, *recordVotes) {
	t.Helper()
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	f.clk.Advance(2 * time.Minute)
	f.pump()
	rv.fail = errors.New("store down")
	m.Send("vote.status", []byte(`{}`))
	m.Step()
	return f, m, cid, rv
}

// A store error that discards a step's changes: Step says so, and
// nothing more is written from that memory.
func TestDiscardStopsWrites(t *testing.T) {
	f, _, cid, _ := discardSetup(t)
	ctx := context.Background()
	if _, err := f.p.Step(ctx, 0); !errors.Is(err, errDiscarded) {
		t.Fatalf("step: %v, want errDiscarded", err)
	}
	if _, err := f.p.Authenticate(ctx, cid, "y", "", 5*time.Minute); err == nil {
		t.Fatal("a write succeeded after the step was discarded")
	}
}

// Run stops at once on it, with the alarm; after a restart on the same
// store the redelivered message is handled once.
func TestDiscardStopsRunAndRestartHandlesOnce(t *testing.T) {
	f, _, _, rv := discardSetup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	started := time.Now()
	if err := f.p.Run(ctx); !errors.Is(err, errDiscarded) {
		t.Fatalf("run: %v, want errDiscarded", err)
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Fatalf("Run took %s to return: it waited for the caller's context", d)
	}
	if !strings.Contains(f.logs.String(), "alarm=peer_discarded") {
		t.Fatal("no peer_discarded alarm line")
	}
	f.clk.Advance(61 * time.Second)
	f.start()
	f.pump()
	rv.mu.Lock()
	n := len(rv.reqs)
	rv.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d vote requests handled after the restart, want 1", n)
	}
}

// A store error before anything changed in memory (here, the collect)
// stays a plain error: Run retries rather than stopping.
func TestCollectErrorDoesNotStopRun(t *testing.T) {
	f := newFixture(t)
	f.failCollect = errors.New("relay unreachable")
	if _, err := f.p.Step(context.Background(), 0); err == nil || errors.Is(err, errDiscarded) {
		t.Fatalf("step: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := f.p.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("run: %v, want it to keep retrying until the context ends", err)
	}
	if strings.Contains(f.logs.String(), "peer_discarded") {
		t.Fatal("a collect error raised peer_discarded")
	}
}
