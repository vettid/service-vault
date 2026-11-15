package peer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// failMsgGet fails the next Get of a message's dedupe record: a store
// error while a batch is handled.
type failMsgGet struct {
	*MemStore
	fail bool
}

func (s *failMsgGet) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if s.fail && kind == kindMsg {
		s.fail = false
		return nil, false, errors.New("store down")
	}
	return s.MemStore.Get(ctx, kind, id)
}

// A store error while a message is handled discards the step: Step says
// so, Run stops on it with the alarm, and after a restart on the same
// store the redelivered message is handled exactly once.
func TestDiscardStopsRunAndRestartHandlesOnce(t *testing.T) {
	f := newFixture(t)
	st := &failMsgGet{MemStore: f.store}
	f.storeWrap = st
	f.start()
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", "", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	st.fail = true
	if _, err := f.p.Step(ctx, 0); !errors.Is(err, errDiscarded) {
		t.Fatalf("step: %v, want errDiscarded", err)
	}
	if n := len(f.ev.of(EventSignInApproved)); n != 0 {
		t.Fatalf("%d approvals from a discarded step", n)
	}
	// Run stops on it: the batch comes back once its lease lapses, and its
	// handling hits the store error again.
	f.clk.Advance(61 * time.Second)
	st.fail = true
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := f.p.Run(rctx); !errors.Is(err, errDiscarded) {
		t.Fatalf("run: %v, want errDiscarded", err)
	}
	if !strings.Contains(f.logs.String(), "alarm=peer_discarded") {
		t.Fatal("no peer_discarded alarm line")
	}
	// The task restarts from the store: the message is handled once.
	f.clk.Advance(61 * time.Second)
	f.start()
	f.pump()
	f.tick()
	if ap := f.ev.of(EventSignInApproved); len(ap) != 1 || ap[0].RequestID != id {
		t.Fatalf("approved %+v after the restart", ap)
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
