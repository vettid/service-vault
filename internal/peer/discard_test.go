package peer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"github.com/vettid/vettid-vault/vms/peerwire"
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

// failWrites fails Apply while on, after letting skip through.
type failWrites struct {
	*MemStore
	on      bool
	skip    int
	err     error              // returned instead of errThrottled, if set
	onlyMsg bool               // fail only a write carrying a message's dedupe mark
	onlyOf  string             // fail only a write carrying a record of this kind, if set
	cancel  context.CancelFunc // called as the write fails, if set
}

func (s *failWrites) Apply(ctx context.Context, cs []Change) error {
	msg, of := false, s.onlyOf == ""
	for _, c := range cs {
		msg = msg || c.Kind == kindMsg
		of = of || c.Kind == s.onlyOf
	}
	if s.on && (msg || !s.onlyMsg) && of {
		if s.skip > 0 {
			s.skip--
		} else {
			if s.cancel != nil {
				s.cancel() // a shutdown arrives as the write fails
			}
			if s.err != nil {
				return s.err
			}
			return errThrottled
		}
	}
	return s.MemStore.Apply(ctx, cs)
}

// throttled is a store error with an AWS error code.
type throttled struct{}

func (throttled) Error() string     { return "throttled" }
func (throttled) ErrorCode() string { return "ProvisionedThroughputExceededException" }

var errThrottled error = throttled{}

// Writes fail while reads work: the message is handled in memory, its
// response queued, and its write fails. The peer stops (one Votes call,
// nothing deposited); after the restart the member gets one response.
func TestFailedMessageWriteStops(t *testing.T) {
	f := newFixture(t)
	st := &failWrites{MemStore: f.store}
	f.storeWrap = st
	f.start()
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
	m.Send("vote.status", []byte(`{}`))
	m.Step()
	chs := len(m.Challenges)
	st.on, st.skip = true, 1 // the lease mark is written, the message's write fails
	if _, err := f.p.Step(context.Background(), 0); !errors.Is(err, errDiscarded) {
		t.Fatalf("step: %v, want errDiscarded", err)
	}
	st.on = false // the store is back: the stopped peer still writes nothing
	ctx := context.Background()
	if err := f.p.Tick(ctx); !errors.Is(err, errDiscarded) {
		t.Fatalf("tick after the stop: %v", err)
	}
	if _, err := f.p.Step(ctx, 0); !errors.Is(err, errDiscarded) {
		t.Fatalf("step after the stop: %v", err)
	}
	if _, err := f.p.Authenticate(ctx, cid, "y", "", 5*time.Minute); !errors.Is(err, errDiscarded) {
		t.Fatalf("authenticate after the stop: %v", err)
	}
	f.p.DeliverEvents(ctx)
	m.Step()
	rv.mu.Lock()
	calls := len(rv.reqs)
	rv.mu.Unlock()
	if calls != 1 || len(m.Received("vote.status")) != 0 || len(m.Challenges) != chs {
		t.Fatalf("before the restart: %d votes calls, %d responses, %d challenges (was %d)", calls, len(m.Received("vote.status")), len(m.Challenges), chs)
	}
	f.clk.Advance(61 * time.Second)
	f.start()
	f.p.cfg.Votes = rv
	f.pump()
	m.Step()
	if n := len(m.Received("vote.status")); n != 1 {
		t.Fatalf("%d responses after the restart, want 1", n)
	}
}

// Events a message raises in memory that a stop then leaves unwritten
// aren't delivered; the restart handles the message again and raises it
// once. (Housekeeping's events are written before the batch: #181.)
func TestDiscardedEventsNotDelivered(t *testing.T) {
	f := newFixture(t)
	st := &failWrites{MemStore: f.store}
	f.storeWrap = st
	f.start()
	m := f.member(10)
	cid := f.connect(m, "t")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", "", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.p.DeliverEvents(ctx)
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[len(m.Challenges)-1], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	st.on, st.onlyMsg = true, true // the answer's write fails
	if _, err := f.p.Step(ctx, 0); !errors.Is(err, errDiscarded) {
		t.Fatalf("step: %v, want errDiscarded", err)
	}
	st.on = false
	f.p.DeliverEvents(ctx)
	if n := len(f.ev.of(EventSignInApproved)); n != 0 {
		t.Fatalf("%d approvals delivered from unwritten memory", n)
	}
	f.clk.Advance(61 * time.Second)
	f.start()
	f.pump()
	f.p.DeliverEvents(ctx)
	if ap := f.ev.of(EventSignInApproved); len(ap) != 1 || ap[0].RequestID != id {
		t.Fatalf("after the restart: %+v", ap)
	}
}

// The store error is wrapped and named: errors.Is finds it, and the alarm
// line carries its code.
func TestDiscardWrapsStoreError(t *testing.T) {
	f, _, _, rv := discardSetup(t)
	rv.mu.Lock()
	rv.fail = errThrottled
	rv.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := f.p.Run(ctx)
	if !errors.Is(err, errDiscarded) || !errors.Is(err, errThrottled) {
		t.Fatalf("run: %v, want errDiscarded wrapping the store error", err)
	}
	if !strings.Contains(f.logs.String(), "store_err=ProvisionedThroughputExceededException") {
		t.Fatal("the alarm line doesn't name the store's error code")
	}
}

// A shutdown that cancels the message's write is a routine stop: no
// alarm. A real store error during a shutdown still raises it.
func TestShutdownMidMessage(t *testing.T) {
	for _, real := range []bool{false, true} {
		f := newFixture(t)
		st := &failWrites{MemStore: f.store}
		f.storeWrap = st
		f.start()
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
		m.Send("vote.status", []byte(`{}`))
		m.Step()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		st.on, st.onlyMsg, st.cancel = true, true, cancel
		if !real {
			st.err = context.Canceled
		}
		err := f.p.Run(ctx)
		alarm := strings.Contains(f.logs.String(), "alarm=peer_discarded")
		if real && (!alarm || !errors.Is(err, errDiscarded)) {
			t.Fatalf("a store error during a shutdown: alarm %v, %v", alarm, err)
		}
		if !real && (alarm || errors.Is(err, errDiscarded)) {
			t.Fatalf("a cancelled write at shutdown: alarm %v, %v", alarm, err)
		}
	}
}

// A conflict on the message's write stops as ErrConflict, without the
// peer_discarded alarm.
func TestMessageWriteConflictStopsWithoutAlarm(t *testing.T) {
	f := newFixture(t)
	st := &failWrites{MemStore: f.store}
	f.storeWrap = st
	f.start()
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
	m.Send("vote.status", []byte(`{}`))
	m.Step()
	st.on, st.onlyMsg, st.err = true, true, ErrConflict
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := f.p.Run(ctx); !errors.Is(err, ErrConflict) || errors.Is(err, errDiscarded) {
		t.Fatalf("run: %v, want ErrConflict", err)
	}
	if strings.Contains(f.logs.String(), "peer_discarded") {
		t.Fatal("a conflict raised peer_discarded")
	}
}
