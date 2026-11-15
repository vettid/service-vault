package peer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// setState makes cid not active (a withdraw can't be queued to it), or
// active again.
func (f *fixture) setState(cid, state string) {
	f.t.Helper()
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	f.p.conns[cid].State = state
	f.p.markDirty(kindConn, cid) // stored at the next flush, so a restart keeps it
}

func (f *fixture) owed(id string) bool {
	f.t.Helper()
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	ch := f.p.challenges[id]
	return ch != nil && ch.WithdrawOwed
}

// A challenge cancelled while its connection can't take the withdraw owes
// it: once the connection is active again the step queues it, once.
func TestWithdrawOwedSentLater(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	exp := m.Received(peerwire.TypeConnAuthChallenge)[0].Exp
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	if !f.owed(id) {
		t.Fatal("no withdraw owed")
	}
	f.tick()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 0 || !f.owed(id) {
		t.Fatalf("%d withdraws while not active", n)
	}
	f.setState(cid, StateActive)
	f.tick()
	f.pump()
	w := m.Received(peerwire.TypeConnAuthWithdraw)
	if len(w) != 1 || f.owed(id) {
		t.Fatalf("%d withdraws once active, owed %v", len(w), f.owed(id))
	}
	if got, ok := peerwire.ParseConnAuthWithdraw(w[0].Body); !ok || got != id || !w[0].Exp.Equal(exp) {
		t.Fatalf("withdraw %q %v exp %v", got, ok, w[0].Exp)
	}
	if !strings.Contains(f.logs.String(), "challenge withdraw sent late") {
		t.Fatal("not logged")
	}
	for i := 0; i < 3; i++ {
		f.tick()
		f.pump()
	}
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 1 {
		t.Fatalf("%d withdraws: sent again", n)
	}
	// An answer to it is still ignored.
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if n := len(f.ev.of(EventSignInApproved)); n != 0 {
		t.Fatalf("%d approvals of a cancelled challenge", n)
	}
}

// The debt survives a restart.
func TestWithdrawOwedAcrossRestart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.pump() // written
	f.start()
	if !f.owed(id) {
		t.Fatal("the debt didn't survive the restart")
	}
	f.setState(cid, StateActive)
	f.tick()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 1 || f.owed(id) {
		t.Fatalf("%d withdraws after the restart", n)
	}
	// Another restart after the late send: the cleared flag was stored, so
	// it isn't sent again.
	f.start()
	if f.owed(id) {
		t.Fatal("owed again after a restart that followed the late send")
	}
	f.tick()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 1 {
		t.Fatalf("%d withdraws after the second restart", n)
	}
}

// Past the challenge's exp the withdraw is no longer owed: never sent, and
// the record goes at exp plus the skew as before.
func TestWithdrawOwedEndsAtExp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.clk.Advance(2 * time.Minute)
	f.tick()
	if f.owed(id) || !strings.Contains(f.logs.String(), "challenge withdraw dropped: expired") {
		t.Fatal("still owed past its exp")
	}
	f.setState(cid, StateActive)
	f.tick()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 0 {
		t.Fatalf("%d withdraws past its exp", n)
	}
	f.clk.Advance(ClockSkew)
	f.tick()
	f.p.mu.Lock()
	_, kept := f.p.challenges[id]
	f.p.mu.Unlock()
	if kept {
		t.Fatal("record kept past exp plus skew")
	}
}

// A removed connection drops the debt with the record.
func TestWithdrawOwedDroppedWithConnection(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.p.mu.Lock()
	f.p.removeConnection(f.p.conns[cid], "in", f.clk.Now())
	_, kept := f.p.challenges[id]
	f.p.mu.Unlock()
	if kept || !strings.Contains(f.logs.String(), "challenge withdraw dropped: connection removed") {
		t.Fatalf("kept %v", kept)
	}
}

// A withdraw that could be queued at the cancel owes nothing.
func TestWithdrawNotOwedWhenQueued(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	if f.owed(id) {
		t.Fatal("owed though queued")
	}
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 1 {
		t.Fatalf("%d withdraws", n)
	}
}

// A connection whose outbox stays full isn't tried on each housekeeping
// (sendEntry would log outbox_full every time): the debt waits quietly, and is paid
// once there is room.
func TestWithdrawOwedWaitsForOutboxRoom(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.setState(cid, StateActive)
	// The connection's outbox is full: entries waiting for its mailbox.
	f.p.mu.Lock()
	saved := f.p.outbox
	for i := 0; i < MaxOutboxPerConn; i++ {
		f.p.outbox = append(f.p.outbox, &outboxEntry{ID: "full", ConnID: cid, Op: opDeposit})
	}
	before := strings.Count(f.logs.String(), "outbox_full")
	for i := 0; i < 5; i++ {
		f.p.expireChallenges(f.clk.Now())
	}
	after := strings.Count(f.logs.String(), "outbox_full")
	owed := f.p.challenges[id].WithdrawOwed
	f.p.outbox = saved
	f.p.mu.Unlock()
	if after != before || !owed {
		t.Fatalf("outbox_full lines %d -> %d, owed %v", before, after, owed)
	}
	f.tick()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 1 || f.owed(id) {
		t.Fatalf("%d withdraws once there was room", n)
	}
}

// A live challenge, never cancelled, gets no withdraw however many
// housekeepings run.
func TestNoWithdrawForLiveChallenge(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	id, err := f.p.Authenticate(context.Background(), cid, "x", peerwire.PurposeApproval, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	for i := 0; i < 5; i++ {
		f.clk.Advance(time.Minute)
		f.tick()
		f.pump()
	}
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 0 || f.owed(id) {
		t.Fatalf("%d withdraws for a live challenge", n)
	}
}

// A queued withdraw dropped before the relay took it is owed again, and
// sent once the connection can take it: for one queued at the cancel
// (whose record was deleted) and one sent late.
func TestWithdrawDroppedOwedAgain(t *testing.T) {
	for _, late := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "tag")
		ctx := context.Background()
		id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		f.pump()
		if late {
			f.setState(cid, StateSuspended)
		}
		f.failDeposit = func(string, string) error { return errUnavailable } // the withdraw waits in the outbox
		if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
			t.Fatalf("cancel: %v %v", ok, err)
		}
		if late {
			f.setState(cid, StateActive)
			f.p.mu.Lock()
			f.p.expireChallenges(f.clk.Now()) // queues the late withdraw
			f.p.mu.Unlock()
		}
		// Dropped before the relay took it.
		f.p.mu.Lock()
		n := 0
		f.p.dropOutbox(func(e *outboxEntry) bool {
			if e.Withdraw == id {
				n++
				return true
			}
			return false
		})
		f.p.mu.Unlock()
		if n != 1 || !f.owed(id) {
			t.Fatalf("late %v: %d entries dropped, owed %v", late, n, f.owed(id))
		}
		f.failDeposit = nil
		f.tick()
		f.pump()
		if got := len(m.Received(peerwire.TypeConnAuthWithdraw)); got != 1 || f.owed(id) {
			t.Fatalf("late %v: %d withdraws after the drop", late, got)
		}
	}
}

// A withdraw the relay took isn't owed again when its entry leaves.
func TestWithdrawDepositedNotOwedAgain(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.pump()
	for i := 0; i < 3; i++ {
		f.tick()
		f.pump()
	}
	if got := len(m.Received(peerwire.TypeConnAuthWithdraw)); got != 1 || f.owed(id) {
		t.Fatalf("%d withdraws, owed %v", got, f.owed(id))
	}
}

// failMsgGet fails the next Get of a message's dedupe record: a store
// error while a batch is handled, after housekeeping ran.
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

// A store error later in the batch that housekeeping queued a late
// withdraw in doesn't leave the withdraw sent while the stored record still
// owes it, which a restart would send a second time (Fable's 1 -> 2).
func TestLateWithdrawNotSentTwiceAfterDiscard(t *testing.T) {
	f := newFixture(t)
	st := &failMsgGet{MemStore: f.store}
	f.storeWrap = st
	f.start()
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.setState(cid, StateActive)
	f.pump()
	// A message arrives; its step's housekeeping queues the late withdraw,
	// then handling the message hits a store error.
	m.Send(peerwire.TypeConnAuthResponse, []byte(`{}`))
	st.fail = true
	if _, err := f.p.Step(ctx, 0); err == nil {
		t.Fatal("the step didn't fail")
	}
	f.pump() // later steps succeed and drain
	sent := len(m.Received(peerwire.TypeConnAuthWithdraw))
	recs, err := f.store.Load(ctx, kindAuth)
	if err != nil {
		t.Fatal(err)
	}
	storedOwed := false
	for _, r := range recs {
		if r.ID == id {
			storedOwed = strings.Contains(string(r.Data), `"withdraw_owed":true`)
		}
	}
	if sent != 1 || storedOwed {
		t.Fatalf("withdraws sent %d (want 1), store still owes it %v: a restart would send it again", sent, storedOwed)
	}
}

// A recreated record keeps the challenge's purpose: a sign-in whose
// withdraw was dropped still counts as pending.
func TestWithdrawDroppedKeepsPurpose(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.failDeposit = func(string, string) error { return errUnavailable }
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.p.mu.Lock()
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.Withdraw == id })
	ch := f.p.challenges[id]
	f.p.mu.Unlock()
	if ch == nil || ch.Purpose != peerwire.PurposeSignIn || !f.p.HasPendingSignIn(cid) {
		t.Fatalf("recreated %+v: not a pending sign-in", ch)
	}
}

// Removing a connection with a withdraw still queued owes nothing and
// doesn't log one as owed again.
func TestWithdrawQueuedThenConnectionRemoved(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.failDeposit = func(string, string) error { return errUnavailable }
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	f.p.mu.Lock()
	f.p.removeConnection(f.p.conns[cid], "in", f.clk.Now())
	_, kept := f.p.challenges[id]
	f.p.mu.Unlock()
	if kept || strings.Contains(f.logs.String(), "owed again") {
		t.Fatalf("kept %v, logs %s", kept, f.logs.String())
	}
}

// withdrawCancelHeld cancels a fresh challenge while deposits are refused
// by refuse, and returns its id and the count of deposits tried.
func withdrawCancelHeld(t *testing.T, f *fixture, cid, purpose string, refuse error) (string, *int) {
	t.Helper()
	ctx := context.Background()
	var id string
	var err error
	if purpose == peerwire.PurposeSignIn {
		id, err = f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", 10*time.Minute)
	} else {
		id, err = f.p.Authenticate(ctx, cid, "x", purpose, 10*time.Minute)
	}
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	n := 0
	f.failDeposit = func(string, string) error { n++; return refuse }
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	return id, &n
}

// A withdraw the relay refuses for good is tried once and not owed again
// (it would be refused again until its exp).
func TestWithdrawRefusedForGoodNotOwed(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, n := withdrawCancelHeld(t, f, cid, peerwire.PurposeApproval, &relayclient.Error{Status: 400, Code: "bad_request"})
	for i := 0; i < 5; i++ {
		f.clk.Advance(time.Minute)
		f.tick()
		f.pump()
	}
	if *n != 1 || f.owed(id) {
		t.Fatalf("%d deposits tried, owed %v", *n, f.owed(id))
	}
}

// A sign-in withdraw refused for good keeps the record (not owed): the
// sign-in still counts as pending until its exp, and isn't re-sent.
func TestWithdrawRefusedKeepsPlace(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, n := withdrawCancelHeld(t, f, cid, peerwire.PurposeSignIn, &relayclient.Error{Status: 400, Code: "bad_request"})
	f.pump()
	if !f.p.HasPendingSignIn(cid) || f.owed(id) {
		t.Fatalf("after the refusal: pending %v, owed %v", f.p.HasPendingSignIn(cid), f.owed(id))
	}
	f.clk.Advance(5 * time.Minute)
	f.tick()
	f.pump()
	if !f.p.HasPendingSignIn(cid) || *n != 1 {
		t.Fatalf("before exp: pending %v, %d deposits", f.p.HasPendingSignIn(cid), *n)
	}
	f.clk.Advance(6*time.Minute + ClockSkew)
	f.tick()
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("still pending past exp plus the skew")
	}
}

// A withdraw already in the outbox isn't queued a second time.
func TestWithdrawOwedNotQueuedTwice(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, _ := withdrawCancelHeld(t, f, cid, peerwire.PurposeApproval, errUnavailable)
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	f.p.challenges[id] = &challenge{ID: id, ConnID: cid, Exp: f.clk.Now().Add(9 * time.Minute), Gone: true, WithdrawOwed: true}
	f.p.expireChallenges(f.clk.Now())
	n := 0
	for _, e := range f.p.outbox {
		if e.Withdraw == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d entries for the withdraw, want 1", n)
	}
}

// A withdraw dropped while being sealed again at a key change
// (held_unsealable) is owed again.
func TestWithdrawDroppedAtResealOwedAgain(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, _ := withdrawCancelHeld(t, f, cid, peerwire.PurposeApproval, errUnavailable)
	f.p.mu.Lock()
	f.p.resealAtKeyChange(f.p.conns[cid], &handshake.Epoch{}, f.clk.Now())
	n := 0
	for _, e := range f.p.outbox {
		if e.Withdraw == id {
			n++
		}
	}
	f.p.mu.Unlock()
	if n != 0 || !f.owed(id) {
		t.Fatalf("after the reseal: %d entries, owed %v", n, f.owed(id))
	}
}

// failApplyOnce fails one Apply when armed, after letting skip through.
type failApplyOnce struct {
	*MemStore
	fail bool
	skip int
}

func (s *failApplyOnce) Apply(ctx context.Context, cs []Change) error {
	if s.fail {
		if s.skip > 0 {
			s.skip--
		} else {
			s.fail = false
			return errors.New("store down")
		}
	}
	return s.MemStore.Apply(ctx, cs)
}

// The flush after housekeeping failing leaves the batch unacked, the start
// latch clear, and the changes dirty for the next flush.
func TestStepHousekeepingFlushFailure(t *testing.T) {
	f := newFixture(t)
	st := &failApplyOnce{MemStore: f.store}
	f.storeWrap = st
	f.start()
	m := f.member(10)
	cid := f.connect(m, "tag")
	f.pump()
	m.Send(peerwire.TypeConnAuthResponse, []byte(`{}`))
	f.p.mu.Lock()
	f.p.markDirty(kindConn, cid) // something for that flush to write
	f.p.drained = true           // as after a short collect, so the step must clear it
	f.p.mu.Unlock()
	st.fail, st.skip = true, 1 // markLeased's write goes through; the flush after housekeeping fails
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("the step didn't fail")
	}
	if st.fail {
		t.Fatal("the failure wasn't reached")
	}
	f.p.mu.Lock()
	drained, dirty, unacked := f.p.drained, len(f.p.dirty), len(f.p.unacked)
	f.p.mu.Unlock()
	if drained || dirty == 0 || unacked != 1 {
		t.Fatalf("drained %v, dirty %d, unacked %d", drained, dirty, unacked)
	}
	msgs, _ := f.sv.Collect(context.Background(), 0, 32)
	if len(msgs) != 0 {
		t.Fatalf("%d messages collectable at once: the batch was acked", len(msgs))
	}
	f.clk.Advance(61 * time.Second)
	f.pump()
	f.p.mu.Lock()
	dirty = len(f.p.dirty)
	f.p.mu.Unlock()
	if dirty != 0 {
		t.Fatal("the dirty changes weren't written by a later flush")
	}
}

// A real mailbox_unknown (the connection goes stale) owes the withdraw
// again; the record is made again, Gone, and kept across a restart.
func TestWithdrawMailboxUnknownOwedAgain(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, _ := withdrawCancelHeld(t, f, cid, peerwire.PurposeApproval, &relayclient.Error{Status: 404, Code: "mailbox_unknown"})
	f.pump()
	f.p.mu.Lock()
	ch := f.p.challenges[id]
	gone := ch != nil && ch.Gone
	f.p.mu.Unlock()
	if !f.owed(id) || !gone {
		t.Fatalf("after mailbox_unknown: owed %v, gone %v", f.owed(id), gone)
	}
	f.failDeposit = nil
	f.pump() // written
	f.start()
	if !f.owed(id) {
		t.Fatal("the re-created debt didn't survive a restart")
	}
}

// A drop after the challenge's exp owes nothing: the vault closes the ask.
func TestWithdrawDroppedAfterExpNotOwed(t *testing.T) {
	f := newFixture(t)
	cid := f.connect(f.member(10), "tag")
	id, _ := withdrawCancelHeld(t, f, cid, peerwire.PurposeApproval, errUnavailable)
	f.clk.Advance(11 * time.Minute)
	f.p.mu.Lock()
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.Withdraw == id })
	_, kept := f.p.challenges[id]
	f.p.mu.Unlock()
	if kept {
		t.Fatal("a record made again past the challenge's exp")
	}
}

// After a late send the record goes: a cancelled sign-in no longer holds
// a replacement back.
func TestLateSendDeletesRecord(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.setState(cid, StateSuspended)
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	if !f.p.HasPendingSignIn(cid) {
		t.Fatal("before the late send, the cancelled sign-in should still hold its place")
	}
	f.setState(cid, StateActive)
	f.tick()
	f.pump()
	f.p.mu.Lock()
	_, kept := f.p.challenges[id]
	f.p.mu.Unlock()
	if kept || f.p.HasPendingSignIn(cid) || len(m.Received(peerwire.TypeConnAuthWithdraw)) != 1 {
		t.Fatalf("after the late send: kept %v, pending %v", kept, f.p.HasPendingSignIn(cid))
	}
}
