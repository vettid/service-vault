package peer

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

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

// A connection whose outbox stays full isn't tried each step (sendEntry
// would log outbox_full every time): the debt waits quietly, and is paid
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
