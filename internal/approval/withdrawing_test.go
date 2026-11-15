package approval

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// remindReplacing makes c1's challenge undelivered, so a reminder
// replaces it, and returns the approval and that challenge.
func remindReplacing(t *testing.T, f *fixture) (*Created, sent) {
	t.Helper()
	f.m.LongChallenges = true
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	old := f.p.last("c1")
	f.p.mu.Lock()
	f.p.delivery = map[string]peer.Delivery{old.req: peer.DeliveryUndelivered}
	f.p.mu.Unlock()
	f.clk.Advance(RemindInterval)
	return c, old
}

func (f *fixture) record(id string) *record {
	f.t.Helper()
	r, err := f.m.load(context.Background(), id)
	if err != nil || r == nil {
		f.t.Fatalf("load %s: %v", id, err)
	}
	return r
}

// errFlush is a store error in the peer's flush, one of the failures the
// real CancelChallenge returns (with peer.ErrNotStarted).
var errFlush = errors.New("peer flush: store down")

func withdrawingIDs(r *record) []string {
	var out []string
	for _, c := range r.Withdrawing {
		out = append(out, c.RequestID)
	}
	return out
}

// The early save names the replaced challenge in Withdrawing and audits
// it; a withdraw that succeeds clears it in the reminder's own save.
func TestRemindRecordsWithdrawing(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.p.cancelled, old.req) {
		t.Fatal("not withdrawn")
	}
	if w := f.record(c.ID).Withdrawing; len(w) != 0 {
		t.Fatalf("withdrawing %v after a withdraw that worked", w)
	}
	a := f.auditOf(AuditReplaced)
	if len(a) != 1 || a[0].ApprovalID != c.ID || len(a[0].Challenges) != 1 || a[0].Challenges[0].RequestID != old.req || a[0].Challenges[0].ConnectionID != "c1" {
		t.Fatalf("audit %+v", a)
	}
}

// A withdraw that fails leaves the replaced challenge in Withdrawing. An
// approval of it doesn't count. Each tick withdraws it again until that
// works, then clears it.
func TestWithdrawingRetriedOnTick(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	f.p.mu.Lock()
	f.p.cancelFail = map[string]error{old.req: errFlush}
	f.p.mu.Unlock()
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if w := withdrawingIDs(f.record(c.ID)); !slices.Equal(w, []string{old.req}) {
		t.Fatalf("withdrawing %v", w)
	}
	// The member approves the replaced challenge: audited, not counted.
	f.answerTo(old, "approve")
	if r := f.lastResponse(); r.RequestID != old.req || r.Counted == nil || *r.Counted {
		t.Fatalf("response %+v", r)
	}
	if s := f.status(c.ID); s.Status != StatusPending || len(s.Approvals) != 0 {
		t.Fatalf("status %+v", s)
	}
	f.tick() // still failing: kept
	if w := withdrawingIDs(f.record(c.ID)); !slices.Equal(w, []string{old.req}) {
		t.Fatalf("withdrawing %v after a failing retry", w)
	}
	f.p.mu.Lock()
	f.p.cancelFail = nil
	f.p.mu.Unlock()
	f.tick()
	if !slices.Contains(f.p.cancelled, old.req) {
		t.Fatal("not withdrawn on the tick")
	}
	if w := f.record(c.ID).Withdrawing; len(w) != 0 {
		t.Fatalf("withdrawing %v after the retry worked", w)
	}
}

// A crash after the early save (the reminder's own save never happens):
// the record names the replaced challenge, an approval of it doesn't
// count, and the next tick withdraws it.
func TestWithdrawingAfterCrash(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	// The early save goes through and the withdraw fails, as if the
	// process stopped between them; then the reminder's save fails.
	f.p.mu.Lock()
	f.p.cancelFail = map[string]error{old.req: peer.ErrNotStarted}
	f.p.mu.Unlock()
	f.m.Store = &failAfterStore{Store: f.st, kind: kindApproval, ok: 1}
	if _, err := f.m.Remind(context.Background(), c.ID); err == nil {
		t.Fatal("the reminder's save didn't fail")
	}
	f.m.Store = f.st
	if w := withdrawingIDs(f.record(c.ID)); !slices.Equal(w, []string{old.req}) {
		t.Fatalf("withdrawing %v", w)
	}
	f.answerTo(old, "approve")
	if r := f.lastResponse(); r.Counted == nil || *r.Counted {
		t.Fatalf("response %+v", r)
	}
	f.p.mu.Lock()
	f.p.cancelFail = nil
	f.p.mu.Unlock()
	f.tick()
	if !slices.Contains(f.p.cancelled, old.req) || len(f.record(c.ID).Withdrawing) != 0 {
		t.Fatalf("after the tick: cancelled %v, withdrawing %v", f.p.cancelled, f.record(c.ID).Withdrawing)
	}
}

// An approval that settles while a withdraw is still owed stays in the
// open index, so the tick keeps withdrawing; it leaves once that works.
func TestWithdrawingOutlivesSettlement(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	f.p.mu.Lock()
	f.p.cancelFail = map[string]error{old.req: errFlush}
	f.p.mu.Unlock()
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	f.answer("c2", "deny")
	if s := f.status(c.ID); s.Status != StatusDenied {
		t.Fatalf("status %s", s.Status)
	}
	if f.openCount() != 1 {
		t.Fatalf("open index %d: dropped with a withdraw owed", f.openCount())
	}
	f.tick()
	if f.openCount() != 1 || len(f.record(c.ID).Withdrawing) != 1 {
		t.Fatalf("after a failing retry: open %d, withdrawing %v", f.openCount(), f.record(c.ID).Withdrawing)
	}
	f.p.mu.Lock()
	f.p.cancelFail = nil
	f.p.mu.Unlock()
	f.tick()
	if !slices.Contains(f.p.cancelled, old.req) || f.openCount() != 0 || len(f.record(c.ID).Withdrawing) != 0 {
		t.Fatalf("after the retry worked: cancelled %v, open %d", f.p.cancelled, f.openCount())
	}
	if s := f.status(c.ID); s.Status != StatusDenied {
		t.Fatalf("status changed to %s", s.Status)
	}
}

// An approval that expires while a withdraw is owed: the same.
func TestWithdrawingOutlivesExpiry(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	f.p.mu.Lock()
	f.p.cancelFail = map[string]error{old.req: errFlush}
	f.p.mu.Unlock()
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(DefaultTTL)
	f.m.once.Do(func() { f.m.kick = make(chan struct{}, 1) })
	f.tick() // the pass that settles it wakes Run, once
	if s := f.status(c.ID); s.Status != StatusExpired || f.openCount() != 1 {
		t.Fatalf("status %s, open %d", s.Status, f.openCount())
	}
	if len(f.m.kick) != 1 {
		t.Fatal("the expiring pass didn't wake Run")
	}
	<-f.m.kick
	f.tick() // still owed, already settled: no wake
	if len(f.m.kick) != 0 {
		t.Fatal("a later pass woke Run")
	}
	f.p.mu.Lock()
	f.p.cancelFail = nil
	f.p.mu.Unlock()
	f.tick()
	if !slices.Contains(f.p.cancelled, old.req) || f.openCount() != 0 {
		t.Fatalf("cancelled %v, open %d", f.p.cancelled, f.openCount())
	}
}

// A settled record kept open for its Withdrawing list doesn't wake Run on
// each pass (which would tick again at once, in a loop, while the
// withdraw keeps failing), nor log "approval settled" again.
func TestWithdrawingSettledDoesNotWake(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c, old := remindReplacing(t, f)
	f.p.mu.Lock()
	f.p.cancelFail = map[string]error{old.req: peer.ErrNotStarted}
	f.p.mu.Unlock()
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	f.answer("c2", "deny")
	f.m.once.Do(func() { f.m.kick = make(chan struct{}, 1) })
	for i := 0; i < 3; i++ {
		select { // drain
		case <-f.m.kick:
		default:
		}
		f.tick()
		if len(f.m.kick) != 0 {
			t.Fatalf("pass %d woke Run", i)
		}
	}
	if n := strings.Count(f.logs.String(), "approval settled"); n != 0 {
		t.Fatalf("settled logged %d times", n)
	}
	if f.openCount() != 1 {
		t.Fatalf("open %d", f.openCount())
	}
}

// Several replaced at once, one failing: only the failing one stays.
func TestWithdrawingKeepsOnlyFailures(t *testing.T) {
	f := newFixture(t, 3, "c1", "c2", "c3")
	f.m.LongChallenges = true
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	o1, o2 := f.p.last("c1"), f.p.last("c2")
	f.p.mu.Lock()
	f.p.delivery = map[string]peer.Delivery{o1.req: peer.DeliveryUndelivered, o2.req: peer.DeliveryUndelivered}
	f.p.cancelFail = map[string]error{o2.req: errFlush}
	f.p.mu.Unlock()
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if w := withdrawingIDs(f.record(c.ID)); !slices.Equal(w, []string{o2.req}) {
		t.Fatalf("withdrawing %v, want only %s", w, o2.req)
	}
}

// A later reminder keeps an earlier one's failed withdraw listed: X fails
// at reminder 1; reminder 2 replaces Y, whose withdraw works; X stays.
func TestWithdrawingKeptAcrossReminders(t *testing.T) {
	f := newFixture(t, 3, "c1", "c2", "c3")
	f.m.LongChallenges = true
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	x, y := f.p.last("c1"), f.p.last("c2")
	f.p.mu.Lock()
	f.p.delivery = map[string]peer.Delivery{x.req: peer.DeliveryUndelivered}
	f.p.cancelFail = map[string]error{x.req: errFlush}
	f.p.mu.Unlock()
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	f.p.delivery = map[string]peer.Delivery{y.req: peer.DeliveryUndelivered}
	f.p.mu.Unlock()
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.p.cancelled, y.req) {
		t.Fatal("Y not withdrawn")
	}
	if w := withdrawingIDs(f.record(c.ID)); !slices.Equal(w, []string{x.req}) {
		t.Fatalf("withdrawing %v, want only %s", w, x.req)
	}
}
