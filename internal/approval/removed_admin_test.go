package approval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// Only approvals of admins still in the set count toward m. With m = 2
// of {c1, c2, c3}: c1 approves and is then removed; c2's approval alone
// is not m, so the approval stays pending; c3's makes it.
func TestRemovedAdminApprovalNotCounted(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	f.answer("c1", "approve")
	if err := f.m.ConnectionRemoved(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	f.answer("c2", "approve")
	if s := f.status(c.ID); s.Status != StatusPending {
		t.Fatalf("status %s with one current admin's approval (admins now %v)", s.Status, f.admins())
	}
	f.answer("c3", "approve")
	if s := f.status(c.ID); s.Status != StatusApproved {
		t.Fatalf("status %s after two current admins", s.Status)
	}
}

// When removals leave too few current admins to reach m, counting only
// current approvals denies it.
func TestRemovedAdminApprovalDeniesWhenUnreachable(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	f.answer("c1", "approve")
	f.answer("c3", "deny")
	if err := f.m.ConnectionRemoved(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if s := f.status(c.ID); s.Status != StatusDenied {
		t.Fatalf("status %s: c2 alone cannot make m = 2", s.Status)
	}
}

// A removal that leaves fewer admins than m raises admins_short; one that
// leaves enough does not.
func TestRemovedAdminBelowThresholdAlarms(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	if err := f.m.ConnectionRemoved(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.logs.String(), "admins_short") {
		t.Fatalf("alarm with two admins left for m = 2:\n%s", f.logs)
	}
	if err := f.m.ConnectionRemoved(context.Background(), "c2"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logs.String(), "alarm=admins_short") {
		t.Fatalf("no alarm with one admin left for m = 2:\n%s", f.logs)
	}
}

// admins_short is logged while the set is short, at start and on ticks at
// most every ShortAlarmEvery, across a restart, and stops with one line
// once the set is back at the threshold (GC #11179).
func TestAdminsShortHeldWhileShort(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	count := func() int { return strings.Count(f.logs.String(), "alarm=admins_short") }
	if err := f.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatalf("start with no admins: %d lines\n%s", count(), f.logs)
	}
	for _, step := range []struct {
		advance time.Duration
		want    int
	}{
		{0, 1},                             // a tick at once: not again
		{ShortAlarmEvery - time.Second, 1}, // within the minute
		{time.Second, 2},                   // a minute on
		{30 * time.Second, 2},
		{30 * time.Second, 3},
		{10 * ShortAlarmEvery, 4},
	} {
		f.clk.Advance(step.advance)
		if err := f.m.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		if count() != step.want {
			t.Fatalf("after %s: %d lines, want %d\n%s", step.advance, count(), step.want, f.logs)
		}
	}
	// A restart: a new manager on the same store logs it at start.
	m2 := &Manager{Peer: f.p, Store: f.st, Pager: f.st, Hooks: f.hk.out, ServiceName: f.m.ServiceName, Threshold: 1, Now: f.clk.Now, Log: f.m.Log}
	if err := m2.Start(ctx); err != nil || count() != 5 {
		t.Fatalf("restart: %d lines, %v", count(), err)
	}
	// The set is filled: one "back" line, and no admins_short after.
	b := m2.batch(f.clk.Now())
	if err := b.setAdmins([]string{"c1"}); err != nil {
		t.Fatal(err)
	}
	if err := b.apply(ctx); err != nil {
		t.Fatal(err)
	}
	f.p.active["c1"] = true
	for i := 0; i < 3; i++ {
		f.clk.Advance(ShortAlarmEvery)
		if err := m2.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if count() != 5 || strings.Count(f.logs.String(), "admin set back at the threshold") != 1 {
		t.Fatalf("after the set was filled: %d alarm lines\n%s", count(), f.logs)
	}
}

// A removal's own admins_short line counts: the next tick within the
// minute doesn't repeat it, the one after does. A set at the threshold
// logs nothing.
func TestAdminsShortAfterRemoval(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	ctx := context.Background()
	count := func() int { return strings.Count(f.logs.String(), "alarm=admins_short") }
	if err := f.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Tick(ctx); err != nil || count() != 0 || strings.Contains(f.logs.String(), "back at the threshold") {
		t.Fatalf("at the threshold: %d lines, %v\n%s", count(), err, f.logs)
	}
	if err := f.m.ConnectionRemoved(ctx, "c1"); err != nil || count() != 1 {
		t.Fatalf("removal: %d lines, %v", count(), err)
	}
	if err := f.m.Tick(ctx); err != nil || count() != 1 {
		t.Fatalf("tick at once: %d lines, %v", count(), err)
	}
	f.clk.Advance(ShortAlarmEvery)
	if err := f.m.Tick(ctx); err != nil || count() != 2 {
		t.Fatalf("a minute on: %d lines, %v", count(), err)
	}
}

// A tick that fails while the set is short still logs admins_short each
// minute: the set isn't known to be mended (fail secure). Here an armed
// bootstrap's bound-connection lookup fails on every tick.
func TestAdminsShortHeldWhenTickFails(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	count := func() int { return strings.Count(f.logs.String(), "alarm=admins_short") }
	f.m.BootstrapKey = "boot-key"
	f.m.BoundConnection = func(context.Context, string) (string, bool, error) { return "", false, errors.New("store fault") }
	if err := f.m.Start(ctx); err != nil || count() != 1 {
		t.Fatalf("start: %d lines, %v", count(), err)
	}
	for i := 2; i <= 4; i++ {
		f.clk.Advance(ShortAlarmEvery)
		if err := f.m.Tick(ctx); err == nil {
			t.Fatal("the tick didn't fail")
		}
		if count() != i {
			t.Fatalf("failing tick %d: %d lines\n%s", i, count(), f.logs)
		}
	}
	// A tick that fails within the minute adds nothing.
	if err := f.m.Tick(ctx); err == nil || count() != 4 {
		t.Fatalf("within the minute: %d lines, %v", count(), err)
	}
}

// failGet fails every Get while fail is set: a store fault.
type failGet struct {
	peer.Store
	fail bool
}

func (s *failGet) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if s.fail {
		return nil, false, errors.New("store fault")
	}
	return s.Store.Get(ctx, kind, id)
}

// A tick that can't read the admin set at all keeps a short set's alarm
// raised, once a minute; one that never saw the set short logs nothing.
func TestAdminsShortHeldWhenStateUnreadable(t *testing.T) {
	f := newFixture(t, 1)
	ctx := context.Background()
	count := func() int { return strings.Count(f.logs.String(), "alarm=admins_short") }
	st := &failGet{Store: f.st}
	f.m.Store = st
	if err := f.m.Start(ctx); err != nil || count() != 1 {
		t.Fatalf("start: %d lines, %v", count(), err)
	}
	st.fail = true
	for i := 2; i <= 3; i++ {
		f.clk.Advance(ShortAlarmEvery)
		if err := f.m.Tick(ctx); err == nil || count() != i {
			t.Fatalf("unreadable tick %d: %d lines, %v", i, count(), err)
		}
	}
	if err := f.m.Tick(ctx); err == nil || count() != 3 {
		t.Fatalf("within the minute: %d lines, %v", count(), err)
	}
	// A manager that never saw the set short says nothing on a fault.
	g := newFixture(t, 1, "c1")
	gst := &failGet{Store: g.st}
	g.m.Store = gst
	if err := g.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	gst.fail = true
	g.clk.Advance(ShortAlarmEvery)
	if err := g.m.Tick(ctx); err == nil || strings.Contains(g.logs.String(), "admins_short") {
		t.Fatalf("not short: %v\n%s", err, g.logs)
	}
}
