package approval

import (
	"context"
	"strings"
	"testing"
)

// Only approvals of admins still in the set count toward m. With m = 2
// of {c1, c2, c3}: c1 approves and is then removed; c2's approval alone
// is not m, so the approval stays pending; c3's makes it.
func TestRemovedAdminApprovalNotCounted(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionVoteOpen, "Open", `{}`)
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
	c := f.create(ActionVoteOpen, "Open", `{}`)
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
