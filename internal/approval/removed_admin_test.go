package approval

import (
	"context"
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
