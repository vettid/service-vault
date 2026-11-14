package main

import (
	"testing"

	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// Admins whose challenge is queued are shown before the remind line, and
// alone when nobody needs a reminder.
func TestRemindLineQueued(t *testing.T) {
	st := &servicevault.Approval{ID: "a1", Status: servicevault.ApprovalStatusPending, Queued: []string{"c2"}}
	if got, want := remindLine(st), "queued, not sent yet: c2\n"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	st.RemindNeeded = []string{"c1"}
	if got, want := remindLine(st), "queued, not sent yet: c2\nremind needed: c1 (svctl remind a1)\n"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	st.Status = servicevault.ApprovalStatusApproved
	if got := remindLine(st); got != "" {
		t.Fatalf("settled: %q", got)
	}
}

// An admin whose queued challenge has left the outbox is named; one that
// left it undelivered (now in remind_needed) is not.
func TestUnqueuedLine(t *testing.T) {
	st := &servicevault.Approval{ID: "a1", Status: servicevault.ApprovalStatusPending, Queued: []string{"c3"}, RemindNeeded: []string{"c2"}}
	if got, want := unqueuedLine([]string{"c1", "c2", "c3"}, st), "no longer queued: c1\n"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got := unqueuedLine(nil, st); got != "" {
		t.Fatalf("nothing was queued: %q", got)
	}
}
