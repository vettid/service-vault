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
