package ballot

import (
	"context"
	"testing"
)

// An extension whose bundle checks is sent to every member, and says how
// many.
func TestExtendSendingCounts(t *testing.T) {
	ctx := context.Background()
	m, s, a, pid, x := extendFixture(t)
	approveExtension(t, a, "a", pid, x)
	o, err := m.Store.OpenProposal(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.ExtendSending(ctx, pid, "a", x)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != "" || got.Sending != len(o.Members) || got.Sending == 0 || got.ClosesAt != x.ClosesAt {
		t.Fatalf("%+v, %d members", got, len(o.Members))
	}
	m.Wait()
	n := 0
	for _, x := range s.sent {
		if x.typ == TypeExtended {
			n++
		}
	}
	if n != got.Sending {
		t.Fatalf("sent %d, said %d", n, got.Sending)
	}
}

// An extension made while the service is stopping is in effect but not
// sent: sending 0, reason stopping.
func TestExtendSendingStopping(t *testing.T) {
	ctx := context.Background()
	m, s, a, pid, x := extendFixture(t)
	approveExtension(t, a, "a", pid, x)
	m.StopSends()
	got, err := m.ExtendSending(ctx, pid, "a", x)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sending != 0 || got.Reason != ReasonStopping || got.ClosesAt != x.ClosesAt {
		t.Fatalf("%+v", got)
	}
	if extended(t, m, pid) != 1 {
		t.Fatal("not in effect")
	}
	for _, x := range s.sent {
		if x.typ == TypeExtended {
			t.Fatal("vote.extended sent while stopping")
		}
	}
}
