package approval

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// challenges returns the challenges of the audit entries of type typ.
func (f *fixture) challenges(typ string) []Challenge {
	f.t.Helper()
	pg, err := f.m.Audit(context.Background(), "", 100)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []Challenge
	for _, e := range pg.Entries {
		if e.Type == typ {
			out = append(out, e.Challenges...)
		}
	}
	return out
}

// A challenge queued behind its connection's reconnect is not shown as
// sent: the audit says queued, the status lists the admin in queued (not
// remind_needed), and a reminder leaves them out. Once deposited, the
// admin is in neither list.
func TestQueuedChallengeNotSent(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.m.LongChallenges = true
	f.p.queue = map[string]bool{"c2": true}
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	got := fmt.Sprint(f.challenges(AuditRequested))
	if want := fmt.Sprintf("[{c1 %s false} {c2 %s true}]", f.p.sent[0].req, f.p.sent[1].req); got != want {
		t.Fatalf("audit %s, want %s", got, want)
	}
	if !strings.Contains(f.logs.String(), "queued=1") {
		t.Fatalf("log: %s", f.logs.String())
	}
	s := f.status(c.ID)
	if fmt.Sprint(s.Queued) != "[c2]" || len(s.RemindNeeded) != 0 || s.RemindAfter != nil {
		t.Fatalf("%+v", s)
	}
	f.clk.Advance(RemindInterval)
	n := len(f.p.sent)
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeNothingToRemind {
		t.Fatalf("remind: %v", err)
	}
	if len(f.p.sent) != n || len(f.p.cancelled) != 0 {
		t.Fatal("a queued challenge was replaced")
	}
	f.p.deliver(f.p.last("c2").req, peer.DeliverySent)
	if s := f.status(c.ID); len(s.Queued) != 0 || len(s.RemindNeeded) != 0 {
		t.Fatalf("after the deposit %+v", s)
	}
}

// A challenge that left the outbox undelivered puts its admin in
// remind_needed, and a reminder replaces it.
func TestUndeliveredChallengeReminded(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.m.LongChallenges = true
	f.p.queue = map[string]bool{"c2": true}
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	old := f.p.last("c2").req
	f.p.deliver(old, peer.DeliveryUndelivered)
	s := f.status(c.ID)
	if fmt.Sprint(s.RemindNeeded) != "[c2]" || len(s.Queued) != 0 || s.RemindAfter == nil {
		t.Fatalf("%+v", s)
	}
	f.p.queue = nil
	f.clk.Advance(RemindInterval)
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || fmt.Sprint(r.Reminded) != "[c2]" {
		t.Fatalf("%+v %v", r, err)
	}
	if !slices.Contains(f.p.cancelled, old) || f.p.last("c2").req == old {
		t.Fatal("not replaced")
	}
	if got := f.challenges(AuditReminded); len(got) != 1 || got[0].Queued {
		t.Fatalf("audit %v", got)
	}
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 || len(s.Queued) != 0 {
		t.Fatalf("after the reminder %+v", s)
	}
}

// With the gate off a reminder challenges every admin who has not
// answered, but not one whose challenge is still queued.
func TestQueuedChallengeNotRemindedWithoutGate(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	f.p.queue = map[string]bool{"c2": true}
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	queued := f.p.last("c2").req
	f.clk.Advance(RemindInterval)
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || fmt.Sprint(r.Reminded) != "[c1]" {
		t.Fatalf("%+v %v", r, err)
	}
	if slices.Contains(f.p.cancelled, queued) || f.p.last("c2").req != queued {
		t.Fatal("the queued challenge was replaced")
	}
	// Only the queued admin left: nothing to remind.
	f.p.queue = map[string]bool{"c1": true}
	g := f.create(ActionContractTemplateChange, "Again", `{}`)
	f.p.deliver(f.p.last("c2").req, peer.DeliveryQueued)
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), g.ID); codeOf(err) != CodeNothingToRemind {
		t.Fatalf("remind: %v", err)
	}
}
