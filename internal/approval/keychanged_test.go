package approval

import (
	"context"
	"strings"
	"testing"
	"time"
)

// forge stores approval id with approvals as given, as a record written
// before a changed key was set aside would hold them.
func (f *fixture) forge(id string, approvals ...Approver) {
	f.t.Helper()
	r, err := f.m.load(context.Background(), id)
	if err != nil || r == nil {
		f.t.Fatalf("load: %v", err)
	}
	r.Approvals = approvals
	b := f.m.batch(f.clk.Now())
	if err := b.save(r); err != nil {
		f.t.Fatal(err)
	}
	if err := b.apply(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) lastResponse() AuditEntry {
	f.t.Helper()
	var last AuditEntry
	for _, e := range f.audit() {
		if e.Type == AuditResponse {
			last = e
		}
	}
	return last
}

// A governance approval signed with a changed key is recorded, audited as
// key_changed and does not count; the threshold is not met by it.
func TestGovernanceKeyChangedNotCounted(t *testing.T) {
	for _, action := range []string{ActionAdminSetAdd, ActionAdminSetRemove, ActionProposalCreate, ActionVoteExtend, ActionContractTemplateChange} {
		if !Governance(action) {
			t.Errorf("%s is not governance", action)
		}
	}
	f := newFixture(t, 2, "c1", "c2", "c3")
	f.p.active["c4"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c4"}`)
	f.answer("c1", "approve")
	f.answer("c2", "approve-changed")
	e := f.lastResponse()
	if e.Counted == nil || *e.Counted || e.Reason != ReasonKeyChanged || !e.KeyChanged || e.Answer != AnswerApproved {
		t.Fatalf("audit %+v", e)
	}
	s := f.status(c.ID)
	if s.Status != StatusPending || len(s.Approvals) != 2 || s.Approvals[1].Counted || !s.Approvals[1].KeyChanged || !s.Approvals[0].Counted {
		t.Fatalf("threshold met by a changed key: %+v", s)
	}
	if strings.Join(f.admins(), ",") != "c1,c2,c3" {
		t.Fatalf("admin set changed: %v", f.admins())
	}
	// The admin has not answered: they are asked again, and a third
	// admin's approval settles it.
	if len(s.RemindNeeded) == 0 || s.RemindNeeded[0] != "c2" {
		t.Fatalf("remind_needed %v", s.RemindNeeded)
	}
	f.answer("c3", "approve")
	if s := f.status(c.ID); s.Status != StatusApproved || s.Applied == nil || !*s.Applied {
		t.Fatalf("%+v", s)
	}
}

// A key-changed approval is a pending admin's alone: with the others
// denying, it cannot make the threshold.
func TestGovernanceKeyChangedAloneNeverApproves(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.p.active["c2"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c2"}`)
	f.answer("c1", "approve-changed")
	if s := f.status(c.ID); s.Status != StatusPending || strings.Join(f.admins(), ",") != "c1" {
		t.Fatalf("%+v %v", s, f.admins())
	}
}

// After the pin has moved (the admin signs in again with the key now
// pinned), their approval counts.
func TestGovernanceApprovesAgainAfterRepin(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.p.active["c3"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	f.answer("c1", "approve-changed")
	if f.status(c.ID).Status != StatusPending {
		t.Fatal("settled")
	}
	f.clk.t = f.clk.t.Add(RemindInterval + time.Second)
	if _, err := f.m.Remind(context.Background(), c.ID, "c1"); err != nil {
		t.Fatalf("remind: %v", err)
	}
	f.answer("c1", "approve")
	s := f.status(c.ID)
	if s.Status != StatusApproved || len(s.Approvals) != 1 || !s.Approvals[0].Counted || s.Applied == nil || !*s.Applied {
		t.Fatalf("%+v", s)
	}
}

// Other actions are unaffected: assignment.push counts a changed key, as
// before, and says so.
func TestNonGovernanceKeyChangedCounts(t *testing.T) {
	if Governance(ActionAssignmentPush) {
		t.Fatal("assignment.push is governance")
	}
	f := newFixture(t, 1, "c1")
	c := f.create(ActionAssignmentPush, "Push", `{}`)
	f.answer("c1", "approve-changed")
	e := f.lastResponse()
	if e.Counted == nil || !*e.Counted || e.Reason != "" || !e.KeyChanged {
		t.Fatalf("audit %+v", e)
	}
	if s := f.status(c.ID); s.Status != StatusApproved || !s.Approvals[0].Counted || !s.Approvals[0].KeyChanged {
		t.Fatalf("%+v", s)
	}
}

// applyAdminSet refuses on a counted approval of a changed key, and when
// the approvals that count do not meet the threshold.
func TestApplyAdminSetRefusesKeyChanged(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.p.active["c2"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c2"}`)
	r, err := f.m.load(context.Background(), c.ID)
	if err != nil || r == nil {
		t.Fatal(err)
	}
	set := []string{"c1"}
	for name, ap := range map[string][]Approver{
		"changed key":  {{ConnectionID: "c1", KeyChanged: true, Counted: true}},
		"not counted":  {{ConnectionID: "c1", KeyChanged: true}},
		"no approvals": nil,
	} {
		r.Approvals = ap
		b := f.m.batch(f.clk.Now())
		if applied, err := f.m.applyAdminSet(b, r, set); err != nil || applied || len(b.changes) != 0 {
			t.Errorf("%s: applied=%v err=%v changes=%d", name, applied, err, len(b.changes))
		}
	}
	r.Approvals = []Approver{{ConnectionID: "c1", Counted: true}}
	if applied, err := f.m.applyAdminSet(f.m.batch(f.clk.Now()), r, set); err != nil || !applied {
		t.Fatalf("a pinned key: applied=%v err=%v", applied, err)
	}
}

// Consume does not count an approval of a changed key.
func TestConsumeRefusesKeyChanged(t *testing.T) {
	f := newFixture(t, 1, "c1")
	pl := canonProposal(t, proposalInput())
	a := f.built(ActionProposalCreate, pl)
	f.answer("c1", "approve")
	f.forge(a.ID, Approver{ConnectionID: "c1", KeyChanged: true, Counted: true})
	if code := codeOf(f.consume(a.ID, ActionProposalCreate, pl)); code != CodeApprovalNotApproved {
		t.Fatalf("consume: %q", code)
	}
	if _, used, _ := f.st.Get(context.Background(), kindUsed, a.ID); used {
		t.Fatal("used")
	}
	f.forge(a.ID, Approver{ConnectionID: "c1", Counted: true})
	if err := f.consume(a.ID, ActionProposalCreate, pl); err != nil {
		t.Fatal(err)
	}
}

// An approval record stored before Counted existed reads as counted.
func TestApproverReadsOldRecordAsCounted(t *testing.T) {
	var a Approver
	if err := a.UnmarshalJSON([]byte(`{"connection_id":"c1","key_changed":false}`)); err != nil || !a.Counted {
		t.Fatalf("%+v %v", a, err)
	}
}

// reevaluate settles at the higher of the approval's threshold and the
// current one, as Consume does.
func TestReevaluateUsesHigherThreshold(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionContractTemplateChange, "Open", `{}`)
	f.answer("c1", "approve")
	f.answer("c3", "deny")
	if f.status(c.ID).Status != StatusPending {
		t.Fatal("not pending")
	}
	f.m.Threshold = 3 // c1 + c2 could no longer make 3
	if err := f.m.reevaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := f.status(c.ID); s.Status != StatusDenied || s.Reason != ReasonAdminsRemoved {
		t.Fatalf("%+v", s)
	}
	// A lower current threshold does not lower the approval's own.
	g := newFixture(t, 2, "c1", "c2", "c3")
	d := g.create(ActionContractTemplateChange, "Open", `{}`)
	g.answer("c1", "approve")
	g.m.Threshold = 1
	if err := g.m.reevaluate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := g.status(d.ID); s.Status != StatusPending {
		t.Fatalf("%+v", s)
	}
}

// With threshold 2, one real admin plus one key-changed approval does not
// create or extend a vote: the approval is not approved, and Consume
// refuses even a record that holds both as counted.
func TestBallotActionsNeedTwoRealAdmins(t *testing.T) {
	for _, tc := range []struct {
		action  string
		payload func(*testing.T) []byte
	}{
		{ActionProposalCreate, func(t *testing.T) []byte { return canonProposal(t, proposalInput()) }},
		{ActionVoteExtend, func(t *testing.T) []byte { return canonExtension(t, extensionInput()) }},
	} {
		f := newFixture(t, 2, "c1", "c2")
		pl := tc.payload(t)
		a := f.built(tc.action, pl)
		f.answer("c1", "approve")
		f.answer("c2", "approve-changed")
		if s := f.status(a.ID); s.Status != StatusPending {
			t.Fatalf("%s: %s", tc.action, s.Status)
		}
		if code := codeOf(f.consume(a.ID, tc.action, pl)); code != CodeApprovalNotApproved {
			t.Fatalf("%s: consume %q", tc.action, code)
		}
		// A record forced to approved with the changed key as counted.
		r, _ := f.m.load(context.Background(), a.ID)
		r.Status = StatusApproved
		r.Approvals = []Approver{{ConnectionID: "c1", Counted: true}, {ConnectionID: "c2", KeyChanged: true, Counted: true}}
		b := f.m.batch(f.clk.Now())
		if err := b.save(r); err != nil {
			t.Fatal(err)
		}
		if err := b.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
		if code := codeOf(f.consume(a.ID, tc.action, pl)); code != CodeApprovalNotApproved {
			t.Fatalf("%s: forced consume %q", tc.action, code)
		}
	}
}
