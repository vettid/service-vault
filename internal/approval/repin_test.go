package approval

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

var (
	keyA = bytes.Repeat([]byte{7}, 32) // the fixture's default credential key
	keyB = bytes.Repeat([]byte{0xb2}, 32)
	keyC = bytes.Repeat([]byte{0xc3}, 32)
)

func repinPay(conn string, key []byte) string {
	return `{"connection_id":"` + conn + `","new_key":"` + base64.StdEncoding.EncodeToString(key) + `"}`
}

// c1 signed in with keyB: its credential key moved, its governance key
// (keyA) did not.
func (f *fixture) moved(conn string, key []byte) {
	f.p.auth = map[string][]byte{conn: key}
}

func (f *fixture) govKey(conn string) []byte {
	ci, _ := f.p.Connection(conn)
	return ci.GovKey
}

// After a key change every later governance approval from the admin is
// set aside, not only the first.
func TestEveryApprovalAfterKeyChangeIsSetAside(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	f.p.active["c4"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c4"}`)
	f.answer("c1", "approve-changed")
	if e := f.lastResponse(); *e.Counted || e.Reason != ReasonKeyChanged {
		t.Fatalf("first: %+v", e)
	}
	f.clk.t = f.clk.t.Add(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID, "c1"); err != nil {
		t.Fatal(err)
	}
	f.answer("c1", "approve-unpinned") // the key is not a change from the last sign-in any more
	e := f.lastResponse()
	if *e.Counted || e.Reason != ReasonNotRepinned || e.KeyChanged {
		t.Fatalf("later: %+v", e)
	}
	f.answer("c2", "approve")
	s := f.status(c.ID)
	if s.Status != StatusPending || len(s.Approvals) != 2 || s.Approvals[0].Counted || s.Approvals[0].Reason != ReasonNotRepinned {
		t.Fatalf("%+v", s)
	}
}

// admin.repin: approved by the other admins, it makes the credential key
// the governance key; the admin's approvals count again.
func TestRepinRestoresCounting(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.moved("c1", keyB)
	if !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatal("governance key moved by a sign-in")
	}
	// The service fills in new_key; the summary names both keys.
	c := f.create(ActionAdminRepin, "", `{"connection_id":"c1"}`)
	s := f.status(c.ID)
	if !strings.HasPrefix(s.Summary, "name not given, old key "+fingerprint(ckFPLabel, keyA)+", new key "+fingerprint(ckFPLabel, keyB)+", connection c1") {
		t.Fatalf("summary %q", s.Summary)
	}
	if strings.Join(s.Admins, ",") != "c2" {
		t.Fatalf("asked %v", s.Admins)
	}
	if n := len(f.p.sent); n != 1 || f.p.sent[0].conn != "c2" {
		t.Fatalf("challenges %+v", f.p.sent)
	}
	if !strings.Contains(f.p.sent[0].ctxt, "Re-pin admin: name not given, old key") {
		t.Fatalf("context %q", f.p.sent[0].ctxt)
	}
	f.answer("c2", "approve")
	s = f.status(c.ID)
	if s.Status != StatusApproved || s.Applied == nil || !*s.Applied || !bytes.Equal(f.govKey("c1"), keyB) {
		t.Fatalf("%+v gov %x", s, f.govKey("c1"))
	}
	var repinned bool
	for _, e := range f.audit() {
		repinned = repinned || e.Type == AuditAdminRepinned && e.ConnectionID == "c1" && e.ApprovalID == c.ID
	}
	if !repinned {
		t.Fatal("no admin.repinned audit entry")
	}
}

func TestRepinThenGovernanceApprovalCounts(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.p.active["c3"] = true
	f.moved("c1", keyB)
	before := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	f.answer("c1", "approve-unpinned")
	if f.status(before.ID).Status != StatusPending {
		t.Fatal("counted before the re-pin")
	}
	r := f.create(ActionAdminRepin, "", repinPay("c1", keyB))
	f.answer("c2", "approve")
	if s := f.status(r.ID); s.Applied == nil || !*s.Applied {
		t.Fatalf("%+v", s)
	}
	// Asked again, c1 signs with the (now) governance key.
	f.clk.t = f.clk.t.Add(RemindInterval)
	if _, err := f.m.Remind(context.Background(), before.ID, "c1"); err != nil {
		t.Fatal(err)
	}
	f.answer("c1", "approve")
	if s := f.status(before.ID); s.Status != StatusApproved || !s.Approvals[0].Counted {
		t.Fatalf("%+v", s)
	}
}

// The admin re-pinned does not approve their own re-pin: they are not
// asked, and a forged approval of theirs does not count.
func TestRepinSelfApprovalDoesNotCount(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.moved("c1", keyB)
	c := f.create(ActionAdminRepin, "", repinPay("c1", keyB))
	for _, s := range f.p.sent {
		if s.conn == "c1" {
			t.Fatal("the admin re-pinned was asked")
		}
	}
	f.forge(c.ID, Approver{ConnectionID: "c1", Counted: true})
	r, _ := f.m.load(context.Background(), c.ID)
	if n := r.standing([]string{"c1", "c2"}); n != 0 {
		t.Fatalf("self-approval counts: %d", n)
	}
	// An approval of their own the settling does not apply either.
	b := f.m.batch(f.clk.Now())
	if applied, err := f.m.applyAdminSet(context.Background(), b, r, []string{"c1", "c2"}); err != nil || applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
	if !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatal("moved")
	}
}

func TestRepinSoleAdminRefused(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.moved("c1", keyB)
	_, err := f.m.Create(context.Background(), Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c1", keyB))})
	if codeOf(err) != CodeSoleAdmin {
		t.Fatalf("%v", err)
	}
	if len(f.p.sent) != 0 {
		t.Fatal("challenges sent")
	}
}

func TestRepinRefusals(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 2, "c1", "c2", "c3")
	f.p.active["c9"] = true
	f.p.auth = map[string][]byte{"c1": keyB, "c9": keyB}
	for name, tc := range map[string]struct {
		req  Request
		code string
	}{
		"app summary":    {Request{Action: ActionAdminRepin, Summary: "x", Payload: json.RawMessage(repinPay("c1", keyB))}, CodeInvalidSummary},
		"not an admin":   {Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c9", keyB))}, CodeInvalidConnection},
		"unknown":        {Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c8", keyB))}, CodeInvalidConnection},
		"stale key":      {Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c1", keyC))}, CodeInvalidPayload},
		"already pinned": {Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c2", keyA))}, CodeInvalidPayload},
		"extra field":    {Request{Action: ActionAdminRepin, Payload: json.RawMessage(`{"connection_id":"c1","x":1}`)}, CodeInvalidPayload},
		"short key":      {Request{Action: ActionAdminRepin, Payload: json.RawMessage(`{"connection_id":"c1","new_key":"AAAA"}`)}, CodeInvalidPayload},
	} {
		if _, err := f.m.Create(ctx, tc.req); codeOf(err) != tc.code {
			t.Errorf("%s: %v, want %s", name, err, tc.code)
		}
	}
	if _, err := f.m.Create(ctx, Request{Action: ActionAdminRepin, Payload: json.RawMessage(repinPay("c1", keyB))}); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

// If the credential key moved again after the admins were shown the keys,
// the re-pin is not applied.
func TestRepinNotAppliedWhenAuthKeyMovedAgain(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.moved("c1", keyB)
	c := f.create(ActionAdminRepin, "", repinPay("c1", keyB))
	f.moved("c1", keyC)
	f.answer("c2", "approve")
	s := f.status(c.ID)
	if s.Status != StatusApproved || s.Applied == nil || *s.Applied || !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatalf("%+v gov %x", s, f.govKey("c1"))
	}
}

// An approval of admin.repin from an admin whose own key changed does not
// count: the governance rule holds for it too.
func TestRepinNeedsPinnedApprovers(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.moved("c1", keyB)
	c := f.create(ActionAdminRepin, "", repinPay("c1", keyB))
	f.answer("c2", "approve-changed")
	if s := f.status(c.ID); s.Status != StatusPending || !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatalf("%+v", s)
	}
}

// Admins from before the governance key are pinned to their credential key
// at start; new admins are pinned when added.
func TestGovKeyMigrationAndAdd(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, "c1")
	f.p.gov = map[string][]byte{"c1": nil} // none pinned: as stored before
	if len(f.govKey("c1")) != 0 {
		t.Fatal("setup")
	}
	if err := f.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatalf("migrated %x", f.govKey("c1"))
	}
	// Added: pinned to the credential key it has when added.
	f.p.active["c2"] = true
	f.p.auth = map[string][]byte{"c2": keyB}
	f.p.gov["c2"] = keyC // a stale value from before
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c2"}`)
	f.answer("c1", "approve")
	if s := f.status(c.ID); s.Applied == nil || !*s.Applied || !bytes.Equal(f.govKey("c2"), keyB) {
		t.Fatalf("%+v %x", s, f.govKey("c2"))
	}
}
