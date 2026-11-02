package approval

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
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
	f.p.changedAt = map[string]time.Time{"c1": time.Date(2026, 11, 2, 11, 42, 59, 0, time.UTC)}
	c := f.create(ActionAdminRepin, "", `{"connection_id":"c1"}`)
	s := f.status(c.ID)
	if want := "name not given, new key " + fingerprint(ckFPLabel, keyB) + ", key changed 2026-11-02 11:42 UTC, connection c1"; s.Summary != want {
		t.Fatalf("summary %q, want %q", s.Summary, want)
	}
	if strings.Join(s.Admins, ",") != "c2" {
		t.Fatalf("asked %v", s.Admins)
	}
	if n := len(f.p.sent); n != 1 || f.p.sent[0].conn != "c2" {
		t.Fatalf("challenges %+v", f.p.sent)
	}
	if !strings.Contains(f.p.sent[0].ctxt, "Re-pin admin: name not given, new key") {
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

func (f *fixture) auditOf(typ string) []AuditEntry {
	f.t.Helper()
	var out []AuditEntry
	for _, e := range f.audit() {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// Admins from before the governance key are pinned at a tick, once the peer
// knows their connection (it loads after the manager starts); with no
// evidence, to the credential key they have, audited so.
func TestGovKeyMigrationNoEvidence(t *testing.T) {
	f := newFixture(t, 1, "c1")
	delete(f.p.active, "c1") // the peer has not loaded its connections
	f.p.gov = map[string][]byte{"c1": nil}
	f.tick()
	if len(f.govKey("c1")) != 0 || len(f.auditOf(AuditGovKeyMigrated)) != 0 {
		t.Fatal("pinned before the peer knew the connection")
	}
	f.p.active["c1"] = true
	f.tick()
	if !bytes.Equal(f.govKey("c1"), keyA) {
		t.Fatalf("migrated %x", f.govKey("c1"))
	}
	au := f.auditOf(AuditGovKeyMigrated)
	if len(au) != 1 || au[0].Reason != ReasonNoEvidence || au[0].ConnectionID != "c1" ||
		au[0].Fingerprint != compactFP(fingerprint(ckFPLabel, keyA)) {
		t.Fatalf("audit %+v", au)
	}
	f.tick()
	if len(f.auditOf(AuditGovKeyMigrated)) != 1 {
		t.Fatal("migrated twice")
	}
}

// The key pinned is that of the admin's earliest signed approval, not the
// one the connection holds now: after a key change the current key needs a
// re-pin. Open governance approvals holding approvals are ended.
func TestGovKeyMigrationFromEvidence(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	f.p.active["c4"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c4"}`)
	f.answer("c1", "approve") // signed with the fixture's 0x11 key
	f.legacy(c.ID, "c1")
	signed := bytes.Repeat([]byte{0x11}, 32)
	f.moved("c1", keyB) // the connection holds another key now
	f.p.gov = map[string][]byte{"c1": nil, "c2": nil, "c3": nil}
	f.tick()
	if !bytes.Equal(f.govKey("c1"), signed) {
		t.Fatalf("c1 pinned %x", f.govKey("c1"))
	}
	if !bytes.Equal(f.govKey("c2"), keyA) {
		t.Fatalf("c2 pinned %x", f.govKey("c2"))
	}
	reasons := map[string]string{}
	for _, e := range f.auditOf(AuditGovKeyMigrated) {
		reasons[e.ConnectionID] = e.Reason
	}
	if reasons["c1"] != ReasonEvidence || reasons["c2"] != ReasonNoEvidence {
		t.Fatalf("reasons %v", reasons)
	}
	if s := f.status(c.ID); s.Status != StatusExpired || s.Reason != ReasonGovMigrated {
		t.Fatalf("%+v", s)
	}
}

// admin_set.add pins the key the admins were shown; if the connection's
// credential key moved after, nothing is applied and it is audited.
func TestAdminSetAddPinsApprovedKey(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.p.active["c2"], f.p.active["c3"], f.p.noAuth = true, true, map[string]bool{"c3": true}
	f.p.auth = map[string][]byte{"c2": keyB}
	f.p.gov = map[string][]byte{"c2": keyC} // a stale value
	if _, err := f.m.Create(context.Background(), Request{Action: ActionAdminSetAdd, Payload: json.RawMessage(`{"connection_id":"c3"}`)}); codeOf(err) != CodeInvalidConnection {
		t.Fatalf("no credential key: %v", err)
	}
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c2"}`)
	if !strings.Contains(f.status(c.ID).Summary, ", cred key "+fingerprint(ckFPLabel, keyB)+", connection c2") {
		t.Fatalf("summary %q", f.status(c.ID).Summary)
	}
	f.p.auth["c2"] = keyC // moved after the admins were shown keyB
	f.answer("c1", "approve")
	s := f.status(c.ID)
	if s.Status != StatusApproved || s.Applied == nil || *s.Applied || strings.Join(f.admins(), ",") != "c1" {
		t.Fatalf("%+v %v", s, f.admins())
	}
	if au := f.auditOf(AuditGovKeyRefused); len(au) != 1 || au[0].Reason != ReasonAuthKeyMoved {
		t.Fatalf("audit %+v", au)
	}
	// Unmoved: pinned.
	g := newFixture(t, 1, "c1")
	g.p.active["c2"] = true
	g.p.auth = map[string][]byte{"c2": keyB}
	d := g.create(ActionAdminSetAdd, "", `{"connection_id":"c2"}`)
	g.answer("c1", "approve")
	if s := g.status(d.ID); s.Applied == nil || !*s.Applied || !bytes.Equal(g.govKey("c2"), keyB) {
		t.Fatalf("%+v %x", s, g.govKey("c2"))
	}
}

// A threshold raised while an approval is open applies to it, in Answer
// and in applyAdminSet.
func TestAnswerSettlesAtRaisedThreshold(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.p.active["c3"] = true
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	f.m.Threshold = 2
	f.answer("c1", "approve")
	if s := f.status(c.ID); s.Status != StatusPending {
		t.Fatalf("settled at the old threshold: %+v", s)
	}
	f.answer("c2", "approve")
	if s := f.status(c.ID); s.Status != StatusApproved || s.Applied == nil || !*s.Applied {
		t.Fatalf("%+v", s)
	}
	// applyAdminSet on its own.
	g := newFixture(t, 1, "c1", "c2")
	g.p.active["c3"] = true
	d := g.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	r, _ := g.m.load(context.Background(), d.ID)
	r.Approvals = []Approver{{ConnectionID: "c1", Counted: true}}
	g.m.Threshold = 2
	if applied, err := g.m.applyAdminSet(context.Background(), g.m.batch(g.clk.Now()), r, []string{"c1", "c2"}); err != nil || applied {
		t.Fatalf("applied=%v err=%v", applied, err)
	}
}

// An approval stored before Counted existed counted unless it carried a
// changed key; a pending governance approval at the migration is covered
// by TestGovKeyMigrationFromEvidence.
func TestApproverLegacyCounted(t *testing.T) {
	for in, want := range map[string]bool{
		`{"connection_id":"c1","key_changed":false}`:                 true,
		`{"connection_id":"c1","key_changed":true}`:                  false,
		`{"connection_id":"c1","key_changed":true,"counted":true}`:   true,
		`{"connection_id":"c1","key_changed":false,"counted":false}`: false,
	} {
		var a Approver
		if err := json.Unmarshal([]byte(in), &a); err != nil || a.Counted != want {
			t.Errorf("%s: counted %v, %v", in, a.Counted, err)
		}
	}
}

// legacy rewrites approval id as an earlier release stored it: the
// approvals of conns without a counted field.
func (f *fixture) legacy(id string, conns ...string) {
	f.t.Helper()
	ctx := context.Background()
	data, ok, err := f.st.Get(ctx, kindApproval, id)
	if err != nil || !ok {
		f.t.Fatalf("get: %v", err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(data, &v); err != nil {
		f.t.Fatal(err)
	}
	var aps []map[string]any
	for _, c := range conns {
		aps = append(aps, map[string]any{"connection_id": c, "at": f.clk.Now(), "key_changed": false})
	}
	v["approvals"], _ = json.Marshal(aps)
	out, _ := json.Marshal(v)
	if err := f.st.Apply(ctx, []peer.Change{{Kind: kindApproval, ID: id, Data: out}}); err != nil {
		f.t.Fatal(err)
	}
}

// flakyStore fails the writes of approval records while fail is set.
type flakyStore struct {
	peer.Store
	fail bool
}

func (s *flakyStore) Apply(ctx context.Context, ch []peer.Change) error {
	if s.fail {
		for _, c := range ch {
			if c.Kind == kindApproval {
				return errors.New("store down")
			}
		}
	}
	return s.Store.Apply(ctx, ch)
}

// A governance approval stored without Counted never stands, whatever
// happens to the migration; pending and approved-unused ones are ended.
func TestLegacyGovernanceApprovalsNeverStand(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, "c1", "c2")
	f.p.active["c3"] = true
	a := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	f.legacy(a.ID, "c1")
	r, _ := f.m.load(ctx, a.ID)
	if n := r.standing([]string{"c1", "c2"}); n != 0 || r.Approvals[0].Counted || r.Approvals[0].Reason != ReasonLegacy {
		t.Fatalf("standing %d %+v", n, r.Approvals)
	}
	// An approved, unused proposal.create is refused by Consume.
	pl := canonProposal(t, proposalInput())
	p := f.built(ActionProposalCreate, pl)
	f.answer("c1", "approve")
	f.legacy(p.ID, "c1")
	if code := codeOf(f.consume(p.ID, ActionProposalCreate, pl)); code != CodeApprovalNotApproved {
		t.Fatalf("consume: %q", code)
	}
	// A vote.extend already used stays as it is; an unused one is expired.
	ext := canonExtension(t, extensionInput())
	e := f.built(ActionVoteExtend, ext)
	f.answer("c1", "approve")
	f.legacy(e.ID, "c1")
	// The migration: a flaky store fails the expiry; the marker is not
	// written, and the next tick ends them.
	fs := &flakyStore{Store: f.st}
	f.m.Store = fs
	f.p.gov = map[string][]byte{"c1": nil, "c2": nil}
	fs.fail = true
	if err := f.m.Tick(ctx); err == nil {
		t.Fatal("tick did not fail with the store down")
	}
	if _, done, _ := f.st.Get(ctx, kindGovMig, govMigID); done || f.m.govDone {
		t.Fatal("marker written after a failed expiry")
	}
	if len(f.govKey("c1")) == 0 {
		t.Fatal("pins lost") // pinned before the failed expiry
	}
	fs.fail = false
	if err := f.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, done, _ := f.st.Get(ctx, kindGovMig, govMigID); !done || !f.m.govDone {
		t.Fatal("no marker")
	}
	for _, id := range []string{a.ID, p.ID, e.ID} {
		if s := f.status(id); s.Status != StatusExpired || s.Reason != ReasonGovMigrated {
			t.Errorf("%s: %+v", id, s)
		}
	}
	// A restart (a new manager) finds the marker and does nothing more.
	g := &Manager{Peer: f.p, Store: f.st, Pager: f.st, Now: f.clk.Now, Threshold: 1, Log: f.m.Log}
	if err := g.Tick(ctx); err != nil || !g.govDone {
		t.Fatalf("restart: %v", err)
	}
}

// A used approval is not expired by the migration.
func TestMigrationLeavesUsedApprovalsAlone(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, "c1")
	pl := canonProposal(t, proposalInput())
	p := f.built(ActionProposalCreate, pl)
	f.answer("c1", "approve")
	if err := f.consume(p.ID, ActionProposalCreate, pl); err != nil {
		t.Fatal(err)
	}
	f.legacy(p.ID, "c1")
	f.tick()
	if s := f.status(p.ID); s.Status != StatusApproved {
		t.Fatalf("%+v", s)
	}
	if _, done, _ := f.st.Get(ctx, kindGovMig, govMigID); !done {
		t.Fatal("no marker")
	}
}
