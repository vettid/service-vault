package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/tlsid"
	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/service-vault/vote"
)

// randomHex: test keys are made at run time, never written down.
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

var exp = time.Date(2026, 10, 27, 12, 10, 0, 0, time.UTC)

// fakeInvites walks inv1 through waiting, waiting, sas, connected, one
// step per status call.
type fakeInvites struct {
	mu      sync.Mutex
	lastKey *string
	n       int
	final   string
}

func (f *fakeInvites) Create(_ context.Context, k string) (*api.Invitation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastKey = &k
	return &api.Invitation{ID: "inv1", URL: "https://relay.vettid.test/connect#abc", Exp: exp}, nil
}

func (f *fakeInvites) Status(_ context.Context, id string) (*api.InviteStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	switch {
	case f.n <= 2:
		return &api.InviteStatus{ID: id, Status: api.InviteWaiting}, nil
	case f.n == 3:
		return &api.InviteStatus{ID: id, Status: api.InviteSAS, SAS: "123456", ConnectionID: "c1"}, nil
	case f.final == api.InviteConnected:
		return &api.InviteStatus{ID: id, Status: api.InviteConnected, ConnectionID: "c1"}, nil
	}
	return &api.InviteStatus{ID: id, Status: f.final}, nil
}

// fakeSignIns answers pending once, then approved (or denied for a
// sign-in started with deny@example.org).
type fakeSignIns struct {
	mu    sync.Mutex
	deny  string
	n     int
	isDen bool
	last  api.SignInRequest

	unsigned      *api.UnsignedSignIns // StartUnsigned's answer
	unsignedCalls int
}

func (f *fakeSignIns) Start(_ context.Context, r api.SignInRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last, f.isDen = r, r.EmailKey == f.deny
	return "s1", nil
}

func (f *fakeSignIns) Status(_ context.Context, id string) (*api.SignInStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	switch {
	case f.n == 1:
		return &api.SignInStatus{ID: id, Status: api.SignInPending}, nil
	case f.isDen:
		return &api.SignInStatus{ID: id, Status: api.SignInDenied}, nil
	}
	kc := false
	return &api.SignInStatus{ID: id, Status: api.SignInApproved, ConnectionID: "c1", KeyChanged: &kc}, nil
}

func (f *fakeSignIns) StartUnsigned(context.Context, int, int) *api.UnsignedSignIns {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unsignedCalls++
	return f.unsigned
}

// fakeApprovals: a1 is pending once, then approved by c1.
type fakeApprovals struct {
	mu          sync.Mutex
	n           int
	req         approval.Request
	badHash     bool
	wrongTarget bool
	noChangeAt  bool // admin.repin: the key change time is not recorded
	forced      []string
}

func (f *fakeApprovals) Create(_ context.Context, r approval.Request) (*approval.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sum, built, err := ballot.SummaryFor(r.Action, r.Payload, "T"); built {
		if err != nil || r.Summary != "" {
			return nil, &approval.Error{Code: approval.CodeInvalidPayload}
		}
		r.Summary = sum
	}
	if r.Action == approval.ActionAdminRepin {
		// As the service does: it builds the summary and fills in new_key.
		if r.Summary != "" {
			return nil, &approval.Error{Code: approval.CodeInvalidSummary}
		}
		var p struct {
			ConnectionID string `json:"connection_id"`
			NewKey       string `json:"new_key"`
		}
		_ = json.Unmarshal(r.Payload, &p)
		if p.NewKey == "" {
			p.NewKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		}
		r.Payload, _ = servicevault.CanonicalJSON([]byte(`{"connection_id":"` + p.ConnectionID + `","new_key":"` + p.NewKey + `"}`))
		at := "key changed 2026-11-02 11:42 UTC"
		if f.noChangeAt {
			at = "key changed time not recorded"
		}
		r.Summary = `name given "Ann", new key 9a1f bb7d 0123 4567, ` + at + `, connection ` + p.ConnectionID
		if f.wrongTarget {
			r.Summary = `"Ann", connection c9`
		}
	}
	if strings.HasPrefix(r.Action, "admin_set.") {
		if r.Summary != "" {
			return nil, &approval.Error{Code: approval.CodeInvalidSummary}
		}
		var p struct {
			ConnectionID string `json:"connection_id"`
		}
		_ = json.Unmarshal(r.Payload, &p)
		r.Summary = `name given "Ann", connected 2026-11-02, key 9a1f bb7d 0123 4567, connection ` + p.ConnectionID
		if f.wrongTarget {
			r.Summary = `"Ann", connection c9`
		}
	}
	f.req = r
	if r.Action == "nope" {
		return nil, &approval.Error{Code: approval.CodeInvalidAction}
	}
	h, err := servicevault.ActionHash(r.Action, r.Summary, r.Payload)
	if err != nil {
		return nil, &approval.Error{Code: approval.CodeInvalidPayload}
	}
	if f.badHash {
		h = strings.Repeat("0", 64)
	}
	return &approval.Created{ID: "a1", ActionHash: h, Status: approval.StatusPending, ExpiresAt: exp}, nil
}

func (f *fakeApprovals) Status(_ context.Context, id string) (*approval.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id != "a1" {
		return nil, approval.ErrNotFound
	}
	f.n++
	st := &approval.Status{ID: id, Action: f.req.Action, Summary: f.req.Summary, Payload: f.req.Payload, Status: approval.StatusPending, Threshold: 1, Admins: []string{"c1"}, RemindNeeded: []string{"c1"}, RemindAfter: &exp}
	if f.n > 1 {
		st.RemindNeeded = []string{}
		st.Status = approval.StatusApproved
		st.Approvals = []approval.Approver{{ConnectionID: "c1", At: exp, Counted: true}}
	}
	return st, nil
}

func (f *fakeApprovals) Remind(_ context.Context, id string, force ...string) (*approval.Reminder, error) {
	f.forced = force // read by the test below
	if len(force) > 0 && id == "a1" {
		switch force[0] {
		case "gone":
			return nil, &approval.Error{Code: approval.CodeNotAdmin}
		case "done":
			return nil, &approval.Error{Code: approval.CodeAnswered}
		case "spent":
			return nil, &approval.Error{Code: approval.CodeAskBudget}
		}
		return &approval.Reminder{ID: id, Reminded: force}, nil
	}
	if id == "idle" {
		return nil, &approval.Error{Code: approval.CodeNothingToRemind}
	}
	if id != "a1" {
		return nil, approval.ErrNotFound
	}
	return &approval.Reminder{ID: id, Reminded: []string{"c2"}}, nil
}

func (f *fakeApprovals) Admins(context.Context) (*approval.Admins, error) {
	return &approval.Admins{Admins: []string{"c1", "c2"}, Threshold: 1}, nil
}

func (f *fakeApprovals) Audit(_ context.Context, since string, limit int) (*approval.AuditPage, error) {
	all := []approval.AuditEntry{{ID: "e1", At: exp, Type: approval.AuditAdminSetChanged, Admins: []string{"c1"}, Added: "c1",
		Reason: approval.ChangeBootstrap}, {ID: "e2", At: exp, Type: approval.AuditRequested, ApprovalID: "a1"}}
	if since == "e1" {
		all = all[1:]
	}
	p := &approval.AuditPage{Entries: all}
	if limit < len(all) {
		p.Entries, p.Next = all[:limit], all[limit-1].ID
	}
	return p, nil
}

type fixture struct {
	inv  *fakeInvites
	si   *fakeSignIns
	apv  *fakeApprovals
	idx  *connect.EmailIndex
	env  map[string]string
	key  string
	pin  string
	addr string
}

// newFixture serves the private API (internal/api) over TLS with a
// tlsid key, in process, behind the fakes.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	idx, err := connect.NewEmailIndex([]byte(randomHex(t, 32)))
	if err != nil {
		t.Fatal(err)
	}
	deny, _ := idx.Key("deny@example.org")
	f := &fixture{inv: &fakeInvites{final: api.InviteConnected}, si: &fakeSignIns{deny: deny}, apv: &fakeApprovals{}, idx: idx,
		key: randomHex(t, 24)}
	f.serve(t, nil)
	return f
}

// serve (re)starts the API for the fixture, with change applied to the
// server first.
func (f *fixture) serve(t *testing.T, change func(*api.Server)) {
	t.Helper()
	s := &api.Server{TestSignIns: true, Keys: [][32]byte{api.HashKey(f.key)}, Email: f.idx, Invites: f.inv, SignIns: f.si, Approvals: f.apv,
		LookupFloor: time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if change != nil {
		change(s)
	}
	der, err := tlsid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, pin, err := tlsid.Certificate(der, []string{"service-vault.test"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = tlsid.ServerConfig(cert)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	f.pin, f.addr = pin, srv.URL
	f.env = map[string]string{"SVCTL_URL": srv.URL, "SVCTL_API_KEY": f.key, "SVCTL_PIN": pin}
}

// run runs svctl with the fixture's environment and a short poll.
func (f *fixture) run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var o, e bytes.Buffer
	code = run(context.Background(), append([]string{"-poll", "5ms"}, args...), func(k string) string { return f.env[k] }, &o, &e)
	if strings.Contains(o.String()+e.String(), f.key) {
		t.Fatal("svctl printed the API key")
	}
	return code, o.String(), e.String()
}

// withoutQR drops the QR code's lines (those of block characters and
// spaces).
func withoutQR(s string) string {
	var keep []string
	for _, l := range strings.SplitAfter(s, "\n") {
		if l != "" && strings.Trim(l, " █▀▄\n") == "" {
			continue
		}
		keep = append(keep, l)
	}
	return strings.Join(keep, "")
}

func TestInvite(t *testing.T) {
	f := newFixture(t)
	code, out, errOut := f.run(t, "invite", "-email", " Member@Example.org ", "-verified")
	want := `invite_id: inv1
expires_at: 2026-10-27T12:10:00Z
url: https://relay.vettid.test/connect#abc
status: waiting
status: sas
sas: 123456
connection_id: c1
status: connected
connection_id: c1
`
	if code != exitOK || withoutQR(out) != want {
		t.Fatalf("exit %d\n%s\nstderr %s", code, out, errOut)
	}
	if !strings.Contains(out, "█") {
		t.Fatal("no QR code")
	}
	k, _ := f.idx.Key("member@example.org")
	if f.inv.lastKey == nil || *f.inv.lastKey != k {
		t.Fatal("a verified invitation did not carry the email")
	}
}

func TestInviteUnverifiedDeclined(t *testing.T) {
	f := newFixture(t)
	f.inv.final = api.InviteDeclined
	code, out, _ := f.run(t, "invite", "-email", "member@example.org", "-no-qr")
	if code != exitOutcome || !strings.HasSuffix(out, "status: declined\n") || strings.Contains(out, "█") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if f.inv.lastKey == nil || *f.inv.lastKey != "" {
		t.Fatal("an unverified invitation carried the email")
	}
}

func TestInviteNoWait(t *testing.T) {
	f := newFixture(t)
	code, out, _ := f.run(t, "invite", "-email", "member@example.org", "-wait", "0", "-no-qr")
	if code != exitOK || strings.Contains(out, "status:") || f.inv.n != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestSignIn(t *testing.T) {
	f := newFixture(t)
	code, out, _ := f.run(t, "signin", "-email", "member@example.org", "-source", "203.0.113.7")
	lines := strings.Split(out, "\n")
	if code != exitOK || len(lines) != 6 || lines[0] != "signin_id: s1" || !strings.HasPrefix(lines[1], "match_code: ") ||
		strings.Join(lines[2:], "\n") != "status: approved\nconnection_id: c1\nkey_changed: false\n" {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if f.si.last.SourceKey == "" {
		t.Fatal("source not sent")
	}
	code, out, _ = newFixture(t).run(t, "signin", "-email", "deny@example.org")
	if code != exitOutcome || !strings.HasSuffix(out, "status: denied\n") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestApprove(t *testing.T) {
	f := newFixture(t)
	code, out, errOut := f.run(t, "approve", "-action", "contract_template.change", "-summary", "Open the vote on proposal 7", "-payload", `{"proposal":7}`)
	h, _ := servicevault.ActionHash("contract_template.change", "Open the vote on proposal 7", []byte(`{"proposal":7}`))
	want := "approval_id: a1\naction_hash: " + h + "\nexpires_at: 2026-10-27T12:10:00Z\naction_hash_check: ok\n" + "remind needed: c1 (svctl remind a1)\n" +
		"status: approved\nthreshold: 1\napproved_by: c1 key_changed=false\n"
	if code != exitOK || out != want {
		t.Fatalf("exit %d\n%s\nstderr %s", code, out, errOut)
	}
	// The summary of proposal.create and vote.extend is the service's:
	// none is given.
	if code, _, errOut := newFixture(t).run(t, "approve", "-action", "proposal.create", "-summary", "x", "-payload", "{}"); code != exitUsage || !strings.Contains(errOut, "takes no -summary") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	// admin_set.* takes no summary either: the service names the target.
	if code, _, errOut := newFixture(t).run(t, "approve", "-action", "admin_set.add", "-summary", "x", "-payload", `{"connection_id":"c2"}`); code != exitUsage || !strings.Contains(errOut, "takes no -summary") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	if code, out, errOut := newFixture(t).run(t, "approve", "-action", "admin_set.add", "-payload", `{"connection_id":"c2"}`); code != exitOK || !strings.Contains(out, `summary: name given "Ann", connected 2026-11-02, key 9a1f bb7d 0123 4567, connection c2`) || !strings.Contains(out, "action_hash_check: ok") {
		t.Fatalf("exit %d %s %s", code, out, errOut)
	}
	// admin.repin: the service builds the summary and fills in new_key; the
	// hash is checked against the payload it returns.
	for _, noAt := range []bool{false, true} {
		rf := newFixture(t)
		rf.apv.noChangeAt = noAt
		code, out, errOut := rf.run(t, "approve", "-action", "admin.repin", "-payload", `{"connection_id":"c2"}`)
		want := "key changed 2026-11-02 11:42 UTC, connection c2"
		if noAt {
			want = "key changed time not recorded, connection c2"
		}
		if code != exitOK || !strings.Contains(out, "summary: name given \"Ann\", new key 9a1f bb7d 0123 4567, "+want) || !strings.Contains(out, "action_hash_check: ok") {
			t.Fatalf("repin (no change time: %v): exit %d %s %s", noAt, code, out, errOut)
		}
	}
	if code, out, errOut := newFixture(t).run(t, "approve", "-action", "admin.repin", "-payload", `{"connection_id":"c2","new_key":"`+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))+`"}`); code != exitOK || !strings.Contains(out, "action_hash_check: ok") {
		t.Fatalf("repin with new_key: exit %d %s %s", code, out, errOut)
	}
	if code, _, errOut := newFixture(t).run(t, "approve", "-action", "admin.repin", "-summary", "x", "-payload", `{"connection_id":"c2"}`); code != exitUsage || !strings.Contains(errOut, "takes no -summary") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	wt := newFixture(t)
	wt.apv.wrongTarget = true
	if code, _, errOut := wt.run(t, "approve", "-action", "admin.repin", "-payload", `{"connection_id":"c2"}`); code != exitError || !strings.Contains(errOut, "does not name the connection") {
		t.Fatalf("repin wrong target: exit %d %s", code, errOut)
	}
	wt = newFixture(t)
	wt.apv.wrongTarget = true
	if code, _, errOut := wt.run(t, "approve", "-action", "admin_set.remove", "-payload", `{"connection_id":"c2"}`); code != exitError || !strings.Contains(errOut, "does not name the connection") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	// A hash that does not match the request is an error.
	f = newFixture(t)
	f.apv.badHash = true
	if code, _, errOut := f.run(t, "approve", "-action", "contract_template.change", "-summary", "x"); code != exitError || !strings.Contains(errOut, "does not match") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	// The API's refusal is reported with its code.
	if code, _, errOut := f.run(t, "approve", "-action", "nope", "-summary", "x"); code != exitError || !strings.Contains(errOut, "invalid_action") {
		t.Fatalf("exit %d %s", code, errOut)
	}
}

func TestApprovalStatus(t *testing.T) {
	f := newFixture(t)
	code, out, errOut := f.run(t, "approval", "a1")
	if want := "status: pending\nthreshold: 1\nremind needed: c1 (svctl remind a1)\n"; code != exitOK || out != want {
		t.Fatalf("exit %d\n%s\nstderr %s", code, out, errOut)
	}
	// Before remind_after a reminder would answer too_soon.
	saved := now
	now = func() time.Time { return exp.Add(-time.Minute) }
	code, out, _ = newFixture(t).run(t, "approval", "a1")
	now = saved
	if want := "status: pending\nthreshold: 1\nremind needed: c1 (svctl remind a1 after 12:10:00Z)\n"; code != exitOK || out != want {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// Settled: no remind line.
	code, out, _ = f.run(t, "approval", "a1")
	if want := "status: approved\nthreshold: 1\napproved_by: c1 key_changed=false\n"; code != exitOK || out != want {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if code, _, errOut := f.run(t, "approval", "nope"); code != exitError || !strings.Contains(errOut, "not_found") {
		t.Fatalf("exit %d %s", code, errOut)
	}
}

func TestRemindAdminsAuditHealth(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"remind", "a1"}, "approval_id: a1\nreminded: c2\n"},
		{[]string{"remind", "idle"}, "nothing to remind: every admin who has not answered still holds a live challenge\n"},
		{[]string{"admins"}, "threshold: 1\nadmin: c1\nadmin: c2\n"},
		{[]string{"health"}, "ok\n"},
		{[]string{"audit", "-since", "e1"}, `{"id":"e2","at":"2026-10-27T12:10:00Z","type":"approval.requested","approval_id":"a1"}` + "\n"},
	} {
		if code, out, errOut := f.run(t, c.args...); code != exitOK || out != c.want {
			t.Errorf("%v: exit %d\n%s\nstderr %s", c.args, code, out, errOut)
		}
	}
	code, out, errOut := f.run(t, "audit", "-limit", "1")
	if code != exitOK || strings.Count(out, "\n") != 1 || !strings.Contains(out, `"type":"admin_set.changed"`) ||
		errOut != "more: svctl audit -since e1\n" {
		t.Fatalf("exit %d\n%s\nstderr %s", code, out, errOut)
	}
	if code, _, errOut := f.run(t, "remind", "nope"); code != exitError || !strings.Contains(errOut, "not_found") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	// A forced re-send names the admins; the refusals exit 1, a bad flag 2.
	if code, out, errOut := f.run(t, "remind", "-force", "c2, c3", "a1"); code != exitOK || out != "approval_id: a1\nreminded: c2\nreminded: c3\n" ||
		strings.Join(f.apv.forced, ",") != "c2,c3" {
		t.Fatalf("forced: exit %d\n%s\nstderr %s %v", code, out, errOut, f.apv.forced)
	}
	if code, _, errOut := f.run(t, "remind", "-force", "gone", "a1"); code != exitError || !strings.Contains(errOut, "not_admin") {
		t.Fatalf("not an admin: exit %d %s", code, errOut)
	}
	if code, _, errOut := f.run(t, "remind", "-force", "done", "a1"); code != exitError || !strings.Contains(errOut, "answered") {
		t.Fatalf("answered: exit %d %s", code, errOut)
	}
	if code, _, errOut := f.run(t, "remind", "-force", "spent", "a1"); code != exitError || !strings.Contains(errOut, "ask_budget") ||
		!strings.Contains(errOut, "5 approval challenges still counting") {
		t.Fatalf("ask budget: exit %d %s", code, errOut)
	}
	if code, _, _ := f.run(t, "remind", "-force", ",", "a1"); code != exitUsage {
		t.Fatalf("empty -force: exit %d", code)
	}
}

func TestConfig(t *testing.T) {
	f := newFixture(t)
	// A wrong pin: refused, and the error does not print the key.
	f.env["SVCTL_PIN"] = "sha256/" + strings.Repeat("A", 43)
	if code, _, errOut := f.run(t, "health"); code != exitError || !strings.Contains(errOut, "pin") {
		t.Fatalf("wrong pin: exit %d %s", code, errOut)
	}
	// The pin from SSM.
	var asked [3]string
	orig := pinFromSSM
	t.Cleanup(func() { pinFromSSM = orig })
	pinFromSSM = func(_ context.Context, name, profile, region string) (string, error) {
		asked = [3]string{name, profile, region}
		return f.pin, nil
	}
	delete(f.env, "SVCTL_PIN")
	if code, _, errOut := f.run(t, "-pin-param", "/sv/pin", "-profile", "staging", "health"); code != exitOK ||
		asked != [3]string{"/sv/pin", "staging", ""} {
		t.Fatalf("pin param: exit %d %s %v", code, errOut, asked)
	}
	// A wrong API key.
	f.env["SVCTL_PIN"], f.env["SVCTL_API_KEY"] = f.pin, randomHex(t, 24)
	if code, _, errOut := f.run(t, "admins"); code != exitError || !strings.Contains(errOut, "unauthorized") {
		t.Fatalf("wrong key: exit %d %s", code, errOut)
	}
	f.env["SVCTL_API_KEY"] = f.key
	for _, c := range []struct {
		env  map[string]string
		args []string
	}{
		{nil, nil},
		{nil, []string{"nope"}},
		{map[string]string{"SVCTL_URL": ""}, []string{"health"}},
		{map[string]string{"SVCTL_API_KEY": ""}, []string{"health"}},
		{map[string]string{"SVCTL_PIN": ""}, []string{"health"}},
		{nil, []string{"-pin-param", "/p", "health"}},
		{nil, []string{"-api-key", "x", "health"}},
		{nil, []string{"invite"}},
		{nil, []string{"signin"}},
		{nil, []string{"approve", "-action", "contract_template.change"}},
		{nil, []string{"approve", "-action", "contract_template.change", "-summary", "x", "-payload", "{"}},
		{nil, []string{"remind"}},
		{nil, []string{"approval"}},
		{nil, []string{"admins", "extra"}},
		{nil, []string{"audit", "-limit", "0"}},
	} {
		saved := map[string]string{}
		for k, v := range c.env {
			saved[k], f.env[k] = f.env[k], v
		}
		if code, _, _ := f.run(t, c.args...); code != exitUsage {
			t.Errorf("%v %v: exit %d", c.env, c.args, code)
		}
		for k, v := range saved {
			f.env[k] = v
		}
	}
}

// The QR code has the code's size plus the quiet zone in columns, and
// half as many lines.
func TestRenderQR(t *testing.T) {
	q, err := renderQR("https://relay.vettid.test/connect#abc", false)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(q, "\n"), "\n")
	w := len([]rune(lines[0]))
	if w < 21+2*qrQuiet || len(lines) != (w+1)/2 {
		t.Fatalf("%d x %d", w, len(lines))
	}
	for _, l := range lines {
		if len([]rune(l)) != w {
			t.Fatal("ragged QR code")
		}
	}
	// The quiet zone is light: the first line is all upper blocks or
	// full blocks; inverted, it is blank.
	if strings.Trim(lines[0], "█") != "" {
		t.Fatalf("quiet zone %q", lines[0])
	}
	inv, _ := renderQR("https://relay.vettid.test/connect#abc", true)
	if strings.Trim(strings.SplitN(inv, "\n", 2)[0], " ") != "" {
		t.Fatal("inverted quiet zone")
	}
}

// proposalFile is a proposal input a file can hold; the extension file
// is an extension of it.
const (
	proposalFile  = `{"title":"T","text":"","choices":[{"label":"Yes"},{"label":"No"}],"quorum":{"text":"","min_ballots":1},"binding":true,"opens_at":1793520000,"closes_at":1793606400,"outage_rule":""}`
	extensionFile = `{"closes_at":1793613600,"outage":{"from":1793600000,"to":1793605400,"source":"https://status.vettid.org/"}}`
)

// fakeProposals answers the proposal routes: the first create is kept
// but not published, and a close before the relay is caught up is
// collecting.
type fakeProposals struct {
	approvals []string // the approval ids the calls carried
	created   int
	caught    bool
	unsigned  int
}

func (p *fakeProposals) Create(_ context.Context, approvalID string, in ballot.ProposalInput) (*ballot.Created, error) {
	p.approvals = append(p.approvals, approvalID)
	if approvalID != "a1" {
		return nil, &approval.Error{Code: approval.CodeApprovalNotApproved}
	}
	p.created++
	if in.Title == "" {
		return nil, &ballot.ErrInput{Err: errors.New("title")}
	}
	if p.created == 1 {
		return nil, &ballot.ErrNotPublished{ProposalID: "01P", Err: errors.New("site down")}
	}
	return &ballot.Created{ProposalID: "01Q", Eligible: 3, Unsigned: p.unsigned}, nil
}

func (p *fakeProposals) Status(_ context.Context, id string) (*ballot.ProposalStatus, error) {
	if id == "01JBQZ0000000000000000000A" {
		return &ballot.ProposalStatus{ProposalID: id, Proposal: `{"title":"T"}`}, nil
	}
	if id != "01P" {
		return nil, nil
	}
	return &ballot.ProposalStatus{ProposalID: id}, nil
}

func (p *fakeProposals) Close(context.Context, string) (*ballot.ResultsSummary, error) {
	if !p.caught {
		return nil, ballot.ErrNotCaught
	}
	return &ballot.ResultsSummary{ProposalID: "01P"}, nil
}

func (p *fakeProposals) Results(context.Context, string) (*ballot.PublishedResults, error) {
	return nil, nil
}

func (p *fakeProposals) Extend(_ context.Context, id, approvalID string, in ballot.ExtensionInput) (*vote.Extension, error) {
	p.approvals = append(p.approvals, approvalID)
	if approvalID != "a1" {
		return nil, &approval.Error{Code: approval.CodeApprovalNotApproved}
	}
	return &vote.Extension{V: 1, ProposalID: id, N: 1, ClosesAt: in.ClosesAt, Outage: in.Outage}, nil
}

func (p *fakeProposals) Publish(context.Context, string) (int, error) { return 3, nil }

// The vote commands pass the API's answers through, and a proposal kept
// but not published names itself for the retry.
func TestProposalCommands(t *testing.T) {
	f := newFixture(t)
	fp := &fakeProposals{}
	f.serve(t, func(s *api.Server) {
		s.Proposals = fp
		s.AnchorKey = &api.AnchorKey{Key: []byte{1}, Cert: []byte{2}, IK: []byte{3}, Sigstore: "staging"}
	})
	in := filepath.Join(t.TempDir(), "proposal.json")
	if err := os.WriteFile(in, []byte(proposalFile), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := f.run(t, "proposal", "create", "-in", in)
	if code != exitError || !strings.Contains(errOut, "svctl proposal publish 01P") || !strings.Contains(errOut, "not_published") {
		t.Fatalf("create, not published: exit %d %s", code, errOut)
	}
	if code, out, errOut := f.run(t, "proposal", "create", "-in", in); code != exitOK || !strings.Contains(out, `"proposal_id": "01Q"`) {
		t.Fatalf("create: exit %d %s %s", code, out, errOut)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"anchor-key"}, `"sigstore": "staging"`},
		{[]string{"proposal", "status", "01P"}, `"proposal_id": "01P"`},
		{[]string{"proposal", "publish", "01P"}, `3`},
	} {
		if code, out, errOut := f.run(t, c.args...); code != exitOK || !strings.Contains(out, c.want) {
			t.Errorf("%v: exit %d\n%s\nstderr %s", c.args, code, out, errOut)
		}
	}
	if code, _, errOut := f.run(t, "proposal", "close", "01P"); code != exitError || !strings.Contains(errOut, "collecting") {
		t.Fatalf("close before caught up: exit %d %s", code, errOut)
	}
	fp.caught = true
	if code, out, _ := f.run(t, "proposal", "close", "01P"); code != exitOK || !strings.Contains(out, "01P") {
		t.Fatalf("close: exit %d %s", code, out)
	}
	for _, args := range [][]string{{"proposal"}, {"proposal", "create"}, {"proposal", "status"}, {"proposal", "nope", "x"}} {
		if code, _, _ := f.run(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want usage", args, code)
		}
	}
	if fp.created != 2 {
		t.Fatalf("%d creates, want 2: a failed create isn't retried", fp.created)
	}
}

// A proposal created with unsigned connections warns on stderr, and not
// otherwise; the exit code and the answer are unchanged.
func TestProposalCreateWarnsUnsigned(t *testing.T) {
	f := newFixture(t)
	fp := &fakeProposals{created: 1} // the first create would be kept, not published
	f.serve(t, func(s *api.Server) { s.Proposals = fp })
	in := filepath.Join(t.TempDir(), "proposal.json")
	if err := os.WriteFile(in, []byte(proposalFile), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := f.run(t, "proposal", "create", "-in", in)
	if code != exitOK || errOut != "" || !strings.Contains(out, `"unsigned": 0`) {
		t.Fatalf("none unsigned: exit %d %q %q", code, out, errOut)
	}
	fp.unsigned = 2
	code, out, errOut = f.run(t, "proposal", "create", "-in", in)
	want := "warning: 2 eligible connection(s) have never signed in; their vaults will refuse to vote until they do: ask them to sign in to the service once (on a test deployment: svctl signin -unsigned)\n"
	if code != exitOK || errOut != want || !strings.Contains(out, `"unsigned": 2`) {
		t.Fatalf("unsigned: exit %d %q %q", code, out, errOut)
	}
}

// signin -unsigned prints each connection's match code or why it was
// skipped, and takes no email.
func TestSignInUnsigned(t *testing.T) {
	f := newFixture(t)
	f.si.unsigned = &api.UnsignedSignIns{SignIns: []api.UnsignedSignIn{
		{ConnectionID: "c1", SignInID: "s1", MatchCode: "42"},
		{ConnectionID: "c2", Skipped: api.SkipPending},
		{ConnectionID: "c3", MatchCode: "17", Skipped: api.SkipNotRecorded},
	}, More: 7}
	code, out, errOut := f.run(t, "signin", "-unsigned")
	want := "connection_id: c1\nsignin_id: s1\nmatch_code: 42\nconnection_id: c2\nskipped: pending\n" +
		"connection_id: c3\nmatch_code: 17\nskipped: not_recorded\nmore: 7 (run again)\n"
	if code != exitOK || out != want || errOut != "" {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// A run that stopped early prints what it did and exits 1.
	f.si.unsigned = &api.UnsignedSignIns{SignIns: []api.UnsignedSignIn{{ConnectionID: "c1", SignInID: "s1", MatchCode: "42"}},
		More: 2, Stopped: api.StoppedTimeout}
	code, out, errOut = f.run(t, "signin", "-unsigned")
	if code != exitError || out != "connection_id: c1\nsignin_id: s1\nmatch_code: 42\nmore: 2 (run again)\nstopped: timeout\n" ||
		!strings.Contains(errOut, "stopped early (timeout)") {
		t.Fatalf("stopped: exit %d\n%s\n%s", code, out, errOut)
	}
	for _, extra := range [][]string{{"-email", "a@example.org"}, {"-source", "x"}, {"-wait", "1m"}} {
		if code, _, _ := f.run(t, append([]string{"signin", "-unsigned"}, extra...)...); code != exitUsage {
			t.Fatalf("-unsigned with %v: exit %d", extra, code)
		}
	}
	if f.si.unsignedCalls != 2 {
		t.Fatalf("%d calls", f.si.unsignedCalls)
	}
}

// With SV_TEST_SIGNINS off, signin -unsigned says it is for testing and
// exits 1.
func TestSignInUnsignedTestOnly(t *testing.T) {
	f := newFixture(t)
	f.serve(t, func(s *api.Server) { s.TestSignIns = false })
	code, out, errOut := f.run(t, "signin", "-unsigned")
	want := "svctl signin: signin -unsigned is for testing only: this service vault has SV_TEST_SIGNINS off\n"
	if code != exitError || out != "" || errOut != want {
		t.Fatalf("exit %d %q %q", code, out, errOut)
	}
	if f.si.unsignedCalls != 0 {
		t.Fatal("a run was started")
	}
}

// Creating or extending a proposal first has the admins approve exactly
// its input, then calls with the approval.
func TestProposalNeedsApproval(t *testing.T) {
	f := newFixture(t)
	fp := &fakeProposals{created: 1}
	f.serve(t, func(s *api.Server) { s.Proposals = fp })
	dir := t.TempDir()
	in := filepath.Join(dir, "proposal.json")
	ext := filepath.Join(dir, "extension.json")
	for p, c := range map[string]string{in: proposalFile, ext: extensionFile} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errOut := f.run(t, "proposal", "create", "-in", in)
	if code != exitOK || !strings.Contains(out, "approval_id: a1\n") || !strings.Contains(out, "summary: BINDING, opens 2026-11-01") ||
		!strings.Contains(out, "action_hash_check: ok") || !strings.Contains(out, `"proposal_id": "01Q"`) || strings.Join(fp.approvals, ",") != "a1" {
		t.Fatalf("create: exit %d\n%s\n%s", code, out, errOut)
	}
	if f.apv.req.Action != "proposal.create" || f.apv.req.Summary == "" {
		t.Fatalf("approval request %+v", f.apv.req)
	}
	// The payload is the input in canonical full form.
	want, _ := ballot.CanonicalProposal(ballot.ProposalInput{Title: "T", Choices: []ballot.ChoiceInput{{Label: "Yes"}, {Label: "No"}},
		Quorum: vote.Quorum{MinBallots: 1}, Binding: true, OpensAt: 1793520000, ClosesAt: 1793606400})
	if string(f.apv.req.Payload) != string(want) {
		t.Fatalf("payload %s", f.apv.req.Payload)
	}
	// Not approved within -wait: nothing is called.
	n := len(fp.approvals)
	f.apv.n = -100
	if code, _, errOut := f.run(t, "proposal", "create", "-in", in, "-wait", "0"); code != exitError || !strings.Contains(errOut, "pending") || len(fp.approvals) != n {
		t.Fatalf("pending: exit %d %s, %d calls", code, errOut, len(fp.approvals))
	}
	f.apv.n = 0
	// An input with a name the proposal doesn't have is refused here.
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"title":"T","extra":1}`), 0o600)
	if code, _, _ := f.run(t, "proposal", "create", "-in", bad); code != exitUsage || len(fp.approvals) != n {
		t.Fatalf("unknown name: exit %d", code)
	}
	// Extend.
	code, out, errOut = f.run(t, "proposal", "extend", "01JBQZ0000000000000000000A", "-in", ext)
	if code != exitOK || !strings.Contains(out, "summary: \"T\" (01JBQZ0000000000000000000A)") || !strings.Contains(out, "approval_id: a1") || !strings.Contains(out, `"closes_at": 1793613600`) {
		t.Fatalf("extend: exit %d\n%s\n%s", code, out, errOut)
	}
	if f.apv.req.Action != "vote.extend" {
		t.Fatalf("approval request %+v", f.apv.req)
	}
	// An existing approval of another action is not used.
	if code, _, errOut := f.run(t, "proposal", "create", "-in", in, "-approval", "a1"); code != exitError || !strings.Contains(errOut, "not an approved proposal.create") {
		t.Fatalf("exit %d %s", code, errOut)
	}
}
