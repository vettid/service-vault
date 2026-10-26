package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/tlsid"
	"github.com/vettid/service-vault/sdk/go/servicevault"
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

// fakeApprovals: a1 is pending once, then approved by c1.
type fakeApprovals struct {
	mu      sync.Mutex
	n       int
	req     approval.Request
	badHash bool
}

func (f *fakeApprovals) Create(_ context.Context, r approval.Request) (*approval.Created, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	st := &approval.Status{ID: id, Action: f.req.Action, Status: approval.StatusPending, Threshold: 1, Admins: []string{"c1"}}
	if f.n > 1 {
		st.Status = approval.StatusApproved
		st.Approvals = []approval.Approver{{ConnectionID: "c1", At: exp}}
	}
	return st, nil
}

func (f *fakeApprovals) Remind(_ context.Context, id string) (*approval.Reminder, error) {
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
	s := &api.Server{Keys: [][32]byte{api.HashKey(f.key)}, Email: idx, Invites: f.inv, SignIns: f.si, Approvals: f.apv,
		LookupFloor: time.Millisecond, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
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
	return f
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
	code, out, errOut := f.run(t, "approve", "-action", "vote.open", "-summary", "Open the vote on proposal 7", "-payload", `{"proposal":7}`)
	h, _ := servicevault.ActionHash("vote.open", "Open the vote on proposal 7", []byte(`{"proposal":7}`))
	want := "approval_id: a1\naction_hash: " + h + "\nexpires_at: 2026-10-27T12:10:00Z\naction_hash_check: ok\n" +
		"status: approved\nthreshold: 1\napproved_by: c1 key_changed=false\n"
	if code != exitOK || out != want {
		t.Fatalf("exit %d\n%s\nstderr %s", code, out, errOut)
	}
	// A hash that does not match the request is an error.
	f = newFixture(t)
	f.apv.badHash = true
	if code, _, errOut := f.run(t, "approve", "-action", "vote.open", "-summary", "x"); code != exitError || !strings.Contains(errOut, "does not match") {
		t.Fatalf("exit %d %s", code, errOut)
	}
	// The API's refusal is reported with its code.
	if code, _, errOut := f.run(t, "approve", "-action", "nope", "-summary", "x"); code != exitError || !strings.Contains(errOut, "invalid_action") {
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
		{nil, []string{"approve", "-action", "vote.open"}},
		{nil, []string{"approve", "-action", "vote.open", "-summary", "x", "-payload", "{"}},
		{nil, []string{"remind"}},
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
