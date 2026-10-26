package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/connect"
)

type fakeInvites struct{ lastKey string }

func (f *fakeInvites) Status(_ context.Context, id string) (*InviteStatus, error) {
	if id != "inv1" {
		return nil, ErrNotFound
	}
	return &InviteStatus{ID: id, Status: InviteSAS, SAS: "123456", ConnectionID: "c1"}, nil
}

func (f *fakeInvites) Create(_ context.Context, emailKey string) (*Invitation, error) {
	f.lastKey = emailKey
	return &Invitation{ID: "inv1", URL: "https://relay.vettid.test/connect#x", Exp: time.Unix(1_800_000_600, 0).UTC()}, nil
}

// fakeSignIns knows one email key; unknown keys get an id that stays
// pending, as the real one does.
type fakeSignIns struct {
	mu      sync.Mutex
	known   string
	started map[string]string // id -> email key
	last    SignInRequest
}

func (f *fakeSignIns) Start(_ context.Context, req SignInRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.started == nil {
		f.started = map[string]string{}
	}
	f.last = req
	emailKey := req.EmailKey
	id := "s" + string(rune('0'+len(f.started)))
	f.started[id] = emailKey
	if emailKey == f.known {
		time.Sleep(20 * time.Millisecond) // the known path does more work
	}
	return id, nil
}

func (f *fakeSignIns) Status(_ context.Context, id string) (*SignInStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.started[id]
	if !ok {
		return nil, ErrNotFound
	}
	if k == f.known {
		kc := true
		return &SignInStatus{ID: id, Status: SignInApproved, ConnectionID: "conn1", KeyChanged: &kc}, nil
	}
	return &SignInStatus{ID: id, Status: SignInPending}, nil
}

const apiKey = "test-api-key-not-a-secret-0123456789"

func newServer(t *testing.T) (*Server, *fakeInvites, *fakeSignIns) {
	t.Helper()
	idx, err := connect.NewEmailIndex(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	known, _ := idx.Key("member@example.org")
	inv, si := &fakeInvites{}, &fakeSignIns{known: known}
	return &Server{Keys: [][32]byte{HashKey("other-key"), HashKey(apiKey)}, Email: idx,
		Invites: inv, SignIns: si, LookupFloor: 60 * time.Millisecond}, inv, si
}

func do(t *testing.T, h http.Handler, method, path, key, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec, m
}

func TestAuth(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	for _, key := range []string{"", "wrong", apiKey + "x"} {
		if rec, _ := do(t, h, "POST", "/v1/invites", key, `{"email":"a@example.org"}`); rec.Code != 401 {
			t.Errorf("key %q: %d", key, rec.Code)
		}
	}
	if rec, _ := do(t, h, "GET", "/health", "", ""); rec.Code != 200 {
		t.Errorf("health: %d", rec.Code)
	}
	empty := &Server{Email: s.Email, Invites: s.Invites, SignIns: s.SignIns}
	if rec, _ := do(t, empty.Handler(), "POST", "/v1/invites", "", `{"email":"a@example.org"}`); rec.Code != 401 {
		t.Errorf("no keys configured: %d", rec.Code)
	}
}

func TestCreateInvite(t *testing.T) {
	s, inv, _ := newServer(t)
	h := s.Handler()
	rec, m := do(t, h, "POST", "/v1/invites", apiKey, `{"email":" Member@Example.org ","email_verified":true}`)
	if rec.Code != 201 || m["invite_id"] != "inv1" || m["url"] != "https://relay.vettid.test/connect#x" {
		t.Fatalf("%d %v", rec.Code, m)
	}
	want, _ := s.Email.Key("member@example.org")
	if inv.lastKey != want {
		t.Fatal("invite not bound to the email's index key")
	}
	for _, body := range []string{`{"email":"nope","email_verified":true}`, `{"email":"nope","email_verified":false}`,
		`{"email":"a@example.org","email_verified":true,"x":1}`, `not json`, `{"email":"a@example.org","email_verified":true}{}`,
		`{"email":"a@example.org","email_verified":"true"}`, `{"email":"a@example.org","email_verified":1}`} {
		if rec, _ := do(t, h, "POST", "/v1/invites", apiKey, body); rec.Code != 400 {
			t.Errorf("body %s: %d", body, rec.Code)
		}
	}
}

// email_verified is required: missing (or null) is a bad request, so
// that every application decides.
func TestCreateInviteVerifiedRequired(t *testing.T) {
	s, inv, _ := newServer(t)
	h := s.Handler()
	for _, body := range []string{`{"email":"a@example.org"}`, `{"email":"a@example.org","email_verified":null}`} {
		inv.lastKey = "untouched"
		rec, m := do(t, h, "POST", "/v1/invites", apiKey, body)
		if rec.Code != 400 || m["error"] != "bad_request" || inv.lastKey != "untouched" {
			t.Errorf("body %s: %d %v", body, rec.Code, m)
		}
	}
}

// An unverified email is not carried by the invitation at all.
func TestCreateInviteUnverified(t *testing.T) {
	s, inv, _ := newServer(t)
	inv.lastKey = "untouched"
	rec, m := do(t, s.Handler(), "POST", "/v1/invites", apiKey, `{"email":"member@example.org","email_verified":false}`)
	if rec.Code != 201 || m["invite_id"] != "inv1" || inv.lastKey != "" {
		t.Fatalf("%d %v key %q", rec.Code, m, inv.lastKey)
	}
}

func TestSignInUniform(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	type result struct {
		code int
		keys []string
		took time.Duration
		id   string
	}
	run := func(email string) result {
		start := time.Now()
		rec, m := do(t, h, "POST", "/v1/signins", apiKey, `{"email":"`+email+`"}`)
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		id, _ := m["signin_id"].(string)
		mc, _ := m["match_code"].(string)
		if len(mc) != 2 {
			t.Fatalf("match code %q", mc)
		}
		return result{rec.Code, keys, time.Since(start), id}
	}
	known, unknown := run("member@example.org"), run("stranger@example.org")
	if known.code != 202 || unknown.code != 202 || len(known.keys) != len(unknown.keys) {
		t.Fatalf("responses differ: %+v %+v", known, unknown)
	}
	for _, r := range []result{known, unknown} {
		if r.took < s.LookupFloor || r.took > s.LookupFloor+40*time.Millisecond {
			t.Fatalf("took %v, floor %v", r.took, s.LookupFloor)
		}
	}
	if _, m := do(t, h, "GET", "/v1/signins/"+known.id, apiKey, ""); m["status"] != "approved" || m["connection_id"] != "conn1" ||
		m["key_changed"] != true || m["signin_id"] != known.id {
		t.Fatalf("known status %v", m)
	}
	if _, m := do(t, h, "GET", "/v1/signins/"+unknown.id, apiKey, ""); m["status"] != "pending" || m["connection_id"] != nil ||
		m["key_changed"] != nil {
		t.Fatalf("unknown status %v", m)
	}
	if rec, _ := do(t, h, "GET", "/v1/signins/none", apiKey, ""); rec.Code != 404 {
		t.Fatalf("missing id: %d", rec.Code)
	}
	if rec, _ := do(t, h, "POST", "/v1/signins", apiKey, `{"email":"bad"}`); rec.Code != 400 {
		t.Fatalf("bad email: %d", rec.Code)
	}
}

func TestInviteStatus(t *testing.T) {
	s, _, _ := newServer(t)
	h := s.Handler()
	if rec, _ := do(t, h, "GET", "/v1/invites/inv1", "", ""); rec.Code != 401 {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	rec, m := do(t, h, "GET", "/v1/invites/inv1", apiKey, "")
	if rec.Code != 200 || m["status"] != "sas" || m["sas"] != "123456" || m["connection_id"] != "c1" || m["invite_id"] != "inv1" {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/invites/nope", apiKey, ""); rec.Code != 404 {
		t.Fatalf("unknown: %d", rec.Code)
	}
}

func TestSignInSource(t *testing.T) {
	s, _, si := newServer(t)
	h := s.Handler()
	rec, m := do(t, h, "POST", "/v1/signins", apiKey, `{"email":"a@example.org","source":"2001:db8:1:2::/64"}`)
	if rec.Code != 202 || m["signin_id"] == nil {
		t.Fatalf("%d %v", rec.Code, m)
	}
	want, _ := s.Email.SourceKey("2001:db8:1:2::/64")
	if si.last.SourceKey != want || want == "" || si.last.MatchCode != m["match_code"] {
		t.Fatalf("request %+v", si.last)
	}
	if rec, _ := do(t, h, "POST", "/v1/signins", apiKey, `{"email":"a@example.org"}`); rec.Code != 202 || si.last.SourceKey != "" {
		t.Fatalf("no source: %d %+v", rec.Code, si.last)
	}
	long := strings.Repeat("1", 65)
	for _, body := range []string{`{"email":"a@example.org","source":"` + long + `"}`, `{"email":"a@example.org","source":"a b"}`} {
		if rec, m := do(t, h, "POST", "/v1/signins", apiKey, body); rec.Code != 400 || m["error"] != "invalid_source" {
			t.Errorf("%s: %d %v", body, rec.Code, m)
		}
	}
}
