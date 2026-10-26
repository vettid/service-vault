package servicevault_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/sdk/go/pinned"
	"github.com/vettid/service-vault/sdk/go/servicevault"
)

func TestClientAgainstAPI(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client(t)
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	inv, err := c.CreateInvite(ctx, knownEmail, servicevault.EmailVerified)
	if err != nil || inv.ID != "inv1" || !strings.HasPrefix(inv.URL, "https://") || !inv.ExpiresAt.Equal(inviteExp) {
		t.Fatalf("CreateInvite %+v, %v", inv, err)
	}
	if tag := f.p.tag.Load(); tag == nil || *tag != f.emailKey {
		t.Fatal("a verified invitation does not carry the email's key")
	}
	st, err := c.InviteStatus(ctx, inv.ID)
	if err != nil || st.Status != servicevault.InviteStatusSAS || st.SAS != "123456" || st.ConnectionID != "c1" {
		t.Fatalf("InviteStatus %+v, %v", st, err)
	}

	// The connection is added and bound to the email; a sign-in sends
	// it a challenge (req1), which the member approves.
	f.deliver(t, peer.Event{ID: "01JEVT1", Type: peer.EventConnectionAdded, ConnectionID: "c1", InviteID: "inv1", Tag: f.emailKey})
	si, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: knownEmail})
	if err != nil || si.ID == "" || len(si.MatchCode) == 0 {
		t.Fatalf("StartSignIn %+v, %v", si, err)
	}
	if ss, err := c.SignInStatus(ctx, si.ID); err != nil || ss.Status != servicevault.SignInStatusPending {
		t.Fatalf("SignInStatus %+v, %v", ss, err)
	}
	f.deliver(t, peer.Event{ID: "01JEVT2", Type: peer.EventSignInApproved, ConnectionID: "c1", RequestID: "req1"})
	ss, err := c.SignInStatus(ctx, si.ID)
	if err != nil || ss.Status != servicevault.SignInStatusApproved || ss.ConnectionID != "c1" {
		t.Fatalf("SignInStatus %+v, %v", ss, err)
	}
	other, _ := c.StartSignIn(ctx, servicevault.SignInRequest{Email: "nobody@example.org"})
	if ss, err := c.SignInStatus(ctx, other.ID); err != nil || ss.Status != servicevault.SignInStatusPending || ss.ConnectionID != "" {
		t.Fatalf("unknown email: %+v, %v", ss, err)
	}
}

func TestClientErrors(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	c := f.client(t)

	_, err := c.InviteStatus(ctx, "nope")
	var ae *servicevault.APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusNotFound || ae.Code != servicevault.CodeNotFound || !servicevault.IsNotFound(err) {
		t.Fatalf("unknown invite: %v", err)
	}
	if _, err := c.SignInStatus(ctx, "nope"); !servicevault.IsNotFound(err) {
		t.Fatalf("unknown sign-in: %v", err)
	}
	if _, err := c.CreateInvite(ctx, "not an email", servicevault.EmailVerified); !errors.As(err, &ae) || ae.Status != http.StatusBadRequest || ae.Code != servicevault.CodeInvalidEmail {
		t.Fatalf("bad email: %v", err)
	}

	wrongKey := randomHex(t, 24)
	wrong, _ := servicevault.New(servicevault.Config{BaseURL: f.url, APIKey: wrongKey, Pin: f.pin})
	_, err = wrong.CreateInvite(ctx, knownEmail, servicevault.EmailVerified)
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized || ae.Code != servicevault.CodeUnauthorized {
		t.Fatalf("wrong key: %v", err)
	}
	if strings.Contains(err.Error(), wrongKey) {
		t.Fatal("error mentions the API key")
	}
}

// An unverified email is not sent to be bound: the invitation carries no
// email, so the connection binds nothing and makes no admin. The zero
// EmailVerification is refused before any request.
func TestClientUnverifiedInvite(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client(t)
	ctx := context.Background()
	for _, v := range []servicevault.EmailVerification{0, 3} {
		if _, err := c.CreateInvite(ctx, knownEmail, v); !errors.Is(err, servicevault.ErrEmailVerification) {
			t.Fatalf("verification %d: %v", v, err)
		}
	}
	if f.p.tag.Load() != nil {
		t.Fatal("a refused CreateInvite reached the server")
	}
	if _, err := c.CreateInvite(ctx, knownEmail, servicevault.EmailUnverified); err != nil {
		t.Fatal(err)
	}
	tag := f.p.tag.Load()
	if tag == nil || *tag != "" {
		t.Fatal("an unverified invitation carries the email")
	}
	f.deliver(t, peer.Event{ID: "01JEVT1", Type: peer.EventConnectionAdded, ConnectionID: "c1", InviteID: "inv1", Tag: *tag})
	if err := f.apv.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if a, err := c.Admins(ctx); err != nil || len(a.Admins) != 0 {
		t.Fatalf("admins %+v, %v", a, err)
	}
	if bound, _, _ := f.svc.BoundConnection(ctx, f.emailKey); bound != "" {
		t.Fatal("bound to an unverified email")
	}
}

func TestClientPinMismatch(t *testing.T) {
	f := newFixture(t, nil)
	_, otherPin := tlsServer(t, http.NotFoundHandler())
	c, _ := servicevault.New(servicevault.Config{BaseURL: f.url, APIKey: f.key, Pin: otherPin})
	if err := c.Health(context.Background()); !errors.Is(err, pinned.ErrPin) {
		t.Fatalf("Health with a wrong pin: %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	f := newFixture(t, nil)
	pin, key := f.pin, f.key
	for _, cfg := range []servicevault.Config{
		{BaseURL: "https://sv.test", Pin: pin},                     // no key
		{BaseURL: "http://sv.test", APIKey: key, Pin: pin},         // not https
		{BaseURL: "sv.test", APIKey: key, Pin: pin},                // not absolute
		{BaseURL: "https://sv.test", APIKey: key, Pin: "sha256/x"}, // malformed pin
		{BaseURL: "https://sv.test", APIKey: key},                  // no pin
	} {
		if _, err := servicevault.New(cfg); err == nil {
			t.Errorf("New(%+v) accepted", cfg.BaseURL)
		}
	}
	if _, err := servicevault.New(servicevault.Config{BaseURL: "http://sv.test", APIKey: key},
		servicevault.WithHTTPClient(http.DefaultClient)); err != nil {
		t.Errorf("WithHTTPClient: %v", err)
	}
}

// scripted serves answers in order and counts requests.
type scripted struct {
	calls   atomic.Int32
	answers []int
	body    atomic.Value // last request body
}

func (s *scripted) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	s.body.Store(string(b))
	n := int(s.calls.Add(1)) - 1
	code := s.answers[min(n, len(s.answers)-1)]
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	switch {
	case code >= 400:
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unavailable"})
	case r.URL.Path == "/v1/signins":
		_ = json.NewEncoder(w).Encode(map[string]string{"signin_id": "s1", "match_code": "42"})
	default:
		_ = json.NewEncoder(w).Encode(map[string]string{"signin_id": "s1", "status": "pending"})
	}
}

func scriptedClient(t *testing.T, s *scripted) *servicevault.Client {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	c, err := servicevault.New(servicevault.Config{BaseURL: srv.URL, APIKey: "k", RetryBackoff: time.Millisecond},
		servicevault.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRetries(t *testing.T) {
	ctx := context.Background()

	s := &scripted{answers: []int{503, 502, 200}}
	if st, err := scriptedClient(t, s).SignInStatus(ctx, "s1"); err != nil || st.Status != "pending" || s.calls.Load() != 3 {
		t.Fatalf("GET after two 5xx: %+v, %v, %d calls", st, err, s.calls.Load())
	}

	s = &scripted{answers: []int{503}}
	_, err := scriptedClient(t, s).SignInStatus(ctx, "s1")
	var ae *servicevault.APIError
	if !errors.As(err, &ae) || ae.Status != 503 || ae.Code != servicevault.CodeUnavailable || s.calls.Load() != servicevault.DefaultGetAttempts {
		t.Fatalf("GET always 503: %v, %d calls", err, s.calls.Load())
	}

	s = &scripted{answers: []int{404}}
	if _, err := scriptedClient(t, s).SignInStatus(ctx, "s1"); !servicevault.IsNotFound(err) || s.calls.Load() != 1 {
		t.Fatalf("GET 404: %v, %d calls", err, s.calls.Load())
	}

	s = &scripted{answers: []int{503, 202}}
	if _, err := scriptedClient(t, s).StartSignIn(ctx, servicevault.SignInRequest{Email: knownEmail}); err == nil || s.calls.Load() != 1 {
		t.Fatalf("POST 503: %v, %d calls", err, s.calls.Load())
	}
}

func TestNetworkErrorRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// Drop the connection without an answer.
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()
	c, _ := servicevault.New(servicevault.Config{BaseURL: srv.URL, APIKey: "k", RetryBackoff: time.Millisecond},
		servicevault.WithHTTPClient(srv.Client()))
	if err := c.Health(context.Background()); err != nil || calls.Load() != 2 {
		t.Fatalf("Health: %v, %d calls", err, calls.Load())
	}
}

func TestSignInSource(t *testing.T) {
	s := &scripted{answers: []int{202}}
	c := scriptedClient(t, s)
	ctx := context.Background()
	if _, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: knownEmail}); err != nil {
		t.Fatal(err)
	}
	if got := s.body.Load().(string); strings.Contains(got, "source") {
		t.Fatalf("empty Source sent: %s", got)
	}
	if _, err := c.StartSignIn(ctx, servicevault.SignInRequest{Email: knownEmail, Source: "web"}); err != nil {
		t.Fatal(err)
	}
	var b map[string]string
	if err := json.Unmarshal([]byte(s.body.Load().(string)), &b); err != nil || b["source"] != "web" || b["email"] != knownEmail {
		t.Fatalf("body %v, %v", b, err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	c, _ := servicevault.New(servicevault.Config{BaseURL: srv.URL, APIKey: "k", Timeout: 20 * time.Millisecond,
		GetAttempts: 1}, servicevault.WithHTTPClient(srv.Client()))
	if err := c.Health(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Health: %v", err)
	}
}
