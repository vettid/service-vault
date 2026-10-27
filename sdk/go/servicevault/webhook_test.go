package servicevault_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	iwebhook "github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/service-vault/sdk/go/webhook"
)

type received struct {
	mu  sync.Mutex
	evs []servicevault.Event
}

func (r *received) handle(_ context.Context, e servicevault.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
	return nil
}

func (r *received) last() servicevault.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.evs) == 0 {
		return nil
	}
	return r.evs[len(r.evs)-1]
}

// TestEventsFromService sends each event the service emits through the
// real dispatcher to a Receiver and checks the decoded fields.
func TestEventsFromService(t *testing.T) {
	secret := []byte(randomHex(t, 32))
	got := &received{}
	rc := &servicevault.Receiver{Secret: secret, Replay: &servicevault.MemoryReplayCache{}}
	srv := httptest.NewServer(rc.Handler(got.handle))
	defer srv.Close()

	f := newFixture(t, &iwebhook.Dispatcher{URL: srv.URL, Secret: secret})
	c := f.client(t)
	at := time.Now().UTC().Truncate(time.Second)
	n := 0
	deliver := func(e peer.Event) servicevault.Event {
		t.Helper()
		n++
		e.ID, e.At = "01JEVENT"+string(rune('A'+n)), at
		f.deliver(t, e)
		ev := got.last()
		if ev == nil || ev.EventHeader().ID != e.ID || ev.EventHeader().Type != e.Type ||
			ev.EventHeader().ConnectionID != e.ConnectionID || !ev.EventHeader().CreatedAt.Equal(at) {
			t.Fatalf("%s: got %#v", e.Type, ev)
		}
		return ev
	}

	if ev, ok := deliver(peer.Event{Type: peer.EventConnectionPending, ConnectionID: "c1", InviteID: "inv1", SAS: "123456",
		Name: "Ada Lovelace"}).(*servicevault.ConnectionPending); !ok || ev.InviteID != "inv1" || ev.SAS != "123456" ||
		ev.Name != "Ada Lovelace" || ev.ConnectionID != "c1" {
		t.Fatalf("pending %#v", ev)
	}
	if ev, ok := deliver(peer.Event{Type: peer.EventConnectionAdded, ConnectionID: "c1", InviteID: "inv1", Tag: f.emailKey,
		Name: "Ada Lovelace"}).(*servicevault.ConnectionAdded); !ok || ev.InviteID != "inv1" || ev.Name != "Ada Lovelace" {
		t.Fatalf("added %#v", ev)
	}
	if ev, ok := deliver(peer.Event{Type: peer.EventConnectionDeclined, ConnectionID: "c2",
		InviteID: "inv2"}).(*servicevault.ConnectionDeclined); !ok || ev.InviteID != "inv2" {
		t.Fatalf("declined %#v", ev)
	}
	if ev, ok := deliver(peer.Event{Type: peer.EventConnectionExpired, ConnectionID: "c3",
		InviteID: "inv3"}).(*servicevault.ConnectionExpired); !ok || ev.InviteID != "inv3" {
		t.Fatalf("expired %#v", ev)
	}

	reqs := 0
	start := func() (string, string) {
		t.Helper()
		si, err := c.StartSignIn(context.Background(), servicevault.SignInRequest{Email: knownEmail})
		if err != nil {
			t.Fatal(err)
		}
		reqs++
		return si.ID, "req" + strconv.Itoa(reqs)
	}
	sid, req := start()
	if ev, ok := deliver(peer.Event{Type: peer.EventSignInApproved, ConnectionID: "c1", RequestID: req,
		KeyChanged: true}).(*servicevault.SignInApproved); !ok || ev.SignInID != sid || !ev.KeyChanged {
		t.Fatalf("approved %#v", ev)
	}
	sid, req = start()
	if ev, ok := deliver(peer.Event{Type: peer.EventSignInDenied, ConnectionID: "c1", RequestID: req,
		Reason: "denied"}).(*servicevault.SignInDenied); !ok || ev.SignInID != sid || ev.Reason != "denied" {
		t.Fatalf("denied %#v", ev)
	}
	sid, req = start()
	if ev, ok := deliver(peer.Event{Type: peer.EventSignInExpired, ConnectionID: "c1",
		RequestID: req}).(*servicevault.SignInExpired); !ok || ev.SignInID != sid {
		t.Fatalf("signin expired %#v", ev)
	}

	if ev, ok := deliver(peer.Event{Type: peer.EventConnectionRemoved, ConnectionID: "c1", Tag: f.emailKey,
		Direction: "in"}).(*servicevault.ConnectionRemoved); !ok || ev.Direction != servicevault.DirectionIn {
		t.Fatalf("removed %#v", ev)
	}
}

// signed makes a signed webhook request.
func signed(t *testing.T, secret []byte, id, body string, at time.Time) *http.Request {
	t.Helper()
	sig, err := webhook.Sign(secret, at, id, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/webhooks/service-vault", bytes.NewBufferString(body))
	r.Header.Set(webhook.HeaderEventID, id)
	r.Header.Set(webhook.HeaderSignature, sig)
	return r
}

const approvedBody = `{"id":"01JEVT1","type":"signin.approved","connection_id":"c1","created_at":"2026-10-27T12:00:00Z",` +
	`"data":{"signin_id":"s1","key_changed":false}}`

func TestParseWebhook(t *testing.T) {
	secret := []byte(randomHex(t, 32))
	now := time.Date(2026, 10, 27, 12, 0, 5, 0, time.UTC)

	ev, err := servicevault.ParseWebhook(signed(t, secret, "01JEVT1", approvedBody, now), secret, now)
	if a, ok := ev.(*servicevault.SignInApproved); err != nil || !ok || a.SignInID != "s1" || a.KeyChanged || a.ConnectionID != "c1" {
		t.Fatalf("ParseWebhook %#v, %v", ev, err)
	}

	// Tampered body, wrong secret, stale, another event's id.
	tampered := signed(t, secret, "01JEVT1", approvedBody, now)
	tampered.Body = io.NopCloser(strings.NewReader(strings.Replace(approvedBody, `"s1"`, `"s2"`, 1)))
	other := []byte(randomHex(t, 32))
	for name, c := range map[string]struct {
		r    *http.Request
		want error
	}{
		"tampered":     {tampered, webhook.ErrMismatch},
		"wrong secret": {signed(t, other, "01JEVT1", approvedBody, now), webhook.ErrMismatch},
		"stale":        {signed(t, secret, "01JEVT1", approvedBody, now.Add(-webhook.DefaultTolerance-time.Second)), webhook.ErrStale},
		"future":       {signed(t, secret, "01JEVT1", approvedBody, now.Add(webhook.DefaultTolerance+time.Second)), webhook.ErrStale},
		"no signature": {httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(approvedBody)), webhook.ErrMalformed},
	} {
		if _, err := servicevault.ParseWebhook(c.r, secret, now); !errors.Is(err, servicevault.ErrSignature) || !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Signed, but the body names another event.
	if _, err := servicevault.ParseWebhook(signed(t, secret, "01JEVT2", approvedBody, now), secret, now); !errors.Is(err, servicevault.ErrBadEvent) {
		t.Errorf("id mismatch: %v", err)
	}
	// Signed, but data of the wrong shape.
	bad := `{"id":"01JEVT3","type":"signin.approved","data":{"key_changed":"yes"}}`
	if _, err := servicevault.ParseWebhook(signed(t, secret, "01JEVT3", bad, now), secret, now); !errors.Is(err, servicevault.ErrBadEvent) {
		t.Errorf("bad data: %v", err)
	}
	// A type this package does not know is passed on, not refused.
	unk := `{"id":"01JEVT4","type":"contract.signed","data":{"x":1}}`
	if ev, err := servicevault.ParseWebhook(signed(t, secret, "01JEVT4", unk, now), secret, now); err != nil {
		t.Errorf("unknown type: %v", err)
	} else if u, ok := ev.(*servicevault.UnknownEvent); !ok || string(u.Data) != `{"x":1}` {
		t.Errorf("unknown type: %#v", ev)
	}
	// EmailBound is decoded when present.
	added := `{"id":"01JEVT5","type":"connection.added","data":{"invite_id":"inv1","name":"A B","email_bound":false}}`
	if ev, err := servicevault.ParseWebhook(signed(t, secret, "01JEVT5", added, now), secret, now); err != nil {
		t.Errorf("added: %v", err)
	} else if a := ev.(*servicevault.ConnectionAdded); a.EmailBound == nil || *a.EmailBound {
		t.Errorf("added: %#v", a)
	}
}

func TestReceiverHandler(t *testing.T) {
	secret := []byte(randomHex(t, 32))
	now := time.Date(2026, 10, 27, 12, 0, 5, 0, time.UTC)
	clock := now
	fail := false
	var handled int
	rc := &servicevault.Receiver{Secret: secret, Replay: &servicevault.MemoryReplayCache{}, MaxBody: 1024,
		Now: func() time.Time { return clock }}
	h := rc.Handler(func(_ context.Context, e servicevault.Event) error {
		handled++
		if fail {
			return errors.New("busy")
		}
		return nil
	})
	serve := func(r *http.Request) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	// The handler fails: 500, and the redelivery (signed afresh) is taken.
	fail = true
	if c := serve(signed(t, secret, "01JEVT1", approvedBody, now)); c != http.StatusInternalServerError || handled != 1 {
		t.Fatalf("failing handler: %d, handled %d", c, handled)
	}
	fail = false
	if c := serve(signed(t, secret, "01JEVT1", approvedBody, now.Add(time.Second))); c != http.StatusNoContent || handled != 2 {
		t.Fatalf("redelivery: %d, handled %d", c, handled)
	}
	// A replay within the window is acknowledged and not handled again.
	clock = now.Add(4 * time.Minute)
	if c := serve(signed(t, secret, "01JEVT1", approvedBody, now.Add(time.Second))); c != http.StatusOK || handled != 2 {
		t.Fatalf("replay: %d, handled %d", c, handled)
	}
	clock = now

	if c := serve(signed(t, []byte(randomHex(t, 32)), "01JEVT1", approvedBody, now)); c != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d", c)
	}
	big := `{"id":"01JEVT9","type":"x","data":"` + string(bytes.Repeat([]byte{'a'}, 2000)) + `"}`
	if c := serve(signed(t, secret, "01JEVT9", big, now)); c != http.StatusRequestEntityTooLarge {
		t.Fatalf("large body: %d", c)
	}
	if c := serve(signed(t, secret, "01JEVT8", `{"id":"01JEVT8"}`, now)); c != http.StatusBadRequest {
		t.Fatalf("no type: %d", c)
	}
	if c := serve(httptest.NewRequest(http.MethodGet, "/", nil)); c != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", c)
	}
	if handled != 2 {
		t.Fatalf("handled %d", handled)
	}
}

func TestMemoryReplayCache(t *testing.T) {
	ctx := context.Background()
	m := &servicevault.MemoryReplayCache{}
	t0 := time.Unix(1_800_000_000, 0)
	if ok, _ := m.Add(ctx, "a", t0, t0.Add(time.Minute)); !ok {
		t.Fatal("first add refused")
	}
	if ok, _ := m.Add(ctx, "a", t0.Add(59*time.Second), t0.Add(2*time.Minute)); ok {
		t.Fatal("replay inside the window accepted")
	}
	if ok, _ := m.Add(ctx, "a", t0.Add(time.Minute), t0.Add(2*time.Minute)); !ok {
		t.Fatal("add after expiry refused")
	}
	_ = m.Remove(ctx, "a")
	if ok, _ := m.Add(ctx, "a", t0.Add(time.Minute), t0.Add(2*time.Minute)); !ok {
		t.Fatal("add after Remove refused")
	}
	// Expired ids are pruned as the cache is used.
	for i := 0; i < 5000; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		if ok, _ := m.Add(ctx, string(rune(0x1000+i)), at, at.Add(time.Second)); !ok {
			t.Fatal("distinct id refused")
		}
	}
}
