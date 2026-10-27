package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// hooks is the webhook endpoint; of delivers what the outboxes hold
// first.
type hooks struct {
	mu   sync.Mutex
	evs  []*webhook.Event
	outs []*webhook.Outbox
	down error // Deliver fails with it
}

func (h *hooks) outbox(st peer.Store, kind string) *webhook.Outbox {
	o := &webhook.Outbox{Store: st, Kind: kind, Sender: h}
	h.outs = append(h.outs, o)
	return o
}

func (h *hooks) Deliver(_ context.Context, e *webhook.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down != nil {
		return h.down
	}
	h.evs = append(h.evs, e)
	return nil
}

func (h *hooks) of(typ string) []*webhook.Event {
	for _, o := range h.outs {
		_ = o.Flush(context.Background())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []*webhook.Event
	for _, e := range h.evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

type fixture struct {
	t       *testing.T
	clk     *peertest.Clock
	w       *peertest.World
	p       *peer.Peer
	svc     *Service
	hk      *hooks
	keys    *peer.Keys
	m       *peertest.Member
	members []*peertest.Member
	logs    *syncBuffer
}

// syncBuffer collects the service's logs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func newFixture(t *testing.T) *fixture {
	clk := peertest.NewClock(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	w := peertest.NewWorld(clk)
	keys, err := peer.KeysFromSeeds(peer.Seeds{IK: bytes.Repeat([]byte{1}, 32), KEM: bytes.Repeat([]byte{2}, 32),
		Relay: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	st := peer.NewMemStore()
	st.Now = clk.Now
	hk := &hooks{}
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	svc := &Service{Store: st, ServiceName: "VettID Member Service", Hooks: hk.outbox(st, HookKind), Now: clk.Now, Log: log}
	p, err := peer.New(peer.Config{Keys: keys, Relay: w.View(keys.Relay), RelayURL: peertest.RelayURL, Store: st, Events: svc,
		Now: clk.Now, Log: log, Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc.Peer = p
	m := peertest.NewMember(t, w, 10)
	return &fixture{t: t, clk: clk, w: w, p: p, svc: svc, hk: hk, keys: keys, m: m, members: []*peertest.Member{m}, logs: logs}
}

func (f *fixture) member(seed byte) *peertest.Member {
	m := peertest.NewMember(f.t, f.w, seed)
	f.members = append(f.members, m)
	return m
}

// connect connects m from an invitation for emailKey; it returns the
// connection id and the connection.added webhook's data.
func (f *fixture) connect(m *peertest.Member, emailKey string) (string, map[string]any) {
	f.t.Helper()
	inv, err := f.svc.Invites().Create(context.Background(), emailKey)
	if err != nil {
		f.t.Fatal(err)
	}
	n := len(f.hk.of(peer.EventConnectionAdded))
	m.Accept(inv.URL[strings.IndexByte(inv.URL, '#')+1:], "")
	f.pump()
	m.Approve()
	f.pump()
	added := f.hk.of(peer.EventConnectionAdded)
	if len(added) != n+1 {
		f.t.Fatalf("no connection.added")
	}
	var d map[string]any
	if err := json.Unmarshal(added[n].Data, &d); err != nil {
		f.t.Fatal(err)
	}
	return added[n].ConnectionID, d
}

func (f *fixture) start(emailKey, source, code string) string {
	f.t.Helper()
	id, err := f.svc.SignIns().Start(context.Background(), api.SignInRequest{EmailKey: emailKey, SourceKey: source, MatchCode: code})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) status(id string) *api.SignInStatus {
	f.t.Helper()
	st, err := f.svc.SignIns().Status(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return st
}

func (f *fixture) sign(m *peertest.Member, ch *peerwire.ConnAuthChallenge, key ed25519.PrivateKey) {
	r, err := peerwire.SignConnAuth(key, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), ch, f.clk.Now(), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
}

func (f *fixture) pump() {
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		n, err := f.p.Step(ctx, 0)
		if err != nil {
			f.t.Fatal(err)
		}
		for _, m := range f.members {
			n += m.Step()
		}
		f.p.DeliverEvents(ctx)
		if n == 0 {
			return
		}
	}
}

func TestConnectAndSignIn(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	inv, err := f.svc.Invites().Create(ctx, "email-key")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := f.svc.Invites().Status(ctx, inv.ID); st.Status != api.InviteWaiting || st.SAS != "" {
		t.Fatalf("status %+v", st)
	}
	f.m.Accept(inv.URL[strings.IndexByte(inv.URL, '#')+1:], "")
	f.pump()
	st, _ := f.svc.Invites().Status(ctx, inv.ID)
	if st.Status != api.InviteSAS || st.SAS != f.m.SAS || st.ConnectionID == "" {
		t.Fatalf("status %+v, member SAS %q", st, f.m.SAS)
	}
	if p := f.hk.of(peer.EventConnectionPending); len(p) != 1 || !strings.Contains(string(p[0].Data), `"sas":"`+f.m.SAS+`"`) {
		t.Fatalf("pending webhook %+v", p)
	}
	f.m.Approve()
	f.pump()
	if st, _ := f.svc.Invites().Status(ctx, inv.ID); st.Status != api.InviteConnected || st.SAS != "" {
		t.Fatalf("status %+v", st)
	}
	added := f.hk.of(peer.EventConnectionAdded)
	if len(added) != 1 || added[0].ConnectionID != st.ConnectionID || strings.Contains(string(added[0].Data), "email-key") {
		t.Fatalf("added %+v", added)
	}

	// Sign-in: the challenge carries the match code; the member signs.
	id := f.start("email-key", "", "42")
	f.pump()
	if len(f.m.Challenges) != 1 {
		t.Fatal("no challenge")
	}
	want, _ := signin.Context("VettID Member Service", "42")
	if f.m.Challenges[0].Context != want {
		t.Fatalf("context %q", f.m.Challenges[0].Context)
	}
	if s := f.status(id); s.Status != "pending" || s.KeyChanged != nil {
		t.Fatalf("status %+v", s)
	}
	f.sign(f.m, f.m.Challenges[0], f.m.Cred)
	if s := f.status(id); s.Status != "approved" || s.ConnectionID != st.ConnectionID || s.KeyChanged == nil || *s.KeyChanged {
		t.Fatalf("status %+v", s)
	}
	ap := f.hk.of(peer.EventSignInApproved)
	var d map[string]any
	if len(ap) != 1 || json.Unmarshal(ap[0].Data, &d) != nil || d["signin_id"] != id || d["key_changed"] != false {
		t.Fatalf("approved webhook %+v", ap)
	}

	// Denied.
	id2 := f.start("email-key", "", "17")
	f.pump()
	f.m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(f.m.Challenges[1].RequestID).Marshal())
	f.pump()
	if s := f.status(id2); s.Status != "denied" || s.ConnectionID != "" || s.KeyChanged != nil {
		t.Fatalf("status %+v", s)
	}
	// Denying ended the challenge: a signed answer after it changes nothing.
	f.sign(f.m, f.m.Challenges[1], f.m.Cred)
	if s := f.status(id2); s.Status != "denied" || len(f.hk.of(peer.EventSignInApproved)) != 1 {
		t.Fatalf("after denial %+v", s)
	}
	if dn := f.hk.of(peer.EventSignInDenied); len(dn) != 1 || !strings.Contains(string(dn[0].Data), `"reason":"denied"`) {
		t.Fatalf("denied webhook %+v", dn)
	}

	// An unknown email: the same kind of id, pending, then expired; no
	// challenge goes anywhere.
	id3 := f.start("unknown-key", "", "55")
	if len(id3) != len(id) {
		t.Fatalf("%q", id3)
	}
	f.pump()
	if len(f.m.Challenges) != 2 {
		t.Fatal("challenge for an unknown email")
	}
	if s := f.status(id3); s.Status != "pending" {
		t.Fatalf("status %+v", s)
	}
	f.clk.Advance(signin.ChallengeTTL)
	if s := f.status(id3); s.Status != "expired" {
		t.Fatalf("status %+v", s)
	}
	if _, err := f.svc.SignIns().Status(ctx, "nope"); err != api.ErrNotFound {
		t.Fatalf("unknown: %v", err)
	}

	// The member removes the connection: the email no longer resolves.
	f.m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	if len(f.hk.of(peer.EventConnectionRemoved)) != 1 {
		t.Fatal("no removed webhook")
	}
	id4 := f.start("email-key", "", "66")
	f.pump()
	if len(f.m.Challenges) != 2 {
		t.Fatal("challenge after removal")
	}
	if s := f.status(id4); s.Status != "pending" {
		t.Fatalf("status %+v", s)
	}
}
