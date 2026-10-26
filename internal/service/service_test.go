package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
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

type hooks struct {
	mu  sync.Mutex
	evs []*webhook.Event
}

func (h *hooks) Deliver(_ context.Context, e *webhook.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evs = append(h.evs, e)
	return nil
}

func (h *hooks) of(typ string) []*webhook.Event {
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
	t    *testing.T
	clk  *peertest.Clock
	p    *peer.Peer
	svc  *Service
	hk   *hooks
	keys *peer.Keys
	m    *peertest.Member
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &Service{Store: st, ServiceName: "VettID Member Service", Webhooks: hk, Now: clk.Now, Log: log}
	p, err := peer.New(peer.Config{Keys: keys, Relay: w.View(keys.Relay), RelayURL: peertest.RelayURL, Store: st, Events: svc,
		Now: clk.Now, Log: log, Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc.Peer = p
	return &fixture{t: t, clk: clk, p: p, svc: svc, hk: hk, keys: keys, m: peertest.NewMember(t, w, 10)}
}

func (f *fixture) pump() {
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		n, err := f.p.Step(ctx, 0)
		if err != nil {
			f.t.Fatal(err)
		}
		n += f.m.Step()
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
	id, err := f.svc.SignIns().Start(ctx, "email-key", "42")
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(f.m.Challenges) != 1 {
		t.Fatal("no challenge")
	}
	want, _ := signin.Context("VettID Member Service", "42")
	if f.m.Challenges[0].Context != want {
		t.Fatalf("context %q", f.m.Challenges[0].Context)
	}
	if s, _, _ := f.svc.SignIns().Status(ctx, id); s != "pending" {
		t.Fatalf("status %q", s)
	}
	r, _ := peerwire.SignConnAuth(f.m.Cred, f.keys.IKPublic(), f.m.IK.Public().(ed25519.PublicKey), f.m.Challenges[0],
		f.clk.Now(), nil)
	f.m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	s, cid, err := f.svc.SignIns().Status(ctx, id)
	if err != nil || s != "approved" || cid != st.ConnectionID {
		t.Fatalf("status %q %q %v", s, cid, err)
	}
	ap := f.hk.of(peer.EventSignInApproved)
	var d map[string]any
	if len(ap) != 1 || json.Unmarshal(ap[0].Data, &d) != nil || d["signin_id"] != id {
		t.Fatalf("approved webhook %+v", ap)
	}

	// Denied.
	id2, _ := f.svc.SignIns().Start(ctx, "email-key", "17")
	f.pump()
	f.m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(f.m.Challenges[1].RequestID).Marshal())
	f.pump()
	if s, _, _ := f.svc.SignIns().Status(ctx, id2); s != "denied" {
		t.Fatalf("status %q", s)
	}

	// An unknown email: the same kind of id, pending, then expired; no
	// challenge goes anywhere.
	id3, err := f.svc.SignIns().Start(ctx, "unknown-key", "55")
	if err != nil || len(id3) != len(id) {
		t.Fatalf("%q %v", id3, err)
	}
	f.pump()
	if len(f.m.Challenges) != 2 {
		t.Fatal("challenge for an unknown email")
	}
	if s, _, _ := f.svc.SignIns().Status(ctx, id3); s != "pending" {
		t.Fatalf("status %q", s)
	}
	f.clk.Advance(signin.ChallengeTTL)
	if s, _, _ := f.svc.SignIns().Status(ctx, id3); s != "expired" {
		t.Fatalf("status %q", s)
	}
	if _, _, err := f.svc.SignIns().Status(ctx, "nope"); err != api.ErrNotFound {
		t.Fatalf("unknown: %v", err)
	}

	// The member removes the connection: the email no longer resolves.
	f.m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	if len(f.hk.of(peer.EventConnectionRemoved)) != 1 {
		t.Fatal("no removed webhook")
	}
	id4, _ := f.svc.SignIns().Start(ctx, "email-key", "66")
	f.pump()
	if len(f.m.Challenges) != 2 {
		t.Fatal("challenge after removal")
	}
	if s, _, _ := f.svc.SignIns().Status(ctx, id4); s != "pending" {
		t.Fatalf("status %q", s)
	}
}
