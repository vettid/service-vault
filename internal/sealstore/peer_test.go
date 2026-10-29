package sealstore_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/internal/sealstore"
)

// A peer on the sealed store connects a member, restarts with its state,
// and leaves nothing of its session keys or held tokens in the table.
func TestPeerOnSealedStore(t *testing.T) {
	ctx := context.Background()
	clk := peertest.NewClock(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	w := peertest.NewWorld(clk)
	keys, err := peer.KeysFromSeeds(peer.Seeds{IK: bytes.Repeat([]byte{1}, 32), KEM: bytes.Repeat([]byte{2}, 32), Relay: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	mem := peer.NewMemStore()
	mem.Now = clk.Now
	st, err := sealstore.New(mem, map[uint32][]byte{1: bytes.Repeat([]byte{9}, 32)}, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	sv := w.View(keys.Relay)
	start := func() *peer.Peer {
		p, err := peer.New(peer.Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Keys: keys, Relay: sv, RelayURL: peertest.RelayURL,
			Store: st, Now: clk.Now, Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Start(ctx); err != nil {
			t.Fatalf("Start: %v", err)
		}
		return p
	}
	p := start()
	m := peertest.NewMember(t, w, 10)
	inv, err := p.CreateInvite(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	m.Accept(inv.Link, "")
	pump := func() {
		for range 50 {
			n, err := p.Step(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			if n+m.Step() == 0 {
				return
			}
		}
	}
	pump()
	m.Approve()
	pump()
	if !m.Active {
		t.Fatal("not connected")
	}
	// Nothing in the clear: not the member's held token, not a key name.
	for _, k := range peer.Kinds() {
		recs, _ := mem.Load(ctx, k)
		for _, r := range recs {
			if bytes.Contains(r.Data, []byte(m.SvcStand)) || bytes.Contains(r.Data, []byte("send_key")) || bytes.Contains(r.Data, []byte("keyring")) {
				t.Fatalf("%s %s stored in the clear", k, r.ID)
			}
		}
	}
	// The peer writes only kinds the migration knows.
	known := map[string]bool{}
	for _, k := range peer.Kinds() {
		known[k] = true
	}
	for _, k := range mem.Kinds() {
		if !known[k] {
			t.Fatalf("the peer wrote kind %q, which peer.Kinds() does not list", k)
		}
	}
	// A restart reads it all back, and the session still works: a
	// challenge reaches the member.
	rec, _ := p.Invite(inv.ID)
	p = start()
	if c, ok := p.Connection(rec.ConnID); !ok || c.State != peer.StateActive {
		t.Fatalf("connection after restart: %+v %v", c, ok)
	}
	if _, err := p.Authenticate(ctx, rec.ConnID, "Sign in", "", time.Minute); err != nil {
		t.Fatalf("Authenticate after restart: %v", err)
	}
	pump()
	if len(m.Challenges) != 1 {
		t.Fatal("no challenge after restart")
	}
}
