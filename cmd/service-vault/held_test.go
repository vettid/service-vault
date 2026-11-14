package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
)

// While held (GC #9109), /health answers 200 and every other request,
// /v1 routes and a POST to /health included, 503 identity_key_mismatch.
func TestHeldHandler(t *testing.T) {
	h := heldHandler()
	for _, tc := range []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/health", 200, `"status":"held"`},
		{"POST", "/health", 503, `"error":"identity_key_mismatch"`},
		{"POST", "/v1/invites", 503, `"error":"identity_key_mismatch"`},
		{"GET", "/v1/approvals/x", 503, `"error":"identity_key_mismatch"`},
		{"GET", "/v1/anchor-key", 503, `"error":"identity_key_mismatch"`},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.body) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}

// serve's first step: the TLS pin is published only once the identity
// check passes; held, it is left as it was.
func TestIdentityThenPin(t *testing.T) {
	ctx := context.Background()
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	st := peer.NewMemStore()
	pins := 0
	publish := func(context.Context) error { pins++; return nil }
	if m, err := identityThenPin(ctx, st, ik, publish); m != nil || err != nil || pins != 1 {
		t.Fatalf("right key: %v %v, %d pins", m, err, pins)
	}
	if m, err := identityThenPin(ctx, st, other, publish); m == nil || err != nil || pins != 1 {
		t.Fatalf("held: %v %v, %d pins", m, err, pins)
	}
}

// A record sealed under a record-key version that is gone (a rollback,
// then a rotation that retired it) can't be opened: held as unreadable,
// not an exit. The same for the stored state of a table without the
// record.
func TestIdentityUnreadableSealed(t *testing.T) {
	ctx := context.Background()
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	k1, k2 := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name  string
		setup func(*sealstore.Store)
	}{
		{"the record", func(v1 *sealstore.Store) {
			if m, err := identityHeld(ctx, v1, ik); m != nil || err != nil {
				t.Fatalf("v1: %v %v", m, err)
			}
		}},
		{"the state", func(v1 *sealstore.Store) {
			if err := v1.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mem := peer.NewMemStore()
			v1, err := sealstore.New(mem, map[uint32][]byte{1: k1}, 1, false)
			if err != nil {
				t.Fatal(err)
			}
			v1.Pages = mem
			tc.setup(v1)
			v2, err := sealstore.New(mem, map[uint32][]byte{2: k2}, 2, false)
			if err != nil {
				t.Fatal(err)
			}
			v2.Pages = mem
			m, err := identityHeld(ctx, v2, ik)
			if err != nil || m == nil || m.From != "unreadable" {
				t.Fatalf("v1 retired: %+v %v", m, err)
			}
		})
	}
}

// identityHeld, as serve calls it: a fresh table gets the record; a table
// from before the record whose approvals audit log names another service
// key is held, with nothing written; one that names this key gets it; a
// record naming another key holds.
func TestIdentityHeld(t *testing.T) {
	ctx := context.Background()
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	audit := func(st *peer.MemStore, k ed25519.PrivateKey) {
		b, _ := json.Marshal(map[string]any{"type": "approval.response", "service_ik": k.Public().(ed25519.PublicKey)})
		if err := st.Apply(ctx, []peer.Change{{Kind: approval.KindAudit, ID: "0001", Data: b}}); err != nil {
			t.Fatal(err)
		}
	}
	held := func(st *peer.MemStore, k ed25519.PrivateKey) *peer.IdentityMismatch {
		t.Helper()
		m, err := identityHeld(ctx, st, k)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	fresh := peer.NewMemStore()
	if held(fresh, ik) != nil {
		t.Fatal("a fresh table held")
	}
	if held(fresh, ik) != nil {
		t.Fatal("held at the second start")
	}
	if m := held(fresh, other); m == nil || m.From != "record" {
		t.Fatalf("another key on a table with the record: %+v", m)
	}
	old := peer.NewMemStore()
	audit(old, other)
	if m := held(old, ik); m == nil || m.From != "state" || !bytes.Equal(m.Recorded, other.Public().(ed25519.PublicKey)) {
		t.Fatalf("an audit log naming another key: %+v", m)
	}
	if held(old, other) != nil {
		t.Fatal("the audit log's own key held")
	}
	if m := held(old, ik); m == nil || m.From != "record" {
		t.Fatalf("the record was not written from the matching key: %+v", m)
	}
}
