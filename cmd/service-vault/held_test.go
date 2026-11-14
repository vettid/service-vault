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
