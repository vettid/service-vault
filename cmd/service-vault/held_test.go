package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
)

// While held, the alarm is raised at every tick and stops with the
// service; the interval keeps every 5-minute alarm period raised.
func TestHeldAlarmRepeats(t *testing.T) {
	if heldAlarmEvery > 150*time.Second {
		t.Fatalf("heldAlarmEvery %s leaves a 5-minute period without a line", heldAlarmEvery)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	raised := make(chan struct{}, 10)
	done := make(chan struct{})
	go func() { heldAlarm(ctx, tick, func() { raised <- struct{}{} }); close(done) }()
	for i := 0; i < 3; i++ {
		tick <- time.Now()
		<-raised
	}
	cancel()
	<-done
	if len(raised) != 0 {
		t.Fatalf("%d extra alarms", len(raised))
	}
}

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

// admin bootstrap's check (identityVerified): a table without the record
// passes and stays without it; one whose record names the keystore's key
// passes; one that names another key is refused.
func TestIdentityVerifiedForAdmin(t *testing.T) {
	ctx := context.Background()
	blobs, st := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	secrets, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", blobs, keystore.SecretsName, keystore.NewSecrets)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := peer.KeysFromSeeds(secrets.Peer)
	if err != nil {
		t.Fatal(err)
	}
	record := func(ik ed25519.PublicKey) {
		b, _ := json.Marshal(map[string]any{"ik": ik})
		if err := st.Apply(ctx, []peer.Change{{Kind: "identity", ID: "ik", Data: b}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := identityVerified(ctx, plainKMS{}, "k", blobs, st); err != nil {
		t.Fatalf("no record: %v", err)
	}
	if _, ok, _ := st.Get(ctx, "identity", "ik"); ok {
		t.Fatal("the record was written by a tool")
	}
	record(keys.IKPublic())
	if err := identityVerified(ctx, plainKMS{}, "k", blobs, st); err != nil {
		t.Fatalf("the keystore's key: %v", err)
	}
	record(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)).Public().(ed25519.PublicKey))
	if err := identityVerified(ctx, plainKMS{}, "k", blobs, st); !errors.Is(err, peer.ErrIdentityMismatch) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("another key: %v", err)
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
