package sealstore

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

var key = bytes.Repeat([]byte{9}, 32) // TEST ONLY

func newStore(t *testing.T, inner peer.Store, legacy bool) *Store {
	t.Helper()
	s, err := New(inner, key, legacy)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// What goes to the table is sealed; it reads back; nothing of the
// plaintext is visible in the stored bytes.
func TestSealedRoundTrip(t *testing.T) {
	ctx := context.Background()
	mem := peer.NewMemStore()
	s := newStore(t, mem, false)
	secret := []byte(`{"send_key":"c2VjcmV0LXNlc3Npb24ta2V5"}`)
	if err := s.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: secret}}); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := mem.Get(ctx, "conn", "c1")
	if !bytes.HasPrefix(raw, prefix) || bytes.Contains(raw, []byte("send_key")) {
		t.Fatalf("stored in the clear: %q", raw)
	}
	got, ok, err := s.Get(ctx, "conn", "c1")
	if err != nil || !ok || !bytes.Equal(got, secret) {
		t.Fatalf("Get: %q %v %v", got, ok, err)
	}
	recs, err := s.Load(ctx, "conn")
	if err != nil || len(recs) != 1 || !bytes.Equal(recs[0].Data, secret) {
		t.Fatalf("Load: %v %v", recs, err)
	}
	if err := s.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", IfVersion: recs[0].Version}}); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

// A sealed record is bound to its kind and id, and to the key: moved,
// tampered with or opened under another key, it is refused.
func TestSealedBinding(t *testing.T) {
	ctx := context.Background()
	mem := peer.NewMemStore()
	s := newStore(t, mem, false)
	if err := s.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"a":1}`)}}); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := mem.Get(ctx, "conn", "c1")
	_ = mem.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c2", Data: raw}})
	if _, _, err := s.Get(ctx, "conn", "c2"); !errors.Is(err, ErrOpen) {
		t.Fatalf("moved record: %v", err)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-1] ^= 1
	_ = mem.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c3", Data: bad}})
	if _, _, err := s.Get(ctx, "conn", "c3"); !errors.Is(err, ErrOpen) {
		t.Fatalf("tampered record: %v", err)
	}
	other, _ := New(mem, bytes.Repeat([]byte{8}, 32), false)
	if _, _, err := other.Get(ctx, "conn", "c1"); !errors.Is(err, ErrOpen) {
		t.Fatalf("another key: %v", err)
	}
}

// Without Legacy, a record that is not sealed is refused (one slipped
// into the table); with it, records written before sealing are sealed in
// place by Migrate, keep their expiry, and later writes go on from the
// new version.
func TestMigration(t *testing.T) {
	ctx := context.Background()
	mem := peer.NewMemStore()
	_ = mem.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"old":true}`)}, {Kind: "msg", ID: "m1", Data: []byte{1}}})
	strict := newStore(t, mem, false)
	if _, err := strict.Load(ctx, "conn"); !errors.Is(err, ErrPlaintext) {
		t.Fatalf("strict Load of plaintext: %v", err)
	}
	if _, _, err := strict.Get(ctx, "msg", "m1"); !errors.Is(err, ErrPlaintext) {
		t.Fatalf("strict Get of plaintext: %v", err)
	}
	legacy := newStore(t, mem, true)
	if err := legacy.Migrate(ctx, []string{"conn", "msg"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"conn", "msg"} {
		recs, _ := mem.Load(ctx, k)
		if len(recs) != 1 || !bytes.HasPrefix(recs[0].Data, prefix) {
			t.Fatalf("%s not sealed in place", k)
		}
	}
	recs, err := strict.Load(ctx, "conn")
	if err != nil || len(recs) != 1 || string(recs[0].Data) != `{"old":true}` {
		t.Fatalf("after migration: %v %v", recs, err)
	}
	if err := strict.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"new":1}`), IfVersion: recs[0].Version}}); err != nil {
		t.Fatalf("write after migration: %v", err)
	}
	if v, _, _ := strict.Get(ctx, "msg", "m1"); !bytes.Equal(v, []byte{1}) {
		t.Fatalf("marker %v", v)
	}
}

func TestKeySize(t *testing.T) {
	if _, err := New(peer.NewMemStore(), []byte("short"), false); err == nil {
		t.Fatal("a short key")
	}
}
