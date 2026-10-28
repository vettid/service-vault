package sealstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

var key = bytes.Repeat([]byte{9}, 32) // TEST ONLY

func newStore(t *testing.T, inner peer.Store, legacy bool) *Store {
	t.Helper()
	s, err := New(inner, map[uint32][]byte{1: key}, 1, legacy)
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
	secret := []byte(`{"send_key":"test-only"}`)
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
	other, _ := New(mem, map[uint32][]byte{1: bytes.Repeat([]byte{8}, 32)}, 1, false)
	if _, _, err := other.Get(ctx, "conn", "c1"); !errors.Is(err, ErrOpen) {
		t.Fatalf("another key: %v", err)
	}
}

// Without Legacy, a record that is not sealed is refused (one slipped
// into the table); with it, records written before sealing are sealed in
// place by Reseal, keep their expiry, and later writes go on from the
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
	if err := legacy.Reseal(ctx, []string{"conn", "msg"}); err != nil {
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
	if _, err := New(peer.NewMemStore(), map[uint32][]byte{1: []byte("short")}, 1, false); err == nil {
		t.Fatal("a short key")
	}
	if _, err := New(peer.NewMemStore(), map[uint32][]byte{1: key}, 2, false); err == nil {
		t.Fatal("no key of the current version")
	}
}

// Rotation: records under version 1 keep the layout from before versions;
// after a new version, writes go under it, Reseal moves every record to
// it (keeping expiry), and once the old key is gone nothing under it
// opens. A record's version can't be relabelled.
func TestRotation(t *testing.T) {
	ctx := context.Background()
	mem := peer.NewMemStore()
	v1 := newStore(t, mem, false)
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = v1.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"a":1}`)}, {Kind: "signin", ID: "s1", Data: []byte(`{"s":1}`), Expires: exp}})
	raw, _, _ := mem.Get(ctx, "conn", "c1")
	if !bytes.HasPrefix(raw, prefix) {
		t.Fatalf("version 1 layout: %q", raw[:4])
	}

	key2 := bytes.Repeat([]byte{7}, 32) // TEST ONLY
	both, err := New(mem, map[uint32][]byte{1: key, 2: key2}, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := both.Get(ctx, "conn", "c1"); err != nil || string(got) != `{"a":1}` {
		t.Fatalf("old record under the new store: %q %v", got, err)
	}
	if err := both.Reseal(ctx, []string{"conn", "signin"}); err != nil {
		t.Fatal(err)
	}
	only2, _ := New(mem, map[uint32][]byte{2: key2}, 2, false)
	for _, k := range []string{"conn", "signin"} {
		raw, _ := mem.Load(ctx, k)
		if len(raw) != 1 || !bytes.HasPrefix(raw[0].Data, prefixV) || binary.BigEndian.Uint32(raw[0].Data[4:]) != 2 {
			t.Fatalf("%s not resealed under version 2", k)
		}
		recs, err := only2.Load(ctx, k)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%s under version 2 alone: %v", k, err)
		}
	}
	if recs, _ := mem.Load(ctx, "signin"); !recs[0].Expires.Equal(exp) {
		t.Fatalf("expiry lost: %v", recs[0].Expires)
	}
	if _, _, err := v1.Get(ctx, "conn", "c1"); !errors.Is(err, ErrOpen) {
		t.Fatalf("version 2 record under version 1 alone: %v", err)
	}

	// Relabel a version 2 record as version 3 (a key that exists).
	raw, _, _ = mem.Get(ctx, "conn", "c1")
	bad := append([]byte(nil), raw...)
	binary.BigEndian.PutUint32(bad[4:], 3)
	_ = mem.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c9", Data: bad}})
	three, _ := New(mem, map[uint32][]byte{2: key2, 3: key2}, 3, false)
	if _, _, err := three.Get(ctx, "conn", "c9"); !errors.Is(err, ErrOpen) {
		t.Fatalf("relabelled version: %v", err)
	}
}

func TestKeyNameOf(t *testing.T) {
	if KeyNameOf(1) != KeyName || KeyNameOf(2) != "record-key.v2" || KeyNameOf(12) != "record-key.v12" {
		t.Fatal(KeyNameOf(2))
	}
}

// Page reads through the pager and opens the records (the audit log).
func TestPage(t *testing.T) {
	ctx := context.Background()
	mem := peer.NewMemStore()
	s := newStore(t, mem, false)
	s.Pages = mem
	_ = s.Apply(ctx, []peer.Change{{Kind: "audit", ID: "a1", Data: []byte(`{"e":1}`)}, {Kind: "audit", ID: "a2", Data: []byte(`{"e":2}`)}})
	recs, err := s.Page(ctx, "audit", "a1", 10)
	if err != nil || len(recs) != 1 || string(recs[0].Data) != `{"e":2}` {
		t.Fatalf("Page: %v %v", recs, err)
	}
}
