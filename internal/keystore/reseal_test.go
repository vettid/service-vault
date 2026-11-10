package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
)

// legacySeal seals as Seal did before encryption contexts: the data key
// bound to none, Context unset.
func legacySeal(t *testing.T, k KMS, keyID, name string, pt []byte) []byte {
	t.Helper()
	dk, wrapped, err := k.GenerateDataKey(context.Background(), keyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := gcm(dk)
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	b, _ := json.Marshal(&Sealed{Version: sealedVersion, KeyID: keyID, WrappedKey: wrapped, Nonce: n, Ciphertext: g.Seal(nil, n, pt, aad(name))})
	return b
}

// A record is sealed with its context and opens with it; one from before
// contexts opens without; a record's Context flag can't be flipped either
// way to open it.
func TestSealContext(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS("k1")
	s, err := Seal(ctx, k, "k1", "rec", []byte("secret"))
	if err != nil || !s.Context {
		t.Fatalf("sealed: %+v %v", s, err)
	}
	dropped := *s
	dropped.Context = false
	if _, err := Open(ctx, k, "rec", &dropped); err == nil {
		t.Fatal("opened with its context dropped")
	}
	var old Sealed
	_ = json.Unmarshal(legacySeal(t, k, "k1", "rec", []byte("old")), &old)
	if pt, err := Open(ctx, k, "rec", &old); err != nil || string(pt) != "old" {
		t.Fatalf("legacy: %q %v", pt, err)
	}
	old.Context = true
	if _, err := Open(ctx, k, "rec", &old); err == nil {
		t.Fatal("a legacy record opened as one with a context")
	}
}

// changingBlobs changes one record just before the first Replace of it.
type changingBlobs struct {
	*memBlobs
	name string
	done bool
}

func (c *changingBlobs) Replace(ctx context.Context, name string, old, data []byte) error {
	if name == c.name && !c.done {
		c.done = true
		c.m[name] = append([]byte(nil), c.m[name]...)
		c.m[name] = append(c.m[name], ' ')
	}
	return c.memBlobs.Replace(ctx, name, old, data)
}

// Reseal moves every record without a context to one, keeps what each
// holds, leaves those with one as they are, and then each opens with its
// context; a record changed meanwhile stops it with nothing lost; a run
// again finishes.
func TestReseal(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS("k1")
	b := &memBlobs{m: map[string][]byte{}}
	for _, n := range []string{"service-secrets", "record-key.v1", "anchor-key"} {
		b.m[n] = legacySeal(t, k, "k1", n, []byte("pt "+n))
	}
	s, _ := Seal(ctx, k, "k1", "record-key.v2", []byte("pt record-key.v2"))
	b.m["record-key.v2"], _ = json.Marshal(s)
	before := map[string][]byte{}
	for n, v := range b.m {
		before[n] = v
	}

	cb := &changingBlobs{memBlobs: b, name: "record-key.v1"}
	rep, err := Reseal(ctx, k, cb)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("a record changed meanwhile: %v", err)
	}
	if !bytes.Equal(b.m["record-key.v1"][:len(before["record-key.v1"])], before["record-key.v1"]) {
		t.Fatal("the changed record was replaced")
	}
	b.m["record-key.v1"] = before["record-key.v1"]
	_ = rep

	rep, err = Reseal(ctx, k, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Already) != 2 || len(rep.Resealed) != 2 { // anchor-key was moved in the first run
		t.Fatalf("report %+v", rep)
	}
	for n := range before {
		var s Sealed
		if err := json.Unmarshal(b.m[n], &s); err != nil || !s.Context {
			t.Fatalf("%s: no context", n)
		}
		pt, err := Open(ctx, k, n, &s)
		if err != nil || string(pt) != "pt "+n {
			t.Fatalf("%s: %q %v", n, pt, err)
		}
	}
	if rep, err := Reseal(ctx, k, b); err != nil || len(rep.Resealed) != 0 || len(rep.Already) != 4 {
		t.Fatalf("again: %+v %v", rep, err)
	}

	// A record that doesn't open stops it.
	b.m["broken"] = []byte("{")
	if _, err := Reseal(ctx, k, b); err == nil {
		t.Fatal("a record that doesn't open passed")
	}
}
