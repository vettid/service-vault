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
	rep, err := Reseal(ctx, k, "k1", cb)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("a record changed meanwhile: %v", err)
	}
	if !bytes.Equal(b.m["record-key.v1"][:len(before["record-key.v1"])], before["record-key.v1"]) {
		t.Fatal("the changed record was replaced")
	}
	b.m["record-key.v1"] = before["record-key.v1"]
	_ = rep

	rep, err = Reseal(ctx, k, "k1", b)
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
	if rep, err := Reseal(ctx, k, "k1", b); err != nil || len(rep.Resealed) != 0 || len(rep.Already) != 4 {
		t.Fatalf("again: %+v %v", rep, err)
	}

	// A record that doesn't open stops it.
	b.m["broken"] = []byte("{")
	if _, err := Reseal(ctx, k, "k1", b); err == nil {
		t.Fatal("a record that doesn't open passed")
	}
}

// recordingKMS records the encryption contexts it is given, and can refuse
// a Decrypt with a context (as a CMK policy written wrong would).
type recordingKMS struct {
	*fakeKMS
	seen          []map[string]string
	refuseContext bool
}

func (r *recordingKMS) GenerateDataKey(ctx context.Context, id string, ec map[string]string) ([]byte, []byte, error) {
	r.seen = append(r.seen, ec)
	return r.fakeKMS.GenerateDataKey(ctx, id, ec)
}

func (r *recordingKMS) Decrypt(ctx context.Context, id string, w []byte, ec map[string]string) ([]byte, error) {
	if ec != nil && r.refuseContext {
		return nil, errors.New("access denied")
	}
	return r.fakeKMS.Decrypt(ctx, id, w, ec)
}

// The context names the record. A new seal that doesn't open stops the
// re-seal before anything is replaced. A record on another KMS key, or a
// legacy record that parses but doesn't open, stops it. One made during
// the run is checked too.
func TestResealSafety(t *testing.T) {
	ctx := context.Background()
	rk := &recordingKMS{fakeKMS: newFakeKMS("k1", "k2")}
	if _, err := Seal(ctx, rk, "k1", "named", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got := rk.seen[len(rk.seen)-1]; got[ContextKey] != "named" || len(got) != 1 {
		t.Fatalf("context %v", got)
	}

	b := &memBlobs{m: map[string][]byte{}}
	b.m["service-secrets"] = legacySeal(t, rk, "k1", "service-secrets", []byte("identity"))
	old := append([]byte(nil), b.m["service-secrets"]...)
	rk.refuseContext = true
	if _, err := Reseal(ctx, rk, "k1", b); err == nil || !bytes.Equal(b.m["service-secrets"], old) {
		t.Fatalf("a new seal that doesn't open replaced the old one: %v", err)
	}
	rk.refuseContext = false

	if _, err := Reseal(ctx, rk, "k2", b); err == nil || !bytes.Equal(b.m["service-secrets"], old) {
		t.Fatalf("a record on another key: %v", err)
	}

	var s Sealed
	_ = json.Unmarshal(legacySeal(t, rk, "k1", "x", []byte("p")), &s)
	s.Ciphertext[0] ^= 1
	b.m["tampered"], _ = json.Marshal(&s)
	if _, err := Reseal(ctx, rk, "k1", b); err == nil {
		t.Fatal("a legacy record that doesn't open passed")
	}
	delete(b.m, "tampered")

	// A legacy record made during the run (after the first List) is seen
	// by the check.
	late := &lateBlobs{memBlobs: b, add: legacySeal(t, rk, "k1", "record-key.v9", []byte("late"))}
	if _, err := Reseal(ctx, rk, "k1", late); err == nil {
		t.Fatal("a legacy record made during the run passed the check")
	}
}

// lateBlobs adds a record after its first List.
type lateBlobs struct {
	*memBlobs
	add   []byte
	lists int
}

func (l *lateBlobs) List(ctx context.Context) ([]string, error) {
	l.lists++
	if l.lists == 2 {
		l.mu.Lock()
		l.m["record-key.v9"] = l.add
		l.mu.Unlock()
	}
	return l.memBlobs.List(ctx)
}

// A re-seal keeps a record's sum, so a table restore sees the same
// secrets; other secrets differ; records without a sum compare by bytes.
func TestSameSecrets(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS("k1")
	a, _ := Seal(ctx, k, "k1", "service-secrets", []byte("identity"))
	b, _ := Seal(ctx, k, "k1", "service-secrets", []byte("identity"))
	c, _ := Seal(ctx, k, "k1", "service-secrets", []byte("another"))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	jc, _ := json.Marshal(c)
	if bytes.Equal(ja, jb) || !SameSecrets(ja, jb) || SameSecrets(ja, jc) {
		t.Fatal("sums")
	}
	l := legacySeal(t, k, "k1", "service-secrets", []byte("identity"))
	if SameSecrets(l, ja) || !SameSecrets(l, l) {
		t.Fatal("a record without a sum compares by its bytes")
	}
}
