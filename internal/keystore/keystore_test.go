package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// fakeKMS wraps data keys with AES-GCM under one master key per key id.
type fakeKMS struct {
	masters map[string][]byte
}

func newFakeKMS(ids ...string) *fakeKMS {
	f := &fakeKMS{masters: map[string][]byte{}}
	for _, id := range ids {
		m := make([]byte, 32)
		rand.Read(m)
		f.masters[id] = m
	}
	return f
}

func (f *fakeKMS) aead(id string) (cipher.AEAD, error) {
	m, ok := f.masters[id]
	if !ok {
		return nil, errors.New("fake kms: unknown key")
	}
	b, _ := aes.NewCipher(m)
	return cipher.NewGCM(b)
}

func (f *fakeKMS) GenerateDataKey(_ context.Context, id string) ([]byte, []byte, error) {
	g, err := f.aead(id)
	if err != nil {
		return nil, nil, err
	}
	dk := make([]byte, 32)
	rand.Read(dk)
	n := make([]byte, g.NonceSize())
	rand.Read(n)
	return dk, append(n, g.Seal(nil, n, dk, nil)...), nil
}

func (f *fakeKMS) Decrypt(_ context.Context, id string, w []byte) ([]byte, error) {
	g, err := f.aead(id)
	if err != nil {
		return nil, err
	}
	if len(w) < g.NonceSize() {
		return nil, errors.New("fake kms: short")
	}
	return g.Open(nil, w[:g.NonceSize()], w[g.NonceSize():], nil)
}

type memBlobs struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (b *memBlobs) Get(_ context.Context, name string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[name]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func (b *memBlobs) Create(_ context.Context, name string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.m == nil {
		b.m = map[string][]byte{}
	}
	if _, ok := b.m[name]; ok {
		return ErrExists
	}
	b.m[name] = data
	return nil
}

func (b *memBlobs) Delete(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, name)
	return nil
}

func TestSealOpen(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS("k1", "k2")
	s, err := Seal(ctx, k, "k1", "rec", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(ctx, k, "rec", s)
	if err != nil || string(pt) != "secret" {
		t.Fatalf("Open: %q %v", pt, err)
	}
	if bytes.Contains(s.Ciphertext, []byte("secret")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	if _, err := Open(ctx, k, "other", s); err != ErrOpen {
		t.Fatalf("other name: %v", err)
	}
	bad := *s
	bad.Ciphertext = append([]byte(nil), s.Ciphertext...)
	bad.Ciphertext[0] ^= 1
	if _, err := Open(ctx, k, "rec", &bad); err != ErrOpen {
		t.Fatalf("tampered: %v", err)
	}
	steered := *s
	steered.KeyID = "k2"
	if _, err := Open(ctx, k, "rec", &steered); err == nil {
		t.Fatal("opened under another KMS key")
	}
}

func TestLoadOrCreateKeepsIdentity(t *testing.T) {
	ctx := context.Background()
	k, blobs := newFakeKMS("k1"), &memBlobs{}
	a, err := LoadOrCreate(ctx, k, "k1", blobs, SecretsName, NewSecrets)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(ctx, k, "k1", blobs, SecretsName, func() (*Secrets, error) {
		t.Fatal("created again on restart")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ka, _ := peer.KeysFromSeeds(a.Peer)
	kb, _ := peer.KeysFromSeeds(b.Peer)
	if ka.Mailbox() != kb.Mailbox() || !bytes.Equal(a.EmailPepper, b.EmailPepper) || len(a.EmailPepper) != 32 {
		t.Fatal("identity changed across restart")
	}
	raw := blobs.m[SecretsName]
	if bytes.Contains(raw, a.EmailPepper) || bytes.Contains(raw, a.Peer.IK) {
		t.Fatal("secret visible in stored record")
	}
	var s Sealed
	if json.Unmarshal(raw, &s) != nil || s.KeyID != "k1" {
		t.Fatalf("stored record %s", raw)
	}
}

func TestLoadOrCreateRace(t *testing.T) {
	ctx := context.Background()
	k, blobs := newFakeKMS("k1"), &memBlobs{}
	var created atomic.Int32
	var wg sync.WaitGroup
	got := make([]*Secrets, 8)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := LoadOrCreate(ctx, k, "k1", blobs, SecretsName, func() (*Secrets, error) {
				created.Add(1)
				return NewSecrets()
			})
			if err != nil {
				t.Error(err)
			}
			got[i] = s
		}()
	}
	wg.Wait()
	for _, s := range got[1:] {
		if s == nil || !bytes.Equal(s.EmailPepper, got[0].EmailPepper) {
			t.Fatal("tasks ended with different secrets")
		}
	}
}
