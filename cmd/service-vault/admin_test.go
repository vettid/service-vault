package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
)

// plainKMS "wraps" a data key by copying it: enough to exercise the
// keystore path, nothing more.
type plainKMS struct{}

func (plainKMS) GenerateDataKey(context.Context, string) ([]byte, []byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, err
	}
	return k, bytes.Clone(k), nil
}

func (plainKMS) Decrypt(_ context.Context, _ string, w []byte) ([]byte, error) {
	return bytes.Clone(w), nil
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
		return nil, keystore.ErrNotFound
	}
	return v, nil
}

func (b *memBlobs) Create(_ context.Context, name string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.m[name]; ok {
		return keystore.ErrExists
	}
	b.m[name] = data
	return nil
}

func TestAdminUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"other"}, {"bootstrap"}, {"bootstrap", "-email", "nope"},
		{"bootstrap", "-email", "a@example.org", "extra"}} {
		if err := admin(args, &bytes.Buffer{}); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

// admin bootstrap arms a one-shot bootstrap for the email's index key
// under the service vault's own pepper; it never makes keys, and it is
// refused while the admin set is not empty.
func TestArmBootstrap(t *testing.T) {
	ctx := context.Background()
	blobs, st := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	var out bytes.Buffer
	if err := armBootstrap(ctx, plainKMS{}, "k", blobs, st, "admin@example.org", &out); !errors.Is(err, errNoSecrets) {
		t.Fatalf("no keystore: %v", err)
	}
	if len(blobs.m) != 0 {
		t.Fatal("the admin command made keys")
	}
	secrets, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", blobs, keystore.SecretsName, keystore.NewSecrets)
	if err != nil {
		t.Fatal(err)
	}
	if err := armBootstrap(ctx, plainKMS{}, "k", blobs, st, " Admin@Example.org ", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "armed") || strings.Contains(out.String(), "example.org") {
		t.Fatalf("output %q", out.String())
	}
	idx, _ := connect.NewEmailIndex(secrets.EmailPepper)
	key, _ := idx.Key("admin@example.org")
	m := &approval.Manager{Store: st}
	if err := m.ConnectionAdded(ctx, "c1", key, true); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.Admins(ctx); len(a.Admins) != 1 || a.Admins[0] != "c1" {
		t.Fatalf("admins %v", a.Admins)
	}
	err = armBootstrap(ctx, plainKMS{}, "k", blobs, st, "admin@example.org", &out)
	if err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("armed with admins: %v", err)
	}
}
