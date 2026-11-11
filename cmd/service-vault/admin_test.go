package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/peer"
)

// plainKMS "wraps" a data key by copying it: enough to exercise the
// keystore path, nothing more.
type plainKMS struct{}

func (plainKMS) GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, nil, err
	}
	return k, bytes.Clone(k), nil
}

func (plainKMS) Decrypt(_ context.Context, _ string, w []byte, _ map[string]string) ([]byte, error) {
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

func (b *memBlobs) Replace(_ context.Context, name string, old, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v, ok := b.m[name]
	switch {
	case !ok:
		return keystore.ErrNotFound
	case !bytes.Equal(v, old):
		return keystore.ErrChanged
	}
	b.m[name] = data
	return nil
}

func (b *memBlobs) List(context.Context) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.m))
	for k := range b.m {
		out = append(out, k)
	}
	return out, nil
}

func (b *memBlobs) Delete(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.m, name)
	return nil
}

// admin reseal-blobs takes no arguments; it reports the items' names,
// never what they hold.
func TestResealBlobs(t *testing.T) {
	if err := admin([]string{"reseal-blobs", "extra"}, &bytes.Buffer{}); err == nil {
		t.Error("reseal-blobs with an argument accepted")
	}
	ctx := context.Background()
	b := &memBlobs{m: map[string][]byte{}}
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", b, keystore.SecretsName, keystore.NewSecrets); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resealBlobs(ctx, plainKMS{}, "k", b, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), keystore.SecretsName) || strings.Contains(out.String(), "pepper") ||
		strings.Contains(out.String(), "INCOMPLETE") {
		t.Fatalf("report: %s", out.String())
	}
	// A record that doesn't open: the run says it is incomplete.
	b.m["broken"] = []byte("{")
	out.Reset()
	if err := resealBlobs(ctx, plainKMS{}, "k", b, &out); err == nil || !strings.Contains(out.String(), "INCOMPLETE") {
		t.Fatalf("a failed run: %v %s", err, out.String())
	}
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
	m := &approval.Manager{Store: st, Peer: ikPeer{}, BoundConnection: func(context.Context, string) (string, bool, error) { return "c1", true, nil }}
	if err := m.ConnectionAdded(ctx, "c1", key, true); err != nil {
		t.Fatal(err)
	}
	// The connection waits for the operator, who is shown its fingerprint.
	if a, _ := m.Admins(ctx); len(a.Admins) != 0 {
		t.Fatalf("admins before the confirmation: %v", a.Admins)
	}
	out.Reset()
	if err := confirmBootstrap(ctx, st, "c1", "", &out); err != nil || !strings.Contains(out.String(), "connection: c1") ||
		!strings.Contains(out.String(), "connected: 2026-11-02 09:30:00 UTC") || !strings.Contains(out.String(), "invitation: inv1") {
		t.Fatalf("show: %v %q", err, out.String())
	}
	_, fp, _ := m.BootstrapPending(ctx)
	if err := confirmBootstrap(ctx, st, "c1", "0000000000000000", &out); err == nil {
		t.Fatal("confirmed with a wrong fingerprint")
	}
	if err := confirmBootstrap(ctx, st, "c1", fp, &out); err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
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

// ikPeer knows every connection, with an identity key.
type ikPeer struct{}

func (ikPeer) Connection(id string) (peer.ConnectionInfo, bool) {
	return peer.ConnectionInfo{ID: id, State: peer.StateActive, IK: bytes.Repeat([]byte{1}, 32), InviteID: "inv1",
		Activated: time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)}, true
}
func (ikPeer) Authenticate(context.Context, string, string, string, time.Duration) (string, error) {
	return "r", nil
}
func (ikPeer) CancelChallenge(context.Context, string) (bool, error)      { return true, nil }
func (ikPeer) PinGov(context.Context, string, []byte, bool) (bool, error) { return true, nil }
func (ikPeer) RepinGov(context.Context, string, []byte) (bool, error)     { return true, nil }
