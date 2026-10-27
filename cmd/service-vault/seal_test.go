package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
)

// Plaintext records are sealed only when the operator asks (the deploy
// that upgrades a deployment from before sealing). Otherwise one is
// refused, even on the start that creates the record key: deleting the
// key from the table, with forged plaintext records in place of the
// sealed ones, must not get them accepted.
func TestSealedStoreMigration(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	_ = inner.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}, {Kind: "admin_set", ID: "admins", Data: []byte(`{"admins":["c1"]}`)}})

	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, true, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, "conn"); !errors.Is(err, sealstore.ErrPlaintext) {
		t.Fatalf("plaintext accepted without the operator's migration: %v", err)
	}
	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, true, true, log); err != nil {
		t.Fatalf("migration: %v", err)
	}
	for _, k := range []string{"conn", "admin_set"} {
		recs, _ := inner.Load(ctx, k)
		if len(recs) != 1 || bytes.Contains(recs[0].Data, []byte(`c1`)) {
			t.Fatalf("%s not sealed", k)
		}
	}
	// The admin CLI never makes a record key.
	if _, err := sealedStore(ctx, plainKMS{}, "k", &memBlobs{m: map[string][]byte{}}, inner, nil, false, false, log); err == nil {
		t.Fatal("the CLI made a record key")
	}
}

// Every kind the service vault writes is in the migration's list.
func TestRecordKindsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range recordKinds() {
		if seen[k] {
			t.Fatalf("kind %q twice", k)
		}
		seen[k] = true
	}
	for _, k := range []string{"conn", "token", "msg", "email", "signin", "hook", "apv", "admin_set", "admin_boot", "audit", "apv_hook"} {
		if !seen[k] {
			t.Fatalf("kind %q missing", k)
		}
	}
}
