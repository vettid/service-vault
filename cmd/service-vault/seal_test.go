package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"testing"

	"github.com/vettid/service-vault/internal/keystore"
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

	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memHasRecords(inner), false, log); !errors.Is(err, errKeysLost) {
		t.Fatalf("a record key made over plaintext records without the operator's migration: %v", err)
	}
	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memHasRecords(inner), true, log); err != nil {
		t.Fatalf("migration: %v", err)
	}
	for _, k := range []string{"conn", "admin_set"} {
		recs, _ := inner.Load(ctx, k)
		if len(recs) != 1 || bytes.Contains(recs[0].Data, []byte(`c1`)) {
			t.Fatalf("%s not sealed", k)
		}
	}
	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memHasRecords(inner), false, log)
	if err != nil {
		t.Fatal(err)
	}
	// A plaintext record written after sealing is refused.
	_ = inner.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c2", Data: []byte(`{"id":"c2"}`)}})
	if _, err := st.Load(ctx, "conn"); !errors.Is(err, sealstore.ErrPlaintext) {
		t.Fatalf("plaintext accepted after sealing: %v", err)
	}
	// The admin CLI never makes a record key.
	if _, err := sealedStore(ctx, plainKMS{}, "k", &memBlobs{m: map[string][]byte{}}, inner, nil, nil, false, log); err == nil {
		t.Fatal("the CLI made a record key")
	}
}

// A key missing from a table that holds records is never made again: a
// new record key would leave the records unreadable, new secrets would
// replace the service's identity. A new deployment makes both.
func TestKeysNotRemadeOverRecords(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	has := memHasRecords(inner)

	// A new deployment: the secrets, then the record key, then records.
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", blobs, keystore.SecretsName, newSecretsIfFresh(ctx, blobs, has)); err != nil {
		t.Fatal(err)
	}
	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, has, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}}); err != nil {
		t.Fatal(err)
	}

	lost := &memBlobs{m: maps.Clone(blobs.m)}
	delete(lost.m, sealstore.KeyName)
	if _, err := sealedStore(ctx, plainKMS{}, "k", lost, inner, nil, has, false, log); !errors.Is(err, errKeysLost) {
		t.Fatalf("record key made again over records: %v", err)
	}
	if _, ok := lost.m[sealstore.KeyName]; ok {
		t.Fatal("record key written")
	}

	lost = &memBlobs{m: maps.Clone(blobs.m)}
	delete(lost.m, keystore.SecretsName)
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", lost, keystore.SecretsName, newSecretsIfFresh(ctx, lost, has)); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again over records: %v", err)
	}
	// Nor over a record key alone (its records may all have been deleted).
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", lost, keystore.SecretsName, newSecretsIfFresh(ctx, lost, memHasRecords(peer.NewMemStore()))); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again beside a record key: %v", err)
	}
}

// memHasRecords is store.Table.HasRecords over a MemStore.
func memHasRecords(st peer.Store) func(context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		for _, k := range recordKinds() {
			recs, err := st.Load(ctx, k)
			if err != nil || len(recs) > 0 {
				return len(recs) > 0, err
			}
		}
		return false, nil
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
