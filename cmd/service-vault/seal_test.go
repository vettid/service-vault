package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"strings"
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

	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, false, log); !errors.Is(err, errKeysLost) {
		t.Fatalf("a record key made over plaintext records without the operator's migration: %v", err)
	}
	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, true, log); err != nil {
		t.Fatalf("migration: %v", err)
	}
	for _, k := range []string{"conn", "admin_set"} {
		recs, _ := inner.Load(ctx, k)
		if len(recs) != 1 || bytes.Contains(recs[0].Data, []byte(`c1`)) {
			t.Fatalf("%s not sealed", k)
		}
	}
	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, false, log)
	if err != nil {
		t.Fatal(err)
	}
	// A plaintext record written after sealing is refused.
	_ = inner.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c2", Data: []byte(`{"id":"c2"}`)}})
	if _, err := st.Load(ctx, "conn"); !errors.Is(err, sealstore.ErrPlaintext) {
		t.Fatalf("plaintext accepted after sealing: %v", err)
	}
	// The admin CLI never makes a record key.
	if _, err := sealedStore(ctx, plainKMS{}, "k", &memBlobs{m: map[string][]byte{}}, inner, nil, memAnyRecord(inner), false, 1, false, log); err == nil {
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
	has := memAnyRecord(inner)

	// A new deployment: the secrets, then the record key, then records.
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", blobs, keystore.SecretsName, newSecretsIfFresh(ctx, blobs, has)); err != nil {
		t.Fatal(err)
	}
	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, has, true, 1, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}}); err != nil {
		t.Fatal(err)
	}

	lost := &memBlobs{m: maps.Clone(blobs.m)}
	delete(lost.m, sealstore.KeyName)
	if _, err := sealedStore(ctx, plainKMS{}, "k", lost, inner, nil, has, true, 1, false, log); !errors.Is(err, errKeysLost) {
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
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", lost, keystore.SecretsName, newSecretsIfFresh(ctx, lost, memAnyRecord(peer.NewMemStore()))); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again beside a record key: %v", err)
	}
}

// Rotating the record key: the start with a higher version makes it,
// reseals every record under it and deletes the older versions; a restart
// does nothing more, whatever the setting; a start cut short goes on,
// also from a task with an older setting (a rollback). A version can't be
// skipped over records, and the admin CLI never makes one.
func TestRecordKeyRotation(t *testing.T) {
	ctx := context.Background()
	logs := &bytes.Buffer{}
	log := slog.New(slog.NewTextHandler(logs, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	start := func(version uint32) (*sealstore.Store, error) {
		return sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, version, false, log)
	}
	st, err := start(1)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}, {Kind: "audit", ID: "a1", Data: []byte(`{"e":1}`)}})

	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), false, 2, false, log); err == nil {
		t.Fatal("the CLI made a record key version")
	}
	if _, err := start(3); err == nil || !strings.Contains(err.Error(), "skips a version") {
		t.Fatalf("a skipped version: %v", err)
	}
	if _, err := start(2); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.m[sealstore.KeyName]; ok {
		t.Fatal("version 1 not retired")
	}
	if !bytes.Contains(logs.Bytes(), []byte("record key rotated")) {
		t.Fatal("no rotation log")
	}
	for _, k := range []string{"conn", "audit"} {
		raw, _ := inner.Load(ctx, k)
		if len(raw) != 1 || sealstore.VersionOf(raw[0].Data) != 2 {
			t.Fatalf("%s not under version 2", k)
		}
	}
	// The setting left out or lowered: the table's version is used.
	for _, v := range []uint32{2, 1} {
		logs.Reset()
		st, err := start(v)
		if err != nil || bytes.Contains(logs.Bytes(), []byte("rotated")) {
			t.Fatalf("restart at %d: %v %s", v, err, logs)
		}
		if got, _, err := st.Get(ctx, "conn", "c1"); err != nil || string(got) != `{"id":"c1"}` {
			t.Fatalf("after rotation: %q %v", got, err)
		}
	}
	// So does the admin CLI with an older setting, and it writes under it.
	cli, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), false, 1, false, log)
	if err != nil {
		t.Fatal(err)
	}
	_ = cli.Apply(ctx, []peer.Change{{Kind: "admin_boot", ID: "b", Data: []byte(`{}`)}})
	if raw, _, _ := inner.Get(ctx, "admin_boot", "b"); sealstore.VersionOf(raw) != 2 {
		t.Fatal("the CLI wrote under an older version")
	}

	// The migration with an older setting makes no older version.
	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, true, log); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.m[sealstore.KeyName]; ok {
		t.Fatal("version 1 made again under the migration")
	}

	// Cut short: version 3 made, version 2 still there, one record moved.
	// A task with the older setting (a rollback) finishes the rotation.
	k3, _ := sealstore.NewRecordKey()
	pt, _ := json.Marshal(k3)
	sealed, _ := keystore.Seal(ctx, plainKMS{}, "k", sealstore.KeyNameOf(3), pt)
	raw, _ := json.Marshal(sealed)
	_ = blobs.Create(ctx, sealstore.KeyNameOf(3), raw)
	partial, _ := sealstore.New(inner, map[uint32][]byte{3: k3.Key}, 3, false)
	_ = partial.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c2", Data: []byte(`{"id":"c2"}`)}})
	if st, err = start(2); err != nil {
		t.Fatalf("rotation cut short: %v", err)
	}
	if _, ok := blobs.m[sealstore.KeyNameOf(2)]; ok {
		t.Fatal("version 2 not retired")
	}
	if recs, err := st.Load(ctx, "conn"); err != nil || len(recs) != 2 || sealstore.VersionOf(mustRaw(t, inner, "c1")) != 3 {
		t.Fatalf("after the rotation went on: %v %v", recs, err)
	}

	// The current version lost from a table with records: refused.
	delete(blobs.m, sealstore.KeyNameOf(3))
	if _, err := start(3); !errors.Is(err, errKeysLost) {
		t.Fatalf("a lost version made over records: %v", err)
	}
}

func mustRaw(t *testing.T, st peer.Store, id string) []byte {
	t.Helper()
	raw, _, err := st.Get(context.Background(), "conn", id)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// memAnyRecord is store.Table.AnyRecord over a MemStore.
func memAnyRecord(st peer.Store) func(context.Context) ([]byte, bool, error) {
	return func(ctx context.Context) ([]byte, bool, error) {
		for _, k := range recordKinds() {
			recs, err := st.Load(ctx, k)
			if err != nil || len(recs) > 0 {
				if err != nil {
					return nil, false, err
				}
				return recs[0].Data, true, nil
			}
		}
		return nil, false, nil
	}
}
