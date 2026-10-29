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

	"github.com/vettid/service-vault/internal/ballot"
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
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", blobs, keystore.SecretsName, newSecretsIfFresh(ctx, has, memAnyRecordKey(blobs))); err != nil {
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
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", lost, keystore.SecretsName, newSecretsIfFresh(ctx, has, memAnyRecordKey(lost))); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again over records: %v", err)
	}
	// Nor over a record key alone (its records may all have been deleted).
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", lost, keystore.SecretsName, newSecretsIfFresh(ctx, memAnyRecord(peer.NewMemStore()), memAnyRecordKey(lost))); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again beside a record key: %v", err)
	}
	// Any version of it.
	later := &memBlobs{m: map[string][]byte{sealstore.KeyNameOf(3): []byte("k")}}
	if _, err := keystore.LoadOrCreate(ctx, plainKMS{}, "k", later, keystore.SecretsName, newSecretsIfFresh(ctx, memAnyRecord(peer.NewMemStore()), memAnyRecordKey(later))); !errors.Is(err, errKeysLost) {
		t.Fatalf("secrets made again beside a later record key: %v", err)
	}
}

// Rotating the record key: the start with a higher version makes it and
// reseals every record under it; the next start reseals what was written
// under the older versions since (an admin run that read the version
// before) and deletes them. Later starts do nothing more, whatever the
// setting; a start cut short goes on, also from a task with an older
// setting (a rollback). A version can't be skipped over records, a
// planted version doesn't make the start probe without end, and the
// admin CLI never makes a version.
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
	stale, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), false, 1, false, log) // an admin run, before the rotation
	if err != nil {
		t.Fatal(err)
	}

	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), false, 2, false, log); err == nil {
		t.Fatal("the CLI made a record key version")
	}
	if _, err := start(3); err == nil || !strings.Contains(err.Error(), "skips a version") {
		t.Fatalf("a skipped version: %v", err)
	}
	if _, err := start(2); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.m[sealstore.KeyName]; !ok {
		t.Fatal("version 1 retired by the start that made version 2")
	}
	for _, k := range []string{"conn", "audit"} {
		raw, _ := inner.Load(ctx, k)
		if len(raw) != 1 || sealstore.VersionOf(raw[0].Data) != 2 {
			t.Fatalf("%s not under version 2", k)
		}
	}
	// The admin run writes under version 1 after the reseal.
	_ = stale.Apply(ctx, []peer.Change{{Kind: "admin_boot", ID: "b", Data: []byte(`{}`)}})
	if _, err := start(1); err != nil { // the setting left out
		t.Fatal(err)
	}
	if _, ok := blobs.m[sealstore.KeyName]; ok {
		t.Fatal("version 1 not retired")
	}
	if !bytes.Contains(logs.Bytes(), []byte("record key rotated")) {
		t.Fatal("no rotation log")
	}
	if raw, _, _ := inner.Get(ctx, "admin_boot", "b"); sealstore.VersionOf(raw) != 2 {
		t.Fatal("the admin run's record not resealed before the retirement")
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
	_ = cli.Apply(ctx, []peer.Change{{Kind: "admin_boot", ID: "b2", Data: []byte(`{}`)}})
	if raw, _, _ := inner.Get(ctx, "admin_boot", "b2"); sealstore.VersionOf(raw) != 2 {
		t.Fatal("the CLI wrote under an older version")
	}
	// The migration with an older setting makes no older version.
	if _, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, true, log); err != nil {
		t.Fatal(err)
	}
	if _, ok := blobs.m[sealstore.KeyName]; ok {
		t.Fatal("version 1 made again under the migration")
	}
	if _, err := start(4); err == nil || !strings.Contains(err.Error(), "skips a version") {
		t.Fatalf("a skipped version after a retirement: %v", err)
	}

	// Cut short: version 3 made, version 2 still there, one record moved.
	// A task with the older setting (a rollback) finishes the reseal; the
	// start after retires version 2.
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

	// A planted record under a huge version: refused at once.
	first := recordKinds()[0] // the one memAnyRecord samples first
	_ = inner.Apply(ctx, []peer.Change{{Kind: first, ID: "0", Data: append([]byte("vsr2\xff\xff\xff\xff"), make([]byte, 40)...)}})
	if _, err := start(3); !errors.Is(err, errKeysLost) {
		t.Fatalf("a planted version: %v", err)
	}
	_ = inner.Apply(ctx, []peer.Change{{Kind: first, ID: "0"}})

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

// memAnyRecordKey is store.Table.AnyBlob(sealstore.KeyName) over memBlobs.
func memAnyRecordKey(b *memBlobs) func(context.Context) (bool, error) {
	return func(context.Context) (bool, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		for name := range b.m {
			if strings.HasPrefix(name, sealstore.KeyName) {
				return true, nil
			}
		}
		return false, nil
	}
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

// The write-once ballot copy is sealed under a key of its own: a ballot
// written before a rotation of the record key still opens after it, once
// the older record key versions are gone. Vote records in the table are
// resealed with the rest. A lost copy key is not made again over
// proposals.
func TestBallotCopySurvivesRotation(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	start := func(version uint32) *sealstore.Store {
		t.Helper()
		st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, version, false, log)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := start(1)
	cp := &ballot.MemCopy{}
	cs, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp)
	if err != nil {
		t.Fatal(err)
	}
	item, err := cs.Seal(ballot.KindBallot, "p|aa", []byte(`{"ballot":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: ballot.KindProposal, ID: "p", Data: []byte(`{"doc":"x"}`)}}); err != nil {
		t.Fatal(err)
	}
	start(2)      // rotate: reseal under 2
	st = start(2) // retire version 1
	if _, err := blobs.Get(ctx, sealstore.KeyNameOf(1)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("record key version 1 not retired: %v", err)
	}
	if got, ok, err := st.Get(ctx, ballot.KindProposal, "p"); err != nil || !ok || string(got) != `{"doc":"x"}` {
		t.Fatalf("a proposal after the rotation: %s %v %v", got, ok, err)
	}
	cs, err = ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := cs.Open(ballot.KindBallot, "p|aa", item); err != nil || string(got) != `{"ballot":1}` {
		t.Fatalf("a copied ballot after the rotation: %s %v", got, err)
	}
	delete(blobs.m, keystore.BallotCopyKeyName)
	var ck *errCopyKey
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); !errors.As(err, &ck) {
		t.Fatalf("a new copy key made over proposals: %v", err)
	}
}

// The copy's key check ties the key to the copy: a lost key isn't made
// again over a copy that has a check, even with no proposals in the
// table (a restore of the table from before the key), and another key
// is refused. Either is errCopyKey: the daemon runs with ballots off.
func TestBallotCopyKeyCheck(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	st, err := sealedStore(ctx, plainKMS{}, "k", blobs, inner, nil, memAnyRecord(inner), true, 1, false, log)
	if err != nil {
		t.Fatal(err)
	}
	cp := &ballot.MemCopy{}
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); err != nil {
		t.Fatal(err)
	}
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); err != nil {
		t.Fatalf("the same key again: %v", err)
	}
	var ck *errCopyKey
	saved := blobs.m[keystore.BallotCopyKeyName]
	delete(blobs.m, keystore.BallotCopyKeyName)
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); !errors.As(err, &ck) {
		t.Fatalf("a new key over a checked copy: %v", err)
	}
	if _, ok := blobs.m[keystore.BallotCopyKeyName]; ok {
		t.Fatal("a key was made over a checked copy")
	}
	// Another key in the keystore: its check doesn't match the copy's.
	other := &memBlobs{m: map[string][]byte{}}
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", other, st, &ballot.MemCopy{}); err != nil {
		t.Fatal(err)
	}
	blobs.m[keystore.BallotCopyKeyName] = other.m[keystore.BallotCopyKeyName]
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); !errors.As(err, &ck) {
		t.Fatalf("another key over the copy: %v", err)
	}
	blobs.m[keystore.BallotCopyKeyName] = saved
	if _, err := ballotCopySeal(ctx, plainKMS{}, "k", blobs, st, cp); err != nil {
		t.Fatalf("the key restored: %v", err)
	}
}
