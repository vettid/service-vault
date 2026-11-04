//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/store"
)

// The ballots' copy: a put never replaces, and Any finds a ballot of any
// proposal but the one it skips.
func TestBallotsCopyOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx) // the same keys as the ballots table
	b := &store.Ballots{Client: tbl.Client, Name: tbl.Name}

	if _, _, ok, err := b.Any(ctx, "_skip"); err != nil || ok {
		t.Fatalf("Any on an empty copy: %v %v", ok, err)
	}
	if _, err := b.PutOnce(ctx, "_skip", []byte{0}, []byte("check"), nil); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := b.Any(ctx, "_skip"); err != nil || ok {
		t.Fatalf("Any with only the skipped partition: %v %v", ok, err)
	}
	if got, err := b.PutOnce(ctx, "p", []byte{0xaa}, []byte("first"), nil); err != nil || string(got) != "first" {
		t.Fatalf("PutOnce: %q %v", got, err)
	}
	if got, err := b.PutOnce(ctx, "p", []byte{0xaa}, []byte("second"), nil); err != nil || string(got) != "first" {
		t.Fatalf("PutOnce replaced: %q %v", got, err)
	}
	pid, it, ok, err := b.Any(ctx, "_skip")
	if err != nil || !ok || pid != "p" || string(it.Tag) != "\xaa" || string(it.Data) != "first" {
		t.Fatalf("Any: %q %x %q %v %v", pid, it.Tag, it.Data, ok, err)
	}
}

// A guarded put is one transaction with a check of the main table's
// record version: a stale version writes nothing, a current one writes,
// and an item already there is returned whatever the guard says.
func TestBallotsGuardedPutOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	main := newTable(t, ctx)
	recs := main.Peer()
	b := &store.Ballots{Client: main.Client, Name: newTable(t, ctx).Name, Main: main}
	if err := recs.Apply(ctx, []peer.Change{{Kind: ballot.KindProposal, ID: "p", Data: []byte("1"), IfAbsent: true}}); err != nil {
		t.Fatal(err)
	}
	stale := &ballot.Guard{Kind: ballot.KindProposal, ID: "p", Version: 2}
	if _, err := b.PutOnce(ctx, "p", []byte{1}, []byte("a"), stale); !errors.Is(err, ballot.ErrGuard) {
		t.Fatalf("a stale guard: %v", err)
	}
	if _, ok, err := b.Get(ctx, "p", []byte{1}); err != nil || ok {
		t.Fatalf("a refused put wrote: %v %v", ok, err)
	}
	if _, err := b.PutOnce(ctx, "p", []byte{1}, []byte("a"), &ballot.Guard{Kind: ballot.KindProposal, ID: "none", Version: 1}); !errors.Is(err, ballot.ErrGuard) {
		t.Fatalf("a guard on a missing record: %v", err)
	}
	current := &ballot.Guard{Kind: ballot.KindProposal, ID: "p", Version: 1}
	if got, err := b.PutOnce(ctx, "p", []byte{1}, []byte("a"), current); err != nil || string(got) != "a" {
		t.Fatalf("a current guard: %q %v", got, err)
	}
	if got, ok, err := b.Get(ctx, "p", []byte{1}); err != nil || !ok || string(got) != "a" {
		t.Fatalf("Get: %q %v %v", got, ok, err)
	}
	// The item is there: its bytes come back, with a current or a stale guard.
	for _, g := range []*ballot.Guard{current, stale} {
		if got, err := b.PutOnce(ctx, "p", []byte{1}, []byte("b"), g); err != nil || string(got) != "a" {
			t.Fatalf("a put over an item: %q %v", got, err)
		}
	}
	// The record changes: the old guard no longer writes.
	if err := recs.Apply(ctx, []peer.Change{{Kind: ballot.KindProposal, ID: "p", Data: []byte("2"), IfVersion: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.PutOnce(ctx, "p", []byte{2}, []byte("c"), current); !errors.Is(err, ballot.ErrGuard) {
		t.Fatalf("after the record changed: %v", err)
	}
	if got, err := b.PutOnce(ctx, "p", []byte{2}, []byte("c"), &ballot.Guard{Kind: ballot.KindProposal, ID: "p", Version: 2}); err != nil || string(got) != "c" {
		t.Fatalf("the new version: %q %v", got, err)
	}
}
