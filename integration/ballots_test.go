//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

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
	if _, err := b.PutOnce(ctx, "_skip", []byte{0}, []byte("check")); err != nil {
		t.Fatal(err)
	}
	if _, _, ok, err := b.Any(ctx, "_skip"); err != nil || ok {
		t.Fatalf("Any with only the skipped partition: %v %v", ok, err)
	}
	if got, err := b.PutOnce(ctx, "p", []byte{0xaa}, []byte("first")); err != nil || string(got) != "first" {
		t.Fatalf("PutOnce: %q %v", got, err)
	}
	if got, err := b.PutOnce(ctx, "p", []byte{0xaa}, []byte("second")); err != nil || string(got) != "first" {
		t.Fatalf("PutOnce replaced: %q %v", got, err)
	}
	pid, it, ok, err := b.Any(ctx, "_skip")
	if err != nil || !ok || pid != "p" || string(it.Tag) != "\xaa" || string(it.Data) != "first" {
		t.Fatalf("Any: %q %x %q %v %v", pid, it.Tag, it.Data, ok, err)
	}
}
