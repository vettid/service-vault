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

// The start that creates the record key seals the records found in the
// clear; later starts refuse one in the clear (slipped into the table),
// unless the operator asks for a migration.
func TestSealedPeerStoreMigration(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blobs, inner := &memBlobs{m: map[string][]byte{}}, peer.NewMemStore()
	_ = inner.Apply(ctx, []peer.Change{{Kind: "conn", ID: "c1", Data: []byte(`{"id":"c1"}`)}})

	st, err := sealedPeerStore(ctx, plainKMS{}, "k", blobs, inner, false, log)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	if raw, _, _ := inner.Get(ctx, "conn", "c1"); bytes.Contains(raw, []byte(`"c1"`)) {
		t.Fatal("not sealed on the first start")
	}
	if st.Legacy {
		t.Fatal("still accepting plaintext after the migration")
	}

	_ = inner.Apply(ctx, []peer.Change{{Kind: "conn", ID: "forged", Data: []byte(`{"id":"forged"}`)}})
	st, err = sealedPeerStore(ctx, plainKMS{}, "k", blobs, inner, false, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Load(ctx, "conn"); !errors.Is(err, sealstore.ErrPlaintext) {
		t.Fatalf("a plaintext record was accepted: %v", err)
	}
	if _, err := sealedPeerStore(ctx, plainKMS{}, "k", blobs, inner, true, log); err != nil {
		t.Fatalf("the operator's migration: %v", err)
	}
}
