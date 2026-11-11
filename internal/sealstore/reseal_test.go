package sealstore

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// countingPager records the largest page it served. With short set, it
// serves at most short records a page, as a pager may before the end.
type countingPager struct {
	*peer.MemStore
	short          int
	largest, pages int
}

func (p *countingPager) Page(ctx context.Context, kind, after string, limit int) ([]peer.Record, error) {
	if p.short > 0 {
		limit = min(limit, p.short)
	}
	recs, err := p.MemStore.Page(ctx, kind, after, limit)
	p.pages++
	p.largest = max(p.largest, len(recs))
	return recs, err
}

// With a pager, Reseal moves every record of a kind to the current key a
// page at a time (never more than ResealPage), reading on until a page
// comes back empty: also past a full last page, and past short pages
// before the end.
func TestResealPaged(t *testing.T) {
	ctx := context.Background()
	type tc struct{ n, short, pages int }
	for _, c := range []tc{
		{0, 0, 1}, {1, 0, 2}, {ResealPage, 0, 2}, {2*ResealPage + 3, 0, 4},
		{2*ResealPage + 3, 7, 9}, // 53 records, 7 a page: 8 pages, then an empty one
	} {
		n := c.n
		mem := peer.NewMemStore()
		v1 := newStore(t, mem, false)
		for i := 0; i < n; i++ {
			if err := v1.Apply(ctx, []peer.Change{{Kind: "chunk", ID: fmt.Sprintf("c%03d", i), Data: []byte{byte(i)}}}); err != nil {
				t.Fatal(err)
			}
		}
		key2 := bytes.Repeat([]byte{7}, 32) // TEST ONLY
		both, err := New(mem, map[uint32][]byte{1: key, 2: key2}, 2, false)
		if err != nil {
			t.Fatal(err)
		}
		pager := &countingPager{MemStore: mem, short: c.short}
		both.Pages = pager
		if err := both.Reseal(ctx, []string{"chunk"}); err != nil {
			t.Fatal(err)
		}
		raw, _ := mem.Load(ctx, "chunk")
		if len(raw) != n {
			t.Fatalf("n=%d: %d records", n, len(raw))
		}
		for _, r := range raw {
			if !bytes.HasPrefix(r.Data, prefixV) || binary.BigEndian.Uint32(r.Data[4:]) != 2 {
				t.Fatalf("n=%d: %s not resealed", n, r.ID)
			}
		}
		if pager.largest > ResealPage || pager.pages != c.pages {
			t.Fatalf("n=%d short=%d: pages of up to %d, %d pages, want %d", n, c.short, pager.largest, pager.pages, c.pages)
		}
	}
}
