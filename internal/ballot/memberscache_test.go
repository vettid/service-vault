package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// countingStore counts the chunk reads under a store.
type countingStore struct {
	*peer.MemStore
	chunkGets int
}

func (c *countingStore) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if kind == KindChunk {
		c.chunkGets++
	}
	return c.MemStore.Get(ctx, kind, id)
}

// A proposal opened again reads no chunk: its members come from the
// cache, each caller with its own copy. A record naming other chunks, or
// the same with another sum, is read and checked again. The cache keeps
// at most membersCached proposals. ProposalDocument reads no chunk.
func TestMembersCache(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	st := &countingStore{MemStore: peer.NewMemStore()}
	rs := &RecordStore{Records: st, Copy: &MemCopy{}}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	id := f.p.ProposalID
	o1, err := rs.OpenProposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	reads := st.chunkGets
	if reads == 0 {
		t.Fatal("the first open read no chunk")
	}
	o2, err := rs.OpenProposal(ctx, id)
	if err != nil || st.chunkGets != reads || len(o2.Members) != len(f.open.Members) {
		t.Fatalf("second open: %v, %d chunk reads", err, st.chunkGets-reads)
	}
	if !bytes.Equal(o2.Members["c0"].Tag, f.open.Members["c0"].Tag) {
		t.Fatal("cached members differ")
	}
	delete(o1.Members, "c0")
	if o3, _ := rs.OpenProposal(ctx, id); len(o3.Members) != len(f.open.Members) {
		t.Fatal("a caller's change reached the cache")
	}

	// The record names a chunk with another sum: a miss, read and refused.
	raw, _, _ := st.Get(ctx, KindProposal, id)
	var rec map[string]json.RawMessage
	_ = json.Unmarshal(raw, &rec)
	var refs []chunkRef
	_ = json.Unmarshal(rec["member_chunks"], &refs)
	refs[0].Sum = bytes.Repeat([]byte{1}, 32)
	rec["member_chunks"], _ = json.Marshal(refs)
	bad, _ := json.Marshal(rec)
	if err := st.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: id, Data: bad}}); err != nil {
		t.Fatal(err)
	}
	before := st.chunkGets
	if _, err := rs.OpenProposal(ctx, id); err == nil || st.chunkGets == before {
		t.Fatalf("another sum: %v, %d chunk reads", err, st.chunkGets-before)
	}

	// ProposalDocument: the document, no chunk read.
	before = st.chunkGets
	if p, err := rs.ProposalDocument(ctx, id); err != nil || p.ProposalID != id || st.chunkGets != before {
		t.Fatalf("ProposalDocument: %v, %d chunk reads", err, st.chunkGets-before)
	}
	if p, err := rs.ProposalDocument(ctx, "01JBQZ00000000000000000000"); err != nil || p != nil {
		t.Fatalf("unknown proposal: %v %v", p, err)
	}

	// Bounded: the oldest is dropped.
	var c membersCache
	for i := 0; i <= membersCached; i++ {
		c.put(fmt.Sprint(i), map[string]Member{"c": {}})
	}
	if c.get("0") != nil || c.get(fmt.Sprint(membersCached)) == nil || len(c.byKey) != membersCached {
		t.Fatalf("bound: %d kept", len(c.byKey))
	}
}
