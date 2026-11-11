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
	delete(o2.Members, "c1") // a hit's copy
	if o3, _ := rs.OpenProposal(ctx, id); len(o3.Members) != len(f.open.Members) {
		t.Fatal("a caller's change reached the cache")
	}

	// Another proposal's record naming these chunks misses (the proposal
	// id is in the key) and is refused (ChunksOf), not served from the
	// cache.
	raw0, _, _ := st.Get(ctx, KindProposal, id)
	var rec0 map[string]json.RawMessage
	_ = json.Unmarshal(raw0, &rec0)
	other := "01JBQZ0000000000000000000B"
	if err := st.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: other, Data: raw0}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rs.OpenProposal(ctx, other); err == nil {
		t.Fatal("another proposal's chunks served")
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

	// Bounded: the least recently used is dropped; a get keeps one.
	var c membersCache
	for i := 0; i < membersCached; i++ {
		c.put(fmt.Sprint(i), map[string]Member{"c": {}})
	}
	_, _ = c.get("0")
	c.put("new", map[string]Member{"c": {}})
	has := func(k string) bool { m, _ := c.get(k); return m != nil }
	if !has("0") || has("1") || !has("new") || len(c.byKey) != membersCached {
		t.Fatalf("bound: %d kept", len(c.byKey))
	}
}

// The cache key covers the proposal, each chunk's id and each sum, each
// field with its length: moving a byte across a field boundary, or
// changing any field, gives another key.
func TestMembersKey(t *testing.T) {
	ref := func(id, sum string) chunkRef { return chunkRef{ID: id, Sum: []byte(sum)} }
	k := membersKey("p", []chunkRef{ref("ab", "c")})
	for name, other := range map[string]string{
		"id across":     membersKey("p", []chunkRef{ref("a", "bc")}),
		"proposal":      membersKey("q", []chunkRef{ref("ab", "c")}),
		"proposal into": membersKey("pa", []chunkRef{ref("b", "c")}),
		"chunk id":      membersKey("p", []chunkRef{ref("ax", "c")}),
		"sum":           membersKey("p", []chunkRef{ref("ab", "d")}),
		"another chunk": membersKey("p", []chunkRef{ref("ab", "c"), ref("", "")}),
		"split in two":  membersKey("p", []chunkRef{ref("a", ""), ref("b", "c")}),
	} {
		if other == k {
			t.Errorf("%s: same key", name)
		}
	}
	if membersKey("p", []chunkRef{ref("ab", "c")}) != k {
		t.Error("the same input, another key")
	}
}

// Opened through the cache, a proposal's record tree is built once and
// shared, and gives the same proofs as one built afresh.
func TestMembersCacheSharesTheTree(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	o1, err := m.Store.OpenProposal(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if len(o1.MemberChunks) == 0 {
		t.Skip("members inline: no cache")
	}
	o2, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	if o1.recordTree() != o2.recordTree() {
		t.Fatal("the tree built again")
	}
	fresh := &OpenProposal{Members: o1.Members}
	for _, mem := range o1.Members {
		a, err1 := o2.proofOf(mem.Tag)
		b, err2 := fresh.proofOf(mem.Tag)
		if err1 != nil || err2 != nil || a.Index != b.Index || a.TreeSize != b.TreeSize || fmt.Sprint(a.Path) != fmt.Sprint(b.Path) {
			t.Fatalf("proofs differ: %+v %+v %v %v", a, b, err1, err2)
		}
	}
}
