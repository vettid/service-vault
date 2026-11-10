package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

func bigValue(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// A value is written in chunks of at most ChunkSize and read back whole,
// in order; chunk ids show nothing of the value and start with the
// proposal's id.
func TestChunksRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := peer.NewMemStore()
	v := bigValue(3*ChunkSize + 5)
	refs, err := putChunks(ctx, st, "p1", v, 8)
	if err != nil || len(refs) != 4 {
		t.Fatalf("put: %d refs, %v", len(refs), err)
	}
	for _, r := range refs {
		if !ChunksOf("p1", r.ID) || ChunksOf("p", r.ID) || len(r.ID) != len("p1|")+32 {
			t.Errorf("chunk id %q", r.ID)
		}
	}
	got, err := getChunks(ctx, st, "p1", refs, 8)
	if err != nil || !bytes.Equal(got, v) {
		t.Fatalf("get: %d bytes, %v", len(got), err)
	}
	// The same value again: new chunks, the old ones untouched.
	refs2, err := putChunks(ctx, st, "p1", v, 8)
	if err != nil || refs2[0].ID == refs[0].ID {
		t.Fatalf("second put: %v", err)
	}
	if _, err := putChunks(ctx, st, "p1", bigValue(4*ChunkSize+1), 4); err == nil {
		t.Error("a value past its chunk bound was written")
	}
}

// A chunk missing, swapped with another, of another proposal, or a list
// longer than maxChunks is an error, never a shorter value.
func TestChunksRefused(t *testing.T) {
	ctx := context.Background()
	st := peer.NewMemStore()
	refs, err := putChunks(ctx, st, "p1", bigValue(2*ChunkSize), 8)
	if err != nil {
		t.Fatal(err)
	}
	get := func(k string, id string) []byte {
		d, ok, err := st.Get(ctx, k, id)
		if err != nil || !ok {
			t.Fatal("chunk not stored")
		}
		return d
	}
	a, b := get(KindChunk, refs[0].ID), get(KindChunk, refs[1].ID)
	swapped := []peer.Change{{Kind: KindChunk, ID: refs[0].ID, Data: b}, {Kind: KindChunk, ID: refs[1].ID, Data: a}}
	if err := st.Apply(ctx, swapped); err != nil {
		t.Fatal(err)
	}
	if _, err := getChunks(ctx, st, "p1", refs, 8); !errors.Is(err, ErrChunkBad) {
		t.Errorf("swapped: %v", err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: refs[0].ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := getChunks(ctx, st, "p1", refs, 8); !errors.Is(err, ErrChunkMissing) {
		t.Errorf("missing: %v", err)
	}
	other, _ := putChunks(ctx, st, "p2", []byte("x"), 8)
	if _, err := getChunks(ctx, st, "p1", other, 8); !errors.Is(err, ErrChunkBad) {
		t.Errorf("another proposal's: %v", err)
	}
	// A list longer than the bound, of intact chunks that would read
	// whole: refused for its length alone.
	intact, err := putChunks(ctx, st, "p3", bigValue(3*ChunkSize), 8)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := getChunks(ctx, st, "p3", intact, 3); err != nil || len(v) != 3*ChunkSize {
		t.Fatalf("at the bound: %v", err)
	}
	if _, err := getChunks(ctx, st, "p3", intact, 2); !errors.Is(err, ErrChunkBad) {
		t.Errorf("too many: %v", err)
	}
}

// The bounds follow MaxEligible.
func TestChunkBounds(t *testing.T) {
	if maxMemberChunks*ChunkSize < MaxEligible*maxMemberBytes || maxRowChunks*ChunkSize < MaxEligible*maxRowBytes {
		t.Fatalf("bounds %d and %d chunks too small", maxMemberChunks, maxRowChunks)
	}
	if (maxMemberChunks-2)*ChunkSize >= MaxEligible*maxMemberBytes || (maxRowChunks-2)*ChunkSize >= MaxEligible*maxRowBytes {
		t.Fatalf("bounds %d and %d chunks looser than the cap needs", maxMemberChunks, maxRowChunks)
	}
}

// A proposal's members are stored in chunks, not in its record, read
// back whole, and not written again by later saves; a record from before
// chunks (members inline) still reads; one with both is refused; with a
// chunk missing the proposal is an error.
func TestProposalMembersInChunks(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	st := peer.NewMemStore()
	rs := &RecordStore{Records: st, Copy: &MemCopy{}}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := st.Get(ctx, KindProposal, f.p.ProposalID)
	if strings.Contains(string(raw), `"members"`) || !strings.Contains(string(raw), `"member_chunks"`) {
		t.Fatalf("record: %s", raw)
	}
	o, err := rs.OpenProposal(ctx, f.p.ProposalID)
	if err != nil || len(o.Members) != len(f.open.Members) || !bytes.Equal(o.Members["c0"].Tag, f.open.Members["c0"].Tag) {
		t.Fatalf("read back: %v", err)
	}
	chunks, _ := st.Load(ctx, KindChunk)
	o.Published = true
	if err := rs.SaveProposal(ctx, o, false); err != nil {
		t.Fatal(err)
	}
	if again, _ := st.Load(ctx, KindChunk); len(again) != len(chunks) {
		t.Errorf("%d chunks after a save, %d before", len(again), len(chunks))
	}
	if o, err := rs.OpenProposal(ctx, f.p.ProposalID); err != nil || !o.Published || len(o.Members) != len(f.open.Members) {
		t.Fatalf("after a save: %v", err)
	}

	// From before chunks: members inline.
	inline := *f.open
	inline.MemberChunks = nil
	data, _ := json.Marshal(&inline)
	st2 := peer.NewMemStore()
	if err := st2.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: f.p.ProposalID, Data: data}}); err != nil {
		t.Fatal(err)
	}
	rs2 := &RecordStore{Records: st2, Copy: &MemCopy{}}
	o2, err := rs2.OpenProposal(ctx, f.p.ProposalID)
	if err != nil || len(o2.Members) != len(f.open.Members) {
		t.Fatalf("inline record: %v", err)
	}
	if err := rs2.SaveProposal(ctx, o2, false); err != nil {
		t.Fatal(err)
	}
	if c, _ := st2.Load(ctx, KindChunk); len(c) != 0 {
		t.Error("an inline record's save wrote chunks")
	}

	// Both: refused.
	both := *f.open
	both.MemberChunks = o.MemberChunks
	data, _ = json.Marshal(&both)
	if err := st.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: f.p.ProposalID, Data: data}}); err != nil {
		t.Fatal(err)
	}
	if o, err := rs.OpenProposal(ctx, f.p.ProposalID); o != nil || err == nil {
		t.Error("a record with members both inline and in chunks was read")
	}

	// A chunk missing.
	st3 := peer.NewMemStore()
	rs3 := &RecordStore{Records: st3, Copy: &MemCopy{}}
	if err := rs3.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	c3, _ := st3.Load(ctx, KindChunk)
	if err := st3.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: c3[0].ID}}); err != nil {
		t.Fatal(err)
	}
	if o, err := rs3.OpenProposal(ctx, f.p.ProposalID); o != nil || !errors.Is(err, ErrChunkMissing) {
		t.Errorf("a chunk missing: %v", err)
	}

	// A member chunk with other bytes (here, a chunk of the same
	// proposal's other value), another proposal's chunk, and a list over
	// the members' bound of intact chunks: refused.
	st5 := peer.NewMemStore()
	rs5 := &RecordStore{Records: st5, Copy: &MemCopy{}}
	if err := rs5.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	named, _, _ := st5.GetRecord(ctx, KindProposal, f.p.ProposalID)
	var rec OpenProposal
	_ = json.Unmarshal(named.Data, &rec)
	otherVal, _ := putChunks(ctx, st5, f.p.ProposalID, []byte("other value"), 8)
	ov, _, _ := st5.Get(ctx, KindChunk, otherVal[0].ID)
	if err := st5.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: rec.MemberChunks[0].ID, Data: ov}}); err != nil {
		t.Fatal(err)
	}
	if o, err := rs5.OpenProposal(ctx, f.p.ProposalID); o != nil || !errors.Is(err, ErrChunkBad) {
		t.Errorf("a member chunk swapped: %v", err)
	}
	foreign, _ := putChunks(ctx, st5, "another-proposal", []byte("x"), 8)
	three, _ := putChunks(ctx, st5, f.p.ProposalID, bigValue(3*ChunkSize), 8)
	for name, refs := range map[string][]chunkRef{"foreign": foreign, "over the bound": three} {
		r := rec
		r.MemberChunks = refs
		data, _ := json.Marshal(&r)
		if err := st5.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: f.p.ProposalID, Data: data}}); err != nil {
			t.Fatal(err)
		}
		if o, err := rs5.OpenProposal(ctx, f.p.ProposalID); o != nil || !errors.Is(err, ErrChunkBad) {
			t.Errorf("member chunks %s: %v", name, err)
		}
	}

	// Other members than the proposal names (none, one lost, one added),
	// inline or in chunks: refused, never a vote with other voters.
	for _, change := range []string{"none", "lost", "added"} {
		short := *f.open
		short.MemberChunks = nil
		short.Members = map[string]Member{}
		if change != "none" {
			for k, v := range f.open.Members {
				short.Members[k] = v
			}
		}
		switch change {
		case "lost":
			for k := range short.Members {
				delete(short.Members, k)
				break
			}
		case "added":
			short.Members["c-extra"] = f.open.Members["c0"]
		}
		st4 := peer.NewMemStore()
		rs4 := &RecordStore{Records: st4, Copy: &MemCopy{}}
		if err := rs4.SaveProposal(ctx, &short, true); err != nil {
			t.Fatal(err)
		}
		if o, err := rs4.OpenProposal(ctx, f.p.ProposalID); o != nil || err == nil {
			t.Errorf("a proposal with %d of %d members was read", len(short.Members), len(f.open.Members))
		}
		short.MemberChunks = nil // SaveProposal named its chunks
		data, _ := json.Marshal(&short)
		if err := st4.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: f.p.ProposalID, Data: data}}); err != nil {
			t.Fatal(err)
		}
		if o, err := rs4.OpenProposal(ctx, f.p.ProposalID); o != nil || err == nil {
			t.Errorf("an inline proposal with %d of %d members was read", len(short.Members), len(f.open.Members))
		}
	}
}

// The results' rows are stored in chunks, read back whole, and not
// written again by a later save; results from before chunks still read.
func TestResultsRowsInChunks(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	st := m.Store.Records
	rows := bigValue(ChunkSize + 7)
	pr := &PublishedResults{Results: []byte(`{}`), Sig: []byte("s"), Rows: rows}
	if err := m.saveResults(ctx, "p1", pr, true); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := st.Get(ctx, KindResults, "p1")
	if strings.Contains(string(raw), `"rows"`) || len(pr.RowChunks) != 2 {
		t.Fatalf("record: %s", raw)
	}
	got, err := m.Results(ctx, "p1")
	if err != nil || !bytes.Equal(got.Rows, rows) {
		t.Fatalf("read back: %v", err)
	}
	got.IndexStale = true
	if err := m.saveResults(ctx, "p1", got, false); err != nil {
		t.Fatal(err)
	}
	if c, _ := st.Load(ctx, KindChunk); len(c) != 2 {
		t.Errorf("%d chunks after a save", len(c))
	}
	if got, err := m.Results(ctx, "p1"); err != nil || !got.IndexStale || !bytes.Equal(got.Rows, rows) {
		t.Fatalf("after a save: %v", err)
	}
	// From before chunks.
	old, _ := json.Marshal(map[string]any{"results": []byte(`{}`), "results_sig": []byte("s"), "rows": []byte("r")})
	if err := st.Apply(ctx, []peer.Change{{Kind: KindResults, ID: "p2", Data: old}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p2"); err != nil || string(got.Rows) != "r" {
		t.Fatalf("inline results: %v", err)
	}

	// Both inline and in chunks: refused.
	both, _ := json.Marshal(map[string]any{"results": []byte(`{}`), "results_sig": []byte("s"), "rows": []byte("r"), "row_chunks": pr.RowChunks})
	if err := st.Apply(ctx, []peer.Change{{Kind: KindResults, ID: "p1", Data: both}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p1"); got != nil || err == nil {
		t.Error("results with rows both inline and in chunks were read")
	}
	// No rows at all: refused.
	none, _ := json.Marshal(map[string]any{"results": []byte(`{}`), "results_sig": []byte("s")})
	if err := st.Apply(ctx, []peer.Change{{Kind: KindResults, ID: "p3", Data: none}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p3"); got != nil || err == nil {
		t.Error("results without rows were read")
	}

	// A chunk swapped, then one missing.
	pr4 := &PublishedResults{Results: []byte(`{}`), Sig: []byte("s"), Rows: bigValue(ChunkSize + 9)}
	if err := m.saveResults(ctx, "p4", pr4, true); err != nil {
		t.Fatal(err)
	}
	a, _, _ := st.Get(ctx, KindChunk, pr4.RowChunks[0].ID)
	b, _, _ := st.Get(ctx, KindChunk, pr4.RowChunks[1].ID)
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: pr4.RowChunks[0].ID, Data: b}, {Kind: KindChunk, ID: pr4.RowChunks[1].ID, Data: a}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p4"); got != nil || !errors.Is(err, ErrChunkBad) {
		t.Errorf("results with a chunk swapped: %v", err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: pr4.RowChunks[0].ID}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p4"); got != nil || !errors.Is(err, ErrChunkMissing) {
		t.Errorf("results with a chunk missing: %v", err)
	}
	// Row chunks over their bound, each intact: refused.
	three, _ := putChunks(ctx, st, "p5", bigValue(3*ChunkSize), 8)
	over, _ := json.Marshal(map[string]any{"results": []byte(`{}`), "results_sig": []byte("s"), "row_chunks": three})
	if err := st.Apply(ctx, []peer.Change{{Kind: KindResults, ID: "p5", Data: over}}); err != nil {
		t.Fatal(err)
	}
	if got, err := m.Results(ctx, "p5"); got != nil || !errors.Is(err, ErrChunkBad) {
		t.Errorf("row chunks over the bound: %v", err)
	}
	// Results without rows are not saved.
	if err := m.saveResults(ctx, "p6", &PublishedResults{Results: []byte(`{}`), Sig: []byte("s")}, true); err == nil {
		t.Error("results without rows were saved")
	}
	if c, _ := st.Load(ctx, KindResults); len(c) != 5 {
		t.Errorf("%d results records", len(c))
	}
}

// A chunk write that conflicts holds only if the chunk stored under the
// id is the same (a retry after a lost answer); another chunk there is an
// error (the write is IfAbsent: it never replaces one).
func TestChunkWriteConflict(t *testing.T) {
	ctx := context.Background()
	st := peer.NewMemStore()
	n := 0
	newChunkID = func(p string) (string, error) { n++; return p + "|fixed", nil }
	defer func() { newChunkID = chunkID }()
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: "p1|fixed", Data: []byte("same")}}); err != nil {
		t.Fatal(err)
	}
	if refs, err := putChunks(ctx, st, "p1", []byte("same"), 8); err != nil || len(refs) != 1 {
		t.Fatalf("a retry finding its own chunk: %v", err)
	}
	if _, err := putChunks(ctx, st, "p1", []byte("different"), 8); err == nil {
		t.Fatal("a write over another chunk held")
	}
	if d, _, _ := st.Get(ctx, KindChunk, "p1|fixed"); string(d) != "same" {
		t.Errorf("the stored chunk was replaced: %q", d)
	}
}

// A copy of the table taken at any point holds every chunk its records
// name: the chunks are written before them. Restored from such a copy,
// the proposal and the results read back whole.
func TestChunksSurviveRestore(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	type snap map[string][]peer.Record
	take := func(st *peer.MemStore) snap {
		s := snap{}
		for _, k := range Kinds() {
			s[k], _ = st.Load(ctx, k)
		}
		return s
	}
	st := peer.NewMemStore()
	var snaps []snap
	// The store records a copy before every write the save makes.
	rs := &RecordStore{Records: &snapStore{MemStore: st, before: func() { snaps = append(snaps, take(st)) }}, Copy: &MemCopy{}}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	snaps = append(snaps, take(st))
	for i, s := range snaps {
		restored := peer.NewMemStore()
		for k, recs := range s {
			for _, r := range recs {
				if err := restored.Apply(ctx, []peer.Change{{Kind: k, ID: r.ID, Data: r.Data}}); err != nil {
					t.Fatal(err)
				}
			}
		}
		rr := &RecordStore{Records: restored, Copy: &MemCopy{}}
		o, err := rr.OpenProposal(ctx, f.p.ProposalID)
		if err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		if o != nil && len(o.Members) != len(f.open.Members) {
			t.Fatalf("copy %d: %d members", i, len(o.Members))
		}
	}
}

// The results' rows too: every copy taken before each of the save's
// writes either lacks the results or holds them whole.
func TestResultsChunksSurviveRestore(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	st := peer.NewMemStore()
	var snaps [][]peer.Record
	take := func() {
		var all []peer.Record
		for _, k := range Kinds() {
			recs, _ := st.Load(ctx, k)
			for _, r := range recs {
				r.Kind = k
				all = append(all, r)
			}
		}
		snaps = append(snaps, all)
	}
	m.Store.Records = &snapStore{MemStore: st, before: take}
	rows := bigValue(ChunkSize + 3)
	if err := m.saveResults(ctx, "p1", &PublishedResults{Results: []byte(`{}`), Sig: []byte("s"), Rows: rows}, true); err != nil {
		t.Fatal(err)
	}
	take()
	if len(snaps) != 4 { // two chunks, the record, and after
		t.Fatalf("%d copies", len(snaps))
	}
	for i, s := range snaps {
		restored := peer.NewMemStore()
		for _, r := range s {
			if err := restored.Apply(ctx, []peer.Change{{Kind: r.Kind, ID: r.ID, Data: r.Data}}); err != nil {
				t.Fatal(err)
			}
		}
		m.Store.Records = restored
		got, err := m.Results(ctx, "p1")
		if err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
		if got != nil && !bytes.Equal(got.Rows, rows) {
			t.Fatalf("copy %d: rows differ", i)
		}
		if i == len(snaps)-1 && got == nil {
			t.Fatal("the last copy lacks the results")
		}
	}
}

// snapStore calls before ahead of each Apply.
type snapStore struct {
	*peer.MemStore
	before func()
}

func (s *snapStore) Apply(ctx context.Context, c []peer.Change) error {
	s.before()
	return s.MemStore.Apply(ctx, c)
}
