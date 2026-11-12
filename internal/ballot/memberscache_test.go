package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

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

	// Bounded: the least recently used is dropped; a use keeps one.
	var c membersCache
	for i := 0; i < membersCached; i++ {
		cacheLoad(t, &c, fmt.Sprint(i), false, t0, map[string]Member{"c": {}})
	}
	if reads := cacheLoad(t, &c, "0", false, t0, nil); reads != 0 {
		t.Fatal("a cached entry read again")
	}
	cacheLoad(t, &c, "new", false, t0, map[string]Member{"c": {}})
	has := func(k string) bool { _, ok := c.byKey[k]; return ok }
	if !has("0") || has("1") || !has("new") || len(c.byKey) != membersCached {
		t.Fatalf("bound: %d kept", len(c.byKey))
	}
}

// cacheLoad loads key at now, reading m if the cache reads; it returns
// how many reads ran.
func cacheLoad(t *testing.T, c *membersCache, key string, fresh bool, now time.Time, m map[string]Member) int {
	t.Helper()
	reads := 0
	_, _, err := c.load(context.Background(), key, fresh, func() time.Time { return now }, func(context.Context) (map[string]Member, error) {
		reads++
		return m, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return reads
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

// A fresh read of a key cached within the time returns the entry kept
// first, with its members (not the second read's), so callers share one
// record tree.
func TestMembersCacheKeepsTheFirst(t *testing.T) {
	ctx := context.Background()
	var c membersCache
	now := func() time.Time { return t0 }
	_, first, _ := c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) { return map[string]Member{"a": {}}, nil })
	_, second, _ := c.load(ctx, "k", true, now, func(context.Context) (map[string]Member, error) { return map[string]Member{"b": {}}, nil })
	if first == nil || second != first {
		t.Fatal("another entry")
	}
	m, e, _ := c.load(ctx, "k", false, now, nil)
	if e != first || len(m) != 1 {
		t.Fatalf("got %v", m)
	}
	if _, ok := m["a"]; !ok {
		t.Fatal("the second read's members kept")
	}
}

// A cached proposal's chunks are read and checked again after
// membersRecheck: a chunk lost while the process runs fails the open
// within that time, as it would without the cache, and keeps failing.
func TestMembersCacheRecheck(t *testing.T) {
	if membersRecheck > time.Minute {
		t.Fatalf("members rechecked only every %v", membersRecheck)
	}
	ctx := context.Background()
	f := newBoxFixture(t)
	st := &countingStore{MemStore: peer.NewMemStore()}
	now := time.Unix(1_800_000_000, 0)
	rs := &RecordStore{Records: st, Copy: &MemCopy{}, Now: func() time.Time { return now }}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	id := f.p.ProposalID
	o, err := rs.OpenProposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.MemberChunks) == 0 {
		t.Fatal("members inline: no cache")
	}
	reads := st.chunkGets
	now = now.Add(membersRecheck - time.Second)
	if _, err := rs.OpenProposal(ctx, id); err != nil || st.chunkGets != reads {
		t.Fatalf("within the time: %v, %d chunk reads", err, st.chunkGets-reads)
	}
	now = now.Add(time.Second)
	if _, err := rs.OpenProposal(ctx, id); err != nil || st.chunkGets == reads {
		t.Fatalf("after the time: %v, no chunk read", err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: o.MemberChunks[0].ID}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(membersRecheck)
	for i := 0; i < 2; i++ {
		if o, err := rs.OpenProposal(ctx, id); o != nil || !errors.Is(err, ErrChunkMissing) {
			t.Fatalf("open %d with a chunk lost: %v", i+1, err)
		}
	}
	if len(rs.members.byKey) != 0 || len(rs.members.order) != 0 {
		t.Fatal("the lost proposal is still cached")
	}
}

// t0 is a fixed time for the cache's own tests.
var t0 = time.Unix(1_800_000_000, 0)

// clockStore advances a fake clock on its first chunk read: the read
// takes time.
type clockStore struct {
	*countingStore
	now  *time.Time
	took time.Duration
}

func (c *clockStore) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if kind == KindChunk && c.took > 0 {
		*c.now = c.now.Add(c.took)
		c.took = 0
	}
	return c.countingStore.Get(ctx, kind, id)
}

// An entry's age counts from when its read started, not when it ended: a
// slow read doesn't stretch the time its members are used.
func TestMembersCacheReadTimeBeforeTheRead(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	now := t0
	st := &clockStore{countingStore: &countingStore{MemStore: peer.NewMemStore()}, now: &now}
	rs := &RecordStore{Records: st, Copy: &MemCopy{}, Now: func() time.Time { return now }}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	st.took = membersRecheck / 2
	if _, err := rs.OpenProposal(ctx, f.p.ProposalID); err != nil {
		t.Fatal(err)
	}
	reads := st.chunkGets
	now = t0.Add(membersRecheck)
	if _, err := rs.OpenProposal(ctx, f.p.ProposalID); err != nil || st.chunkGets == reads {
		t.Fatalf("a minute after the read began: %v, no chunk read", err)
	}
}

// A changed chunk fails the open with ErrChunkBad once its entry is due,
// leaves nothing cached, and raises vote_chunk_missing, at most once per
// chunkAlarmEvery for the proposal.
func TestMembersCacheChunkChanged(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	st := peer.NewMemStore()
	now := t0
	var log bytes.Buffer
	rs := &RecordStore{Records: st, Copy: &MemCopy{}, Now: func() time.Time { return now }, Log: slog.New(slog.NewJSONHandler(&log, nil))}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	id := f.p.ProposalID
	o, err := rs.OpenProposal(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: o.MemberChunks[0].ID, Data: []byte("other bytes")}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(membersRecheck)
	for i := 0; i < 3; i++ {
		if o, err := rs.OpenProposal(ctx, id); o != nil || !errors.Is(err, ErrChunkBad) {
			t.Fatalf("open %d with a chunk changed: %v", i+1, err)
		}
	}
	if len(rs.members.byKey) != 0 {
		t.Fatal("the changed proposal is still cached")
	}
	if n := strings.Count(log.String(), `"alarm":"vote_chunk_missing"`); n != 1 || !strings.Contains(log.String(), id) {
		t.Fatalf("%d alarm lines: %s", n, log.String())
	}
	now = now.Add(chunkAlarmEvery)
	_, _ = rs.OpenProposal(ctx, id)
	if n := strings.Count(log.String(), `"alarm":"vote_chunk_missing"`); n != 2 || !strings.Contains(log.String(), `"opens":3`) {
		t.Fatalf("after %v: %d alarm lines: %s", chunkAlarmEvery, n, log.String())
	}
}

// A read that began before another check found the chunks lost is not
// kept after it: the failure stays until a read that began after it
// succeeds.
func TestMembersCacheFailureSticks(t *testing.T) {
	ctx := context.Background()
	var c membersCache
	now := func() time.Time { return t0 }
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error)
	go func() {
		_, _, err := c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) {
			close(started)
			<-release
			return map[string]Member{"a": {}}, nil // read before the loss
		})
		done <- err
	}()
	<-started
	if _, _, err := c.load(ctx, "k", true, now, func(context.Context) (map[string]Member, error) {
		return nil, ErrChunkMissing
	}); !errors.Is(err, ErrChunkMissing) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, ok := c.byKey["k"]; ok {
		t.Fatal("a read from before the failed check was cached")
	}
	// A read that begins after the failure is kept.
	if cacheLoad(t, &c, "k", false, t0, map[string]Member{"a": {}}) != 1 || c.byKey["k"] == nil {
		t.Fatal("a later read not kept")
	}
}

// Concurrent opens of a due key read its chunks once.
func TestMembersCacheOneReadAtATime(t *testing.T) {
	ctx := context.Background()
	var c membersCache
	now := func() time.Time { return t0 }
	var mu sync.Mutex
	reads := 0
	release := make(chan struct{})
	read := func(context.Context) (map[string]Member, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		<-release
		return map[string]Member{"a": {}}, nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, _, err := c.load(ctx, "k", false, now, read)
			if err == nil && len(m) != 1 {
				err = errors.New("no members")
			}
			errs <- err
		}()
	}
	for {
		c.mu.Lock()
		_, flying := c.inflight["k"]
		c.mu.Unlock()
		if flying {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // the others reach the wait
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if reads != 1 {
		t.Fatalf("%d reads", reads)
	}
	// A reader whose own context ends doesn't fail the others: they read
	// again.
	var c2 membersCache
	cctx, cancel := context.WithCancel(ctx)
	started := make(chan struct{})
	go func() {
		_, _, _ = c2.load(cctx, "k", false, now, func(ctx context.Context) (map[string]Member, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}()
	<-started
	res := make(chan error)
	go func() {
		_, _, err := c2.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) { return map[string]Member{"a": {}}, nil })
		res <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-res; err != nil {
		t.Fatalf("a waiter failed with the reader's context: %v", err)
	}
}

// A close, a publication and an extension read the members from their
// chunks, never from the cache: none acts on members the store has lost,
// even within membersRecheck. A status keeps the cache until such a read
// finds the loss, and then fails too.
func TestMembersFreshForCloseAndPublish(t *testing.T) {
	ctx := context.Background()
	for name, op := range map[string]func(e *extEnv) error{
		"publish": func(e *extEnv) error { _, err := e.m.Publish(ctx, e.id); return err },
		"extend":  func(e *extEnv) error { _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); return err },
		"close": func(e *extEnv) error {
			*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
			_, err := e.m.Close(ctx, e.id)
			return err
		},
	} {
		e := newExtEnv(t)
		o := e.open(t)
		if len(o.MemberChunks) == 0 {
			t.Fatal("members inline: no cache")
		}
		if err := e.m.Store.Records.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: o.MemberChunks[0].ID}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.Status(ctx, e.id); err != nil {
			t.Fatalf("%s: status, cached: %v", name, err)
		}
		if err := op(e); !errors.Is(err, ErrChunkMissing) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := e.m.Status(ctx, e.id); !errors.Is(err, ErrChunkMissing) {
			t.Fatalf("%s: status after the loss was found: %v", name, err)
		}
	}
}

// An opener that joins a read in progress, after another check found
// the chunks lost, reads again instead of taking what the read in
// progress found (it may be from before the loss).
func TestMembersCacheWaiterAfterLoss(t *testing.T) {
	ctx := context.Background()
	var c membersCache
	now := func() time.Time { return t0 }
	started, release := make(chan struct{}), make(chan struct{})
	go func() {
		_, _, _ = c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) {
			close(started)
			<-release
			return map[string]Member{"before": {}}, nil // read before the loss
		})
	}()
	<-started
	if _, _, err := c.load(ctx, "k", true, now, func(context.Context) (map[string]Member, error) {
		return nil, ErrChunkMissing
	}); !errors.Is(err, ErrChunkMissing) {
		t.Fatal(err)
	}
	res := make(chan error)
	go func() {
		_, _, err := c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) {
			return nil, ErrChunkMissing // the chunks, read now
		})
		res <- err
	}()
	for {
		c.mu.Lock()
		f := c.inflight["k"]
		c.mu.Unlock()
		if f != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // the waiter joins the read in progress
	close(release)
	if err := <-res; !errors.Is(err, ErrChunkMissing) {
		t.Fatalf("a waiter after the loss: %v", err)
	}
}

// A read that panics completes its flight: the openers waiting for it
// read again, and later ones don't wait.
func TestMembersCacheReadPanics(t *testing.T) {
	ctx := context.Background()
	var c membersCache
	now := func() time.Time { return t0 }
	started, release := make(chan struct{}), make(chan struct{})
	panicked := make(chan any)
	go func() {
		defer func() { panicked <- recover() }()
		_, _, _ = c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) {
			close(started)
			<-release
			panic("read")
		})
	}()
	<-started
	res := make(chan error)
	go func() {
		m, _, err := c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) {
			return map[string]Member{"a": {}}, nil
		})
		if err == nil && len(m) != 1 {
			err = errors.New("no members")
		}
		res <- err
	}()
	time.Sleep(20 * time.Millisecond) // the waiter joins
	close(release)
	if r := <-panicked; r != "read" {
		t.Fatalf("the panic: %v", r)
	}
	tctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	select {
	case err := <-res:
		if err != nil {
			t.Fatalf("the waiter: %v", err)
		}
	case <-tctx.Done():
		t.Fatal("the waiter still waits")
	}
	if _, ok := c.inflight["k"]; ok {
		t.Fatal("the flight is left")
	}
}

// A successful read after a failure clears its record; a lost chunk's
// alarm records that are due again with nothing held are pruned.
func TestMembersCachePrunes(t *testing.T) {
	var c membersCache
	ctx := context.Background()
	now := func() time.Time { return t0 }
	_, _, _ = c.load(ctx, "k", false, now, func(context.Context) (map[string]Member, error) { return nil, ErrChunkMissing })
	if c.failed["k"] == 0 {
		t.Fatal("no failure recorded")
	}
	cacheLoad(t, &c, "k", false, t0, map[string]Member{"a": {}})
	if _, ok := c.failed["k"]; ok {
		t.Fatal("the failure record kept")
	}
	at := t0
	rs := &RecordStore{Now: func() time.Time { return at }}
	rs.chunkAlarm("p1")
	at = at.Add(chunkAlarmEvery)
	rs.chunkAlarm("p2")
	if _, ok := rs.lostAt["p1"]; ok || rs.lostAt["p2"] == nil {
		t.Fatalf("pruned: %v", rs.lostAt)
	}
}
