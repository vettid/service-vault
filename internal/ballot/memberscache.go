package ballot

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"
)

// membersCached is how many proposals' members are kept decoded: each
// cast and vote.status opens its proposal, and at 15,000 members that is
// about 2.1 MB of chunks to read and unseal (#6946). A proposal's members
// are written once, to fresh chunks, and never change, so a proposal's
// members are cached by the chunks its record names, each with its
// SHA-256: a record that names other chunks, or other sums, is a miss
// and is read again (and checked) from the store.
const membersCached = 8

// membersRecheck is how long a cached proposal's members are used before
// its chunks are read and checked again. The members never change, but
// the store can lose a chunk (a deletion, a restore that lacks it): the
// cache must not hide that from a running process. Within this time of
// the loss, the next open reads the chunks and fails, as it would
// without the cache. A close, a publication and an extension never use
// the cache (OpenProposalFresh).
const membersRecheck = time.Minute

// membersKey is the cache key of a proposal's member chunks: each field
// is written with its length first, so no two lists share a key.
func membersKey(proposalID string, refs []chunkRef) string {
	h := sha256.New()
	field := func(b []byte) {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
		h.Write(b)
	}
	field([]byte(proposalID))
	for _, r := range refs {
		field([]byte(r.ID))
		field(r.Sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// membersCache keeps the decoded members of the proposals used last.
// Each caller gets its own copy of the map, so that no two proposals read
// share one (a Member's byte slices are shared, and never written). A map
// in the cache is never changed after it is kept, so it is copied
// outside the lock.
//
// One read per key runs at a time for the openers that use the cache
// (the others wait for it), so an expiry is one read, not one per
// concurrent cast. A read that finds the chunks lost or changed is
// recorded: no read that started before it is kept after it, so a
// failed check stays failed until a read that started after it
// succeeds.
type membersCache struct {
	mu       sync.Mutex
	order    []string // least recently used first
	byKey    map[string]*membersEntry
	inflight map[string]*membersFlight
	seq      uint64            // counts the failed checks
	failed   map[string]uint64 // a key's last failed check, by seq
}

// membersEntry is one proposal's cached members, and its record tree,
// built once from them on first use and shared by every caller after (a
// vote.status needs a proof; at 15,000 members the tree is about 30,000
// hashes). The tree is never changed once built, and its proofs are
// copies (vote.Tree).
type membersEntry struct {
	members  map[string]Member
	read     time.Time // when the read of its chunks started
	treeOnce sync.Once
	tree     *recordTree
}

// membersFlight is a read of a key's chunks in progress.
type membersFlight struct {
	done  chan struct{}
	token uint64        // c.seq when the read began
	entry *membersEntry // when it succeeded
	err   error
}

// errReadPanicked completes the flight of a read that panicked: its
// waiters read again.
var errReadPanicked = errors.New("ballot: a members read panicked")

// recordTree returns the entry's record tree, building it the first time.
func (e *membersEntry) recordTree() *recordTree {
	e.treeOnce.Do(func() { e.tree = newRecordTree(tagsOf(e.members)) })
	return e.tree
}

// chunkLost is whether err says the stored chunks are not the ones named
// (missing or changed), as opposed to a store that didn't answer.
func chunkLost(err error) bool {
	return errors.Is(err, ErrChunkMissing) || errors.Is(err, ErrChunkBad)
}

// load returns a copy of key's members and their entry. With fresh, the
// chunks are always read (and the cache is not used); otherwise an entry
// read less than membersRecheck before now is used, or the read in
// progress for key is waited for. read reads and checks the chunks;
// now() is taken before it starts.
func (c *membersCache) load(ctx context.Context, key string, fresh bool, now func() time.Time,
	read func(context.Context) (map[string]Member, error)) (map[string]Member, *membersEntry, error) {
	for {
		c.mu.Lock()
		if c.byKey == nil {
			c.byKey, c.inflight, c.failed = map[string]*membersEntry{}, map[string]*membersFlight{}, map[string]uint64{}
		}
		start := now()
		if !fresh {
			if e, ok := c.byKey[key]; ok {
				if start.Before(e.read.Add(membersRecheck)) {
					c.touch(key)
					c.mu.Unlock()
					return maps.Clone(e.members), e, nil
				}
				c.drop(key)
			}
			if f, ok := c.inflight[key]; ok {
				c.mu.Unlock()
				select {
				case <-f.done:
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
				if f.err != nil && !chunkLost(f.err) && ctx.Err() == nil {
					continue // the reader's own failure (its context, a panic): read again
				}
				if f.err != nil {
					return nil, nil, f.err
				}
				c.mu.Lock()
				stale := c.failed[key] > f.token
				c.mu.Unlock()
				if stale {
					// A check failed while the read ran: what it read may be
					// from before the loss, so this opener reads again.
					continue
				}
				return maps.Clone(f.entry.members), f.entry, nil
			}
		}
		token := c.seq
		var f *membersFlight
		if !fresh {
			f = &membersFlight{done: make(chan struct{}), token: token}
			c.inflight[key] = f
		}
		c.mu.Unlock()

		m, err := c.read(ctx, key, f, read)

		c.mu.Lock()
		var e *membersEntry
		switch {
		case err != nil && chunkLost(err):
			c.seq++
			c.failed[key] = c.seq
			c.drop(key)
		case err == nil:
			e = c.keep(key, m, start, token)
		}
		if f != nil {
			f.entry, f.err = e, err
			delete(c.inflight, key)
			close(f.done)
		}
		c.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		return maps.Clone(e.members), e, nil
	}
}

// read runs the read for flight f (nil for a fresh read). If it panics,
// f is completed with errReadPanicked before the panic goes on, so its
// waiters don't wait for it.
func (c *membersCache) read(ctx context.Context, key string, f *membersFlight, read func(context.Context) (map[string]Member, error)) (map[string]Member, error) {
	ok := false
	defer func() {
		if ok || f == nil {
			return
		}
		c.mu.Lock()
		f.err = errReadPanicked
		delete(c.inflight, key)
		close(f.done)
		c.mu.Unlock()
	}()
	m, err := read(ctx)
	ok = true
	return m, err
}

// keep caches m, read from start, under key, unless a check that failed
// after the read began says otherwise; it returns the entry the caller
// uses (the one cached, or its own). c.mu is held.
func (c *membersCache) keep(key string, m map[string]Member, start time.Time, token uint64) *membersEntry {
	if c.failed[key] > token {
		// Another check found the chunks lost while this read ran: this
		// caller has what it read, and the cache keeps nothing.
		return &membersEntry{members: maps.Clone(m), read: start}
	}
	if e, ok := c.byKey[key]; ok && start.Before(e.read.Add(membersRecheck)) {
		// Kept by another reader: share its tree.
		c.touch(key)
		return e
	}
	c.drop(key)
	// This read began after any failed check of key: the chunks are
	// back, and the record of the failure is no longer needed.
	delete(c.failed, key)
	e := &membersEntry{members: maps.Clone(m), read: start}
	c.byKey[key] = e
	c.order = append(c.order, key)
	if len(c.order) > membersCached {
		delete(c.byKey, c.order[0])
		c.order = c.order[1:]
	}
	return e
}

// touch makes key the most recently used; c.mu is held.
func (c *membersCache) touch(key string) {
	if i := slices.Index(c.order, key); i >= 0 {
		c.order = append(append(c.order[:i:i], c.order[i+1:]...), key)
	}
}

// drop removes key's entry; c.mu is held.
func (c *membersCache) drop(key string) {
	delete(c.byKey, key)
	if i := slices.Index(c.order, key); i >= 0 {
		c.order = slices.Delete(c.order, i, i+1)
	}
}
