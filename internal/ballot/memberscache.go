package ballot

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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
// without the cache.
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
// in the cache is never changed after put, so it is copied outside the
// lock.
type membersCache struct {
	mu    sync.Mutex
	order []string // least recently used first
	byKey map[string]*membersEntry
}

// membersEntry is one proposal's cached members, and its record tree,
// built once from them on first use and shared by every caller after (a
// vote.status needs a proof; at 15,000 members the tree is about 30,000
// hashes). The tree is never changed once built, and its proofs are
// copies (vote.Tree).
type membersEntry struct {
	members  map[string]Member
	read     time.Time // when its chunks were read and checked
	treeOnce sync.Once
	tree     *recordTree
}

// recordTree returns the entry's record tree, building it the first time.
func (e *membersEntry) recordTree() *recordTree {
	e.treeOnce.Do(func() { e.tree = newRecordTree(tagsOf(e.members)) })
	return e.tree
}

// get returns a copy of key's members and its entry, or nil. An entry
// read membersRecheck ago or more (by now) is dropped, so its chunks are
// read and checked again.
func (c *membersCache) get(key string, now time.Time) (map[string]Member, *membersEntry) {
	c.mu.Lock()
	e, ok := c.byKey[key]
	if ok && !now.Before(e.read.Add(membersRecheck)) {
		c.drop(key)
		ok = false
	}
	if ok {
		// Most recently used last: a proposal in use stays.
		if i := slices.Index(c.order, key); i >= 0 {
			c.order = append(append(c.order[:i:i], c.order[i+1:]...), key)
		}
	}
	c.mu.Unlock()
	if !ok {
		return nil, nil
	}
	return maps.Clone(e.members), e
}

// put keeps a copy of m, read and checked at now, under key, and returns
// key's entry (the one kept before, if another caller put it first).
func (c *membersCache) put(key string, m map[string]Member, now time.Time) *membersEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKey == nil {
		c.byKey = map[string]*membersEntry{}
	}
	if e, ok := c.byKey[key]; ok {
		return e
	}
	e := &membersEntry{members: maps.Clone(m), read: now}
	c.byKey[key] = e
	c.order = append(c.order, key)
	if len(c.order) > membersCached {
		delete(c.byKey, c.order[0])
		c.order = c.order[1:]
	}
	return e
}

// drop removes key's entry; c.mu is held.
func (c *membersCache) drop(key string) {
	delete(c.byKey, key)
	if i := slices.Index(c.order, key); i >= 0 {
		c.order = slices.Delete(c.order, i, i+1)
	}
}
