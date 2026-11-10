package ballot

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"sync"
)

// membersCached is how many proposals' members are kept decoded: each
// cast and vote.status opens its proposal, and at 15,000 members that is
// about 2.4 MB of chunks to read and unseal (#6946). A proposal's members
// are written once, to fresh chunks, and never change, so a proposal's
// members are cached by the chunks its record names, each with its
// SHA-256: a record that names other chunks, or other sums, is a miss
// and is read again (and checked) from the store. The cache is the
// process's: a chunk lost in a table restore isn't noticed while its
// proposal is cached, so the restore's check (RebuildAll: open every
// running proposal) runs in a freshly started service vault, as -rebuild
// does.
const membersCached = 8

// membersKey is the cache key of a proposal's member chunks.
func membersKey(proposalID string, refs []chunkRef) string {
	h := sha256.New()
	h.Write([]byte(proposalID))
	for _, r := range refs {
		h.Write([]byte{0})
		h.Write([]byte(r.ID))
		h.Write([]byte{0})
		h.Write(r.Sum)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// membersCache keeps the decoded members of the proposals opened last.
// Each caller gets its own copy of the map, so that no two proposals read
// share one.
type membersCache struct {
	mu    sync.Mutex
	order []string // oldest first
	byKey map[string]map[string]Member
}

func (c *membersCache) get(key string) map[string]Member {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.byKey[key]
	if !ok {
		return nil
	}
	return maps.Clone(m)
}

func (c *membersCache) put(key string, m map[string]Member) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byKey == nil {
		c.byKey = map[string]map[string]Member{}
	}
	if _, ok := c.byKey[key]; ok {
		return
	}
	c.byKey[key] = maps.Clone(m)
	c.order = append(c.order, key)
	if len(c.order) > membersCached {
		delete(c.byKey, c.order[0])
		c.order = c.order[1:]
	}
}
