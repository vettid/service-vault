package peer

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Store keeps the peer's records: connections, invitations, handshakes
// and requests in flight, the tokens it issued (the jti registry), its
// outbox, its challenges, its events and its dedupe markers. A record is
// an opaque blob under a kind and an id; the peer encodes it.
//
// The peer runs alone on its mailbox (one task holds it), keeps every
// record but the dedupe markers in memory, and writes the records a
// message changed with Apply before it acks the message (VAULT-MESSAGING
// §8.3). Dedupe markers are looked up with Get instead of being loaded.
type Store interface {
	// Load returns every record of a kind that has not expired.
	Load(ctx context.Context, kind string) ([]Record, error)
	// Get returns one record's data if it exists and has not expired.
	Get(ctx context.Context, kind, id string) (data []byte, ok bool, err error)
	// Apply writes and deletes records, all or nothing. A change with
	// IfAbsent fails the whole call with ErrConflict when its record
	// exists; one with IfVersion fails it unless the stored record's
	// version is that one (0: absent).
	Apply(ctx context.Context, changes []Change) error
}

// Record is one stored record.
type Record struct {
	Kind    string
	ID      string
	Data    []byte
	Version uint64    // incremented by every write
	Expires time.Time // zero: kept until deleted
}

// Change is a write (Data non-nil) or a delete (Data nil) of one record.
type Change struct {
	Kind, ID string
	Data     []byte
	Expires  time.Time
	// IfAbsent makes the write conditional on the record not existing
	// (a dedupe marker, a jti, an invitation's first use).
	IfAbsent bool
	// IfVersion, when non-zero, makes the change conditional on the
	// stored version. A delete also holds when the record is already gone
	// (expired).
	IfVersion uint64
}

// ErrConflict is a conditional change that did not hold.
var ErrConflict = errors.New("peer: store conflict")

// MemStore is an in-memory Store, for tests and local runs.
type MemStore struct {
	mu  sync.Mutex
	m   map[string]map[string]Record
	Now func() time.Time
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{m: map[string]map[string]Record{}, Now: time.Now} }

func (s *MemStore) live(r Record) bool { return r.Expires.IsZero() || s.Now().Before(r.Expires) }

// Kinds returns the kinds the store holds records of (tests check that
// every kind written is one a migration knows).
func (s *MemStore) Kinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k, m := range s.m {
		if len(m) > 0 {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// Load implements Store.
func (s *MemStore) Load(_ context.Context, kind string) ([]Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Record
	for _, r := range s.m[kind] {
		if s.live(r) {
			r.Data = append([]byte(nil), r.Data...)
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Get implements Store.
func (s *MemStore) Get(_ context.Context, kind, id string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[kind][id]
	if !ok || !s.live(r) {
		return nil, false, nil
	}
	return append([]byte(nil), r.Data...), true, nil
}

// Apply implements Store.
func (s *MemStore) Apply(_ context.Context, changes []Change) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range changes {
		r, ok := s.m[c.Kind][c.ID]
		ok = ok && s.live(r)
		if c.IfAbsent && ok {
			return ErrConflict
		}
		if c.IfVersion != 0 && (ok && r.Version != c.IfVersion || !ok && c.Data != nil) {
			return ErrConflict
		}
	}
	for _, c := range changes {
		if c.Data == nil {
			delete(s.m[c.Kind], c.ID)
			continue
		}
		if s.m[c.Kind] == nil {
			s.m[c.Kind] = map[string]Record{}
		}
		v := s.m[c.Kind][c.ID].Version + 1
		s.m[c.Kind][c.ID] = Record{Kind: c.Kind, ID: c.ID, Data: append([]byte(nil), c.Data...), Version: v, Expires: c.Expires}
	}
	return nil
}

// Page returns at most limit records of a kind whose ids sort after
// after ("" for the first), in id order: the read side of an
// append-only kind such as the audit log (store.Table has the same).
func (s *MemStore) Page(ctx context.Context, kind, after string, limit int) ([]Record, error) {
	all, err := s.Load(ctx, kind)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, r := range all {
		if r.ID > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}
