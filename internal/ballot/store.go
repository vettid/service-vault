package ballot

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vettid/service-vault/internal/peer"
)

// Record kinds in the service vault's record store (the peer's, sealed:
// internal/sealstore).
const (
	KindProposal = "vote_proposal" // id: proposal_id
	KindBallot   = "vote_ballot"   // id: proposal_id "|" hex(record_tag)
)

// Kinds lists the record kinds the ballot box stores, for a migration
// that must touch them all (internal/sealstore).
func Kinds() []string { return []string{KindProposal, KindBallot, KindResults} }

// Copy is the write-once store of accepted ballots outside the record
// store's table (BALLOT-PROTOCOL §6 "Durability"): one item per tag,
// which can be written once and never changed or deleted, so a restore of
// the table can't lose a ballot or let a second one in.
type Copy interface {
	// PutOnce writes data under (proposal, tag) unless something is
	// there, and returns what is stored: data, or the earlier bytes.
	PutOnce(ctx context.Context, proposalID string, tag, data []byte) ([]byte, error)
	// List returns every stored ballot of a proposal.
	List(ctx context.Context, proposalID string) ([]CopyItem, error)
}

// CopyItem is one stored ballot: its tag and its bytes.
type CopyItem struct {
	Tag  []byte
	Data []byte
}

// RecordStore is the BoxStore on the record store and the copy.
type RecordStore struct {
	Records peer.Store
	Copy    Copy
}

var _ BoxStore = (*RecordStore)(nil)

func ballotID(proposalID string, tag []byte) string {
	return BallotID(proposalID, tag)
}

// BallotID is a ballot's id in the copy and the record store: what its
// seal is bound to.
func BallotID(proposalID string, tag []byte) string {
	return proposalID + "|" + hex.EncodeToString(tag)
}

// ErrProposalChanged is a save of a proposal that another writer saved
// since it was read: read it again and retry.
var ErrProposalChanged = errors.New("ballot: the proposal changed since it was read")

// OpenProposal implements BoxStore. The proposal keeps the version it was
// read at, for SaveProposal.
func (s *RecordStore) OpenProposal(ctx context.Context, id string) (*OpenProposal, error) {
	g, ok := s.Records.(peer.RecordGetter)
	if !ok {
		return nil, errors.New("ballot: the record store returns no versions")
	}
	r, ok, err := g.GetRecord(ctx, KindProposal, id)
	if err != nil || !ok {
		return nil, err
	}
	var o OpenProposal
	if err := json.Unmarshal(r.Data, &o); err != nil {
		return nil, fmt.Errorf("ballot: stored proposal %s: %w", id, err)
	}
	o.version = r.Version
	return &o, nil
}

// SaveProposal writes a proposal's record: created with IfAbsent, or
// replaced (an extension, publication) only if no other writer saved it
// since o was read (ErrProposalChanged): the lock in Manager holds within
// one process, the version across two tasks running at once.
func (s *RecordStore) SaveProposal(ctx context.Context, o *OpenProposal, create bool) error {
	p, err := o.Parsed()
	if err != nil {
		return err
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	c := peer.Change{Kind: KindProposal, ID: p.ProposalID, Data: data, IfAbsent: create}
	if !create {
		if o.version == 0 {
			return errors.New("ballot: saving a proposal that wasn't read")
		}
		c.IfVersion = o.version
	}
	switch err := s.Records.Apply(ctx, []peer.Change{c}); {
	case errors.Is(err, peer.ErrConflict) && !create:
		return ErrProposalChanged
	case err != nil:
		return err
	}
	o.version = c.IfVersion + 1
	return nil
}

// Ballot implements BoxStore.
func (s *RecordStore) Ballot(ctx context.Context, proposalID string, tag []byte) (*BallotRecord, error) {
	data, ok, err := s.Records.Get(ctx, KindBallot, ballotID(proposalID, tag))
	if err != nil || !ok {
		return nil, err
	}
	return decodeBallot(data)
}

func decodeBallot(data []byte) (*BallotRecord, error) {
	var r BallotRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("ballot: stored ballot: %w", err)
	}
	return &r, nil
}

// PutBallot implements BoxStore. The copy decides which ballot a tag has:
// it is written first, and the record store then holds the same.
func (s *RecordStore) PutBallot(ctx context.Context, proposalID string, rec *BallotRecord) (*BallotRecord, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	stored, err := s.Copy.PutOnce(ctx, proposalID, rec.Ballot.RecordTag, data)
	if err != nil {
		return nil, err
	}
	got := rec
	if !bytes.Equal(stored, data) {
		if got, err = decodeBallot(stored); err != nil {
			return nil, err
		}
	}
	err = s.Records.Apply(ctx, []peer.Change{{Kind: KindBallot, ID: ballotID(proposalID, rec.Ballot.RecordTag), Data: stored, IfAbsent: true}})
	if err != nil && !errors.Is(err, peer.ErrConflict) {
		return nil, err
	}
	return got, nil
}

// Rebuild puts back into the record store every ballot of a proposal the
// copy holds (after a restore of the table), and returns how many it put.
func (s *RecordStore) Rebuild(ctx context.Context, proposalID string) (int, error) {
	all, err := s.Copy.List(ctx, proposalID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, it := range all {
		if _, err := decodeBallot(it.Data); err != nil {
			return n, err
		}
		err = s.Records.Apply(ctx, []peer.Change{{Kind: KindBallot, ID: ballotID(proposalID, it.Tag), Data: it.Data, IfAbsent: true}})
		switch {
		case err == nil:
			n++
		case !errors.Is(err, peer.ErrConflict):
			return n, err
		}
	}
	return n, nil
}

// SealedCopy seals what it writes to Inner and opens what it reads, for
// each ballot's place (sealstore.Store's Seal and Open).
type SealedCopy struct {
	Inner Copy
	Seal  func(kind, id string, data []byte) ([]byte, error)
	Open  func(kind, id string, data []byte) ([]byte, error)
}

// PutOnce implements Copy.
func (c *SealedCopy) PutOnce(ctx context.Context, proposalID string, tag, data []byte) ([]byte, error) {
	id := ballotID(proposalID, tag)
	sealed, err := c.Seal(KindBallot, id, data)
	if err != nil {
		return nil, err
	}
	stored, err := c.Inner.PutOnce(ctx, proposalID, tag, sealed)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(stored, sealed) {
		return data, nil
	}
	return c.Open(KindBallot, id, stored)
}

// List implements Copy.
func (c *SealedCopy) List(ctx context.Context, proposalID string) ([]CopyItem, error) {
	all, err := c.Inner.List(ctx, proposalID)
	if err != nil {
		return nil, err
	}
	out := make([]CopyItem, 0, len(all))
	for _, it := range all {
		data, err := c.Open(KindBallot, ballotID(proposalID, it.Tag), it.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, CopyItem{Tag: it.Tag, Data: data})
	}
	return out, nil
}

// MemCopy is an in-memory Copy, for tests and local runs.
type MemCopy struct {
	items map[string]CopyItem
}

// PutOnce implements Copy.
func (m *MemCopy) PutOnce(_ context.Context, proposalID string, tag, data []byte) ([]byte, error) {
	if m.items == nil {
		m.items = map[string]CopyItem{}
	}
	k := ballotID(proposalID, tag)
	if prev, ok := m.items[k]; ok {
		return prev.Data, nil
	}
	m.items[k] = CopyItem{Tag: append([]byte(nil), tag...), Data: append([]byte(nil), data...)}
	return data, nil
}

// Any returns one stored ballot of any proposal but skip, if there is
// one (store.Ballots.Any).
func (m *MemCopy) Any(_ context.Context, skip string) (string, CopyItem, bool, error) {
	for k, v := range m.items {
		if pid, _, _ := strings.Cut(k, "|"); pid != skip {
			return pid, v, true, nil
		}
	}
	return "", CopyItem{}, false, nil
}

// List implements Copy.
func (m *MemCopy) List(_ context.Context, proposalID string) ([]CopyItem, error) {
	var out []CopyItem
	for k, v := range m.items {
		if len(k) > len(proposalID) && k[:len(proposalID)+1] == proposalID+"|" {
			out = append(out, v)
		}
	}
	return out, nil
}
