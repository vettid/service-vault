package ballot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/vettid/service-vault/internal/peer"
)

// KindChunk is a part of a large value of a proposal (its members, its
// results' rows) stored outside the record that names it, because one
// DynamoDB item holds at most 400 KB (id: proposal_id "|" a random
// hex id).
const KindChunk = "vote_chunk"

// ChunkSize is the most bytes of a value one chunk holds (chosen; not in
// the spec): under the 400 KB item with room for the seal, the keys and
// the attribute names.
const ChunkSize = 300_000

// maxChunks bounds the chunks one value may name: the largest value is a
// results record's rows at MaxEligible members (about 5.0 MB, see
// MaxEligible), so a list longer than this is refused when read.
const maxChunks = 24

// chunkRef names one chunk in the record that holds the value: its id,
// and the SHA-256 of its bytes. The record is sealed, so the digest is
// not visible in the table; the chunk's own seal is bound to its id
// (internal/sealstore), so it can't be read under another chunk's place.
type chunkRef struct {
	ID  string `json:"id"`
	Sum []byte `json:"sum"`
}

// Chunk errors: a value whose chunks are not all there or not the ones
// named. Neither is ever read as an empty value.
var (
	ErrChunkMissing = errors.New("ballot: a stored chunk is missing")
	ErrChunkBad     = errors.New("ballot: a stored chunk is not the one named")
)

// chunkID is a new chunk's id: random, so that the table shows nothing
// of what the chunk holds, and with the proposal's id first, so that a
// proposal's chunks can all be found by prefix.
func chunkID(proposalID string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return proposalID + "|" + hex.EncodeToString(b[:]), nil
}

// ChunksOf reports whether a chunk id belongs to a proposal, for a sweep
// that deletes a proposal's chunks with it.
func ChunksOf(proposalID, chunkID string) bool {
	return strings.HasPrefix(chunkID, proposalID+"|")
}

// putChunks writes data in chunks of at most ChunkSize, each in its own
// write (a transaction holds at most 4 MB), and returns the list that
// names them. They are written before the record that names them, so a
// copy of the table from any moment that holds the record holds its
// chunks; the chunks of a record whose write then fails stay behind
// unnamed, and are deleted with the proposal.
func putChunks(ctx context.Context, recs peer.Store, proposalID string, data []byte) ([]chunkRef, error) {
	n := (len(data) + ChunkSize - 1) / ChunkSize
	if n > maxChunks {
		return nil, fmt.Errorf("ballot: a value of %d bytes needs more than %d chunks", len(data), maxChunks)
	}
	refs := make([]chunkRef, 0, n)
	for off := 0; off < len(data); off += ChunkSize {
		part := data[off:min(off+ChunkSize, len(data))]
		id, err := chunkID(proposalID)
		if err != nil {
			return nil, err
		}
		if err := recs.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: id, Data: part, IfAbsent: true}}); err != nil {
			return nil, err
		}
		s := sha256.Sum256(part)
		refs = append(refs, chunkRef{ID: id, Sum: s[:]})
	}
	return refs, nil
}

// getChunks reads a value back from the chunks refs names, in order, and
// checks each against its digest. A list longer than maxChunks, a chunk
// of another proposal, a missing chunk or one with other bytes is an
// error.
func getChunks(ctx context.Context, recs peer.Store, proposalID string, refs []chunkRef) ([]byte, error) {
	if len(refs) > maxChunks {
		return nil, fmt.Errorf("%w: %d chunks named, at most %d", ErrChunkBad, len(refs), maxChunks)
	}
	var out bytes.Buffer
	for _, r := range refs {
		if !ChunksOf(proposalID, r.ID) {
			return nil, fmt.Errorf("%w: of another proposal", ErrChunkBad)
		}
		data, ok, err := recs.Get(ctx, KindChunk, r.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrChunkMissing
		}
		s := sha256.Sum256(data)
		if !bytes.Equal(s[:], r.Sum) {
			return nil, ErrChunkBad
		}
		out.Write(data)
	}
	return out.Bytes(), nil
}
