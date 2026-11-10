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

// The most bytes a member takes in a proposal's members, and a row in
// the results' rows (chosen; not in the spec): measured at about 140 and
// 251 at MaxEligible with the largest inputs (TestMaxEligibleFitsOneItem
// checks they stay under these). maxRowBytes is also bounded by the
// results' single upload to the votes site: MaxEligible rows of it, as
// base64, fit siteRowsUpload (TestChunkBounds).
const (
	maxMemberBytes = 200
	maxRowBytes    = 270
)

// siteRowsUpload is the most rows, as base64, the results' upload to the
// votes site can carry whatever the rest of it: the site takes 6,225,920
// bytes (its MaxUpload, measured on staging, GC #7325; Lambda's 6 MB
// request, less room), less the largest results (512 KB) and bundle
// (64 KB) as base64, and the JSON around them. The site is another
// repository: a change to its limit has to change this.
const siteRowsUpload = 6_225_920 - 699_052 - 87_384 - 4_096

// The most chunks each value may name, from MaxEligible: a list longer
// than this is refused when read, and a longer value is not written.
const (
	maxMemberChunks = (MaxEligible*maxMemberBytes+ChunkSize-1)/ChunkSize + 1
	maxRowChunks    = (MaxEligible*maxRowBytes+ChunkSize-1)/ChunkSize + 1
)

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

// newChunkID makes chunk ids (tests replace it).
var newChunkID = chunkID

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
// chunks. The chunks of a record whose write then fails stay behind
// unnamed. Nothing deletes a proposal or its results today; whatever
// comes to delete them must delete their chunks too, found by prefix
// (ChunksOf), named or not.
//
// A write that the store answered with a conflict (a retry after a lost
// answer found its own chunk there) holds if the chunk stored is this
// one; any other chunk under the id is an error.
func putChunks(ctx context.Context, recs peer.Store, proposalID string, data []byte, maxChunks int) ([]chunkRef, error) {
	n := (len(data) + ChunkSize - 1) / ChunkSize
	if n > maxChunks {
		return nil, fmt.Errorf("ballot: a value of %d bytes needs more than %d chunks", len(data), maxChunks)
	}
	refs := make([]chunkRef, 0, n)
	for off := 0; off < len(data); off += ChunkSize {
		part := data[off:min(off+ChunkSize, len(data))]
		id, err := newChunkID(proposalID)
		if err != nil {
			return nil, err
		}
		s := sha256.Sum256(part)
		switch err := recs.Apply(ctx, []peer.Change{{Kind: KindChunk, ID: id, Data: part, IfAbsent: true}}); {
		case errors.Is(err, peer.ErrConflict):
			have, ok, gerr := recs.Get(ctx, KindChunk, id)
			if gerr != nil {
				return nil, gerr
			}
			if hs := sha256.Sum256(have); !ok || !bytes.Equal(hs[:], s[:]) {
				return nil, fmt.Errorf("ballot: another chunk is stored under a new chunk's id: %w", err)
			}
		case err != nil:
			return nil, err
		}
		refs = append(refs, chunkRef{ID: id, Sum: s[:]})
	}
	return refs, nil
}

// getChunks reads a value back from the chunks refs names, in order, and
// checks each against its digest. A list longer than maxChunks, a chunk
// of another proposal, a missing chunk or one with other bytes is an
// error.
func getChunks(ctx context.Context, recs peer.Store, proposalID string, refs []chunkRef, maxChunks int) ([]byte, error) {
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
