package vote

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// Merkle trees per RFC 6962 §2.1 with SHA-256 (BALLOT-PROTOCOL §8.2):
// leaf hash H(0x00 ‖ leaf), node hash H(0x01 ‖ left ‖ right), split at
// the largest power of two below n, the empty tree H(""). Proofs are
// RFC 6962 §2.1.1 audit paths, nearest sibling first.

// LeafHash is H(0x00 ‖ leaf).
func LeafHash(leaf []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(leaf)
	return h.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// split is the largest power of two below n (n ≥ 2).
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root is the tree head over the leaves, in order.
func Root(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		s := sha256.Sum256(nil)
		return s[:]
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return rootOf(hashes)
}

func rootOf(h [][]byte) []byte {
	if len(h) == 1 {
		return h[0]
	}
	k := split(len(h))
	return nodeHash(rootOf(h[:k]), rootOf(h[k:]))
}

// Proof is the audit path of leaf index m in a tree of the leaves.
func Proof(leaves [][]byte, m int) ([][]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, errors.New("ballot: leaf index out of range")
	}
	hashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = LeafHash(l)
	}
	return path(hashes, m), nil
}

func path(h [][]byte, m int) [][]byte {
	if len(h) == 1 {
		return nil
	}
	k := split(len(h))
	if m < k {
		return append(path(h[:k], m), rootOf(h[k:]))
	}
	return append(path(h[k:], m-k), rootOf(h[:k]))
}

// Tree is a Merkle tree over its leaves with every node hashed once, so
// each audit path costs O(log n); Proof hashes every leaf on each call.
// A proposal's record tree gives each member's record_proof from one
// Tree (§8.5).
type Tree struct {
	n     int
	nodes map[[2]int][]byte // the subtree over leaves [lo, hi) -> its hash
}

// NewTree builds the tree over the leaves, in order.
func NewTree(leaves [][]byte) *Tree {
	t := &Tree{n: len(leaves), nodes: make(map[[2]int][]byte, 2*len(leaves))}
	if t.n > 0 {
		t.build(leaves, 0, t.n)
	}
	return t
}

func (t *Tree) build(leaves [][]byte, lo, hi int) []byte {
	var h []byte
	if hi-lo == 1 {
		h = LeafHash(leaves[lo])
	} else {
		k := split(hi - lo)
		h = nodeHash(t.build(leaves, lo, lo+k), t.build(leaves, lo+k, hi))
	}
	t.nodes[[2]int{lo, hi}] = h
	return h
}

// Size is the number of leaves.
func (t *Tree) Size() int { return t.n }

// Root is the tree head (Root of the same leaves).
func (t *Tree) Root() []byte {
	if t.n == 0 {
		s := sha256.Sum256(nil)
		return s[:]
	}
	return t.nodes[[2]int{0, t.n}]
}

// Proof is the audit path of leaf index m, nearest sibling first (Proof
// of the same leaves).
func (t *Tree) Proof(m int) ([][]byte, error) {
	if m < 0 || m >= t.n {
		return nil, errors.New("ballot: leaf index out of range")
	}
	var out [][]byte
	lo, hi := 0, t.n
	for hi-lo > 1 {
		k := split(hi - lo)
		if m < lo+k {
			out = append(out, t.nodes[[2]int{lo + k, hi}])
			hi = lo + k
		} else {
			out = append(out, t.nodes[[2]int{lo, lo + k}])
			lo += k
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// VerifyProof checks that leaf is at index m of a tree of n leaves with
// the given root (RFC 9162 §2.1.3.2, the RFC 6962 audit path check).
func VerifyProof(root, leaf []byte, m, n int, proof [][]byte) bool {
	if m < 0 || m >= n {
		return false
	}
	fn, sn := m, n-1
	r := LeafHash(leaf)
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}
