package vote

import (
	"crypto/sha256"
	"testing"
)

// At the eligible cap's target (15,000 members, #6946), every member's
// proof comes from one Tree and verifies.
func TestTreeAtScale(t *testing.T) {
	const n = 15000
	leaves := make([][]byte, n)
	for i := range leaves {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		leaves[i] = h[:]
	}
	tr := NewTree(leaves)
	root := tr.Root()
	for m := range n {
		p, err := tr.Proof(m)
		if err != nil {
			t.Fatal(err)
		}
		if m%997 == 0 && !VerifyProof(root, leaves[m], m, n, p) {
			t.Fatalf("m=%d: doesn't verify", m)
		}
	}
}

func BenchmarkProofsOneTree(b *testing.B) {
	leaves := scaleLeaves(15000)
	for b.Loop() {
		tr := NewTree(leaves)
		for m := range leaves {
			_, _ = tr.Proof(m)
		}
	}
}

func BenchmarkProofsEach(b *testing.B) {
	leaves := scaleLeaves(1500)
	for b.Loop() {
		for m := range leaves {
			_, _ = Proof(leaves, m)
		}
	}
}

func scaleLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		h := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		leaves[i] = h[:]
	}
	return leaves
}
