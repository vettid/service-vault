package vote

import (
	"encoding/hex"
	"testing"
)

// Certificate Transparency's RFC 6962 known-answer tree: these eight
// leaves and the roots of their first n.
var ctLeaves = []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"}

var ctRoots = []string{
	"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
	"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func ctTree(t *testing.T, n int) [][]byte {
	t.Helper()
	out := make([][]byte, n)
	for i := range n {
		b, err := hex.DecodeString(ctLeaves[i])
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestMerkleKnownAnswers(t *testing.T) {
	if got := hex.EncodeToString(Root(nil)); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty tree %s", got)
	}
	for n := 1; n <= 8; n++ {
		if got := hex.EncodeToString(Root(ctTree(t, n))); got != ctRoots[n-1] {
			t.Fatalf("root of %d: %s, want %s", n, got, ctRoots[n-1])
		}
	}
}

// Every proof of every leaf, in trees of 1 to 33 leaves, verifies with
// the RFC 9162 algorithm, and fails for another index, another tree's
// root, another leaf or a shortened path. (An audit path doesn't bind
// the size by itself; the size is published with the root.)
func TestMerkleProofs(t *testing.T) {
	for n := 1; n <= 33; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte{byte(i), byte(n)}
		}
		root := Root(leaves)
		for m := range n {
			p, err := Proof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyProof(root, leaves[m], m, n, p) {
				t.Fatalf("n=%d m=%d: proof does not verify", n, m)
			}
			if n > 1 && VerifyProof(root, leaves[m], (m+1)%n, n, p) {
				t.Fatalf("n=%d m=%d: verified at another index", n, m)
			}
			if VerifyProof(Root(append(leaves, []byte("extra"))), leaves[m], m, n+1, p) {
				t.Fatalf("n=%d m=%d: verified against another tree's root", n, m)
			}
			if VerifyProof(root, []byte("other"), m, n, p) {
				t.Fatalf("n=%d m=%d: verified another leaf", n, m)
			}
			if len(p) > 0 && VerifyProof(root, leaves[m], m, n, p[:len(p)-1]) {
				t.Fatalf("n=%d m=%d: a shortened path verified", n, m)
			}
		}
	}
	if _, err := Proof(nil, 0); err == nil {
		t.Fatal("a proof in an empty tree")
	}
}
