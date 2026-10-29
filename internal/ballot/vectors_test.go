package ballot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

// The encoding and Merkle vectors of BALLOT-PROTOCOL §11 (items 3 and 5,
// with the tags and the leaf), from fixed inputs. vettid-vault copies
// testdata/vectors.json; run with UPDATE_VECTORS=1 to rewrite it after a
// deliberate change to the protocol.
type vectors struct {
	ProposalID   string `json:"proposal_id"`
	ProposalHash string `json:"proposal_hash"`
	VKSeed       string `json:"vk_seed"`
	VK           string `json:"vk"`
	CertMsg      string `json:"cert_msg"`
	Ballot       struct {
		Seq       uint32 `json:"seq"`
		PoolSeq   uint32 `json:"pool_seq"`
		PoolHash  string `json:"pool_hash"`
		ChoiceID  string `json:"choice_id"`
		BallotMsg string `json:"ballot_msg"`
		BallotSig string `json:"ballot_sig"`
	} `json:"ballot"`
	RecordSecret string `json:"record_secret"`
	RecordTag    string `json:"record_tag"`
	IssuedTag    string `json:"issued_tag"`
	Leaf         struct {
		CertPrefix string `json:"cert_prefix"`
		CertSig    string `json:"cert_sig"`
		Day        string `json:"day"`
		Leaf       string `json:"leaf"`
		LeafHash   string `json:"leaf_hash"`
	} `json:"leaf"`
	Merkle []merkleVector `json:"merkle"`
}

type merkleVector struct {
	Leaves []string   `json:"leaves"`
	Root   string     `json:"root"`
	Proofs [][]string `json:"proofs,omitempty"`
}

func h(b []byte) string { return hex.EncodeToString(b) }

func sum(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }

func makeVectors(t *testing.T) *vectors {
	t.Helper()
	var v vectors
	must := func(b []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v.ProposalID = "01JBQZ0000000000000000000A"
	ph := sum("example proposal bytes")
	v.ProposalHash = h(ph)
	seed := sum("example voting key seed")
	sk := ed25519.NewKeyFromSeed(seed)
	vk := sk.Public().(ed25519.PublicKey)
	v.VKSeed, v.VK = h(seed), h(vk)
	v.CertMsg = h(must(CertMsg(ph, vk)))

	b := &v.Ballot
	b.Seq, b.PoolSeq, b.ChoiceID = 2, 1, "yes"
	poolHash := sum("example pool bytes")
	b.PoolHash = h(poolHash)
	msg := must(BallotMsg(ph, b.Seq, b.PoolSeq, poolHash, b.ChoiceID))
	b.BallotMsg = h(msg)
	sig := must(suite.Sign(sk, BallotLabel, msg))
	b.BallotSig = h(sig)

	secret := sum("example record secret")
	v.RecordSecret = h(secret)
	v.RecordTag = h(must(RecordTag(v.ProposalID, secret)))
	v.IssuedTag = h(must(IssuedTag(v.ProposalID, secret)))

	prefix, certSig := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 256)
	l := &v.Leaf
	l.CertPrefix, l.CertSig, l.Day = h(prefix), h(certSig), "2026-11-02"
	leaf := must((&Ballot{VK: vk, CertPrefix: prefix, CertSig: certSig, Seq: b.Seq, PoolSeq: b.PoolSeq, PoolHash: poolHash,
		ChoiceID: b.ChoiceID, BallotSig: sig, Day: l.Day}).Leaf())
	l.Leaf, l.LeafHash = h(leaf), h(LeafHash(leaf))

	for _, n := range []int{0, 1, 2, 3, 5, 8} {
		leaves := make([][]byte, n)
		mv := merkleVector{Leaves: []string{}}
		for i := range leaves {
			leaves[i] = []byte{byte('a' + i)}
			mv.Leaves = append(mv.Leaves, h(leaves[i]))
		}
		mv.Root = h(Root(leaves))
		if n == 5 {
			for m := range n {
				p, _ := Proof(leaves, m)
				ps := []string{}
				for _, x := range p {
					ps = append(ps, h(x))
				}
				mv.Proofs = append(mv.Proofs, ps)
			}
		}
		v.Merkle = append(v.Merkle, mv)
	}
	return &v
}

func TestVectors(t *testing.T) {
	got, err := json.MarshalIndent(makeVectors(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const path = "testdata/vectors.json"
	if os.Getenv("UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the vectors differ from testdata/vectors.json: a protocol change needs UPDATE_VECTORS=1 and a note in BALLOT-PROTOCOL's Changes")
	}
}

// The encodings refuse fields out of bounds.
func TestEncodingBounds(t *testing.T) {
	ph, vk, ph2 := sum("p"), make([]byte, VKLen), sum("q")
	if _, err := CertMsg(ph[:31], vk); err == nil {
		t.Fatal("short proposal hash")
	}
	if _, err := CertMsg(ph, vk[:31]); err == nil {
		t.Fatal("short vk")
	}
	for _, c := range []string{"", "Yes", "a b", string(bytes.Repeat([]byte{'a'}, 33))} {
		if _, err := BallotMsg(ph, 1, 1, ph2, c); err == nil {
			t.Fatalf("choice %q accepted", c)
		}
	}
	if _, err := BallotMsg(ph, 0, 1, ph2, "yes"); err == nil {
		t.Fatal("seq 0 accepted")
	}
	for _, id := range []string{"01jbqz0000000000000000000a", "81JBQZ0000000000000000000A", "01JBQZ000000000000000000IA", "01JBQZ"} {
		if ValidProposalID(id) {
			t.Fatalf("proposal id %q accepted", id)
		}
		if _, err := RecordTag(id, make([]byte, SecretLen)); err == nil {
			t.Fatalf("tag for %q", id)
		}
	}
	if _, err := (&Ballot{VK: vk, PoolHash: ph, ChoiceID: "yes", Day: "2026-1-2"}).Leaf(); err == nil {
		t.Fatal("bad day accepted")
	}
}
