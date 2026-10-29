package ballot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sort"
	"testing"

	"filippo.io/edwards25519"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The vectors of BALLOT-PROTOCOL §11 (items 1, 2 and 4) from fixed inputs.
// vettid-vault copies testdata/vectors.json; run with UPDATE_VECTORS=1 to
// rewrite it after a deliberate change to the protocol.
type vectors struct {
	ProposalID   string `json:"proposal_id"`
	ProposalHash string `json:"proposal_hash"`
	RecordSecret string `json:"record_secret"`
	RecordTag    string `json:"record_tag"`
	VKSeed       string `json:"vk_seed"`
	VK           string `json:"vk"`
	ChoiceID     string `json:"choice_id"`
	BallotMsg    string `json:"ballot_msg"`
	BallotSig    string `json:"ballot_sig"`
	BallotLeaf   string `json:"ballot_leaf"`
	Credential   struct {
		Seed    string `json:"seed"`
		Key     string `json:"key"`
		CastMsg string `json:"cast_msg"`
		CastSig string `json:"cast_sig"`
	} `json:"credential"`
	Service struct {
		Seed       string `json:"seed"`
		IK         string `json:"ik"`
		MsgMS      uint64 `json:"msg_ms"`
		ReceiptMsg string `json:"receipt_msg"`
		ReceiptSig string `json:"receipt_sig"`
		StatusMsg  string `json:"status_msg"`
		StatusSig  string `json:"status_sig"`
		Refusal    struct {
			Connection  string `json:"connection"`
			Type        string `json:"type"`
			Code        string `json:"code"`
			RequestHash string `json:"request_hash"`
			Msg         string `json:"msg"`
			Sig         string `json:"sig"`
		} `json:"refusal"`
	} `json:"service"`
	Merkle  []merkleVector `json:"merkle"`
	Ed25519 []sigVector    `json:"ed25519"`
}

type merkleVector struct {
	Leaves []string   `json:"leaves"`
	Root   string     `json:"root"`
	Proofs [][]string `json:"proofs,omitempty"`
}

// sigVector is one §2 verification case, over label LabelBallot.
type sigVector struct {
	Case  string `json:"case"`
	Key   string `json:"key"`
	Msg   string `json:"msg"`
	Sig   string `json:"sig"`
	Valid bool   `json:"valid"`
}

func h(b []byte) string { return hex.EncodeToString(b) }

func digest(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }

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
	ph := digest("example proposal bytes")
	v.ProposalHash = h(ph)
	secret := digest("example record secret")
	v.RecordSecret = h(secret)
	tag := must(RecordTag(v.ProposalID, secret))
	v.RecordTag = h(tag)

	seed := digest("example voting key seed")
	sk := ed25519.NewKeyFromSeed(seed)
	vk := sk.Public().(ed25519.PublicKey)
	v.VKSeed, v.VK, v.ChoiceID = h(seed), h(vk), "yes"
	msg := must(BallotMsg(ph, tag, v.ChoiceID))
	sig := must(suite.Sign(sk, LabelBallot, msg))
	v.BallotMsg, v.BallotSig = h(msg), h(sig)
	b := &Ballot{RecordTag: tag, VK: vk, ChoiceID: v.ChoiceID, BallotSig: sig}
	leaf := must(b.Leaf())
	v.BallotLeaf = h(leaf)

	cseed := digest("example credential key seed")
	csk := ed25519.NewKeyFromSeed(cseed)
	cast := must(CastMsg(ph, leaf))
	v.Credential.Seed, v.Credential.Key = h(cseed), h(csk.Public().(ed25519.PublicKey))
	v.Credential.CastMsg, v.Credential.CastSig = h(cast), h(must(suite.Sign(csk, LabelCast, cast)))

	s := &v.Service
	sseed := digest("example service identity seed")
	ssk := ed25519.NewKeyFromSeed(sseed)
	s.Seed, s.IK, s.MsgMS = h(sseed), h(ssk.Public().(ed25519.PublicKey)), 1793606400123
	receipt := must(ReceiptMsg(ph, leaf, s.MsgMS))
	s.ReceiptMsg, s.ReceiptSig = h(receipt), h(must(suite.Sign(ssk, LabelReceipt, receipt)))
	status := must(StatusMsg(v.ProposalID, tag, leaf))
	s.StatusMsg, s.StatusSig = h(status), h(must(suite.Sign(ssk, LabelStatus, status)))
	r := &s.Refusal
	conn := digest("example connection peer key")
	r.Connection, r.Type, r.Code, r.RequestHash = h(conn), "vote.cast", "bad_ballot", h(digest(string(leaf)))
	refusal := must(RefusalMsg(v.ProposalID, conn, tag, r.Type, r.Code, s.MsgMS, digest(string(leaf))))
	r.Msg, r.Sig = h(refusal), h(must(suite.Sign(ssk, LabelRefusal, refusal)))

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
	v.Ed25519 = sigVectors(t, sk, msg)
	return &v
}

// sigVectors builds §11 item 4: a valid signature, and refused cases for
// §2's rules. The refused key cases are signatures Go's ed25519.Verify
// accepts (R = the identity, S = 0, and a message for which [k]A is the
// identity), so they exercise the rules it lacks.
func sigVectors(t *testing.T, sk ed25519.PrivateKey, msg []byte) []sigVector {
	t.Helper()
	pub := sk.Public().(ed25519.PublicKey)
	sig, err := suite.Sign(sk, LabelBallot, msg)
	if err != nil {
		t.Fatal(err)
	}
	out := []sigVector{{Case: "valid", Key: h(pub), Msg: h(msg), Sig: h(sig), Valid: true}}
	identity := append([]byte{0x01}, make([]byte, 31)...)
	forged := append(append([]byte{}, identity...), make([]byte, 32)...) // R = identity, S = 0
	forge := func(c string, key []byte) {
		t.Helper()
		m, err := forgeMsg(key, msg)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		out = append(out, sigVector{Case: c, Key: h(key), Msg: h(m), Sig: h(forged)})
	}
	for i, p := range smallOrderPoints(t) {
		forge("small-order key and R "+string(rune('0'+i)), p)
	}
	// y = p + 1: a non-canonical encoding of the identity.
	forge("key with y not below p", append(append([]byte{0xee}, bytes.Repeat([]byte{0xff}, 30)...), 0x7f))
	forge("key with x = 0 and the sign bit", append(append([]byte{0x01}, make([]byte, 30)...), 0x80))
	// S + L: the valid signature with a non-canonical S.
	out = append(out, sigVector{Case: "S not below L", Key: h(pub), Msg: h(msg),
		Sig: h(append(append([]byte{}, sig[:32]...), addL(sig[32:])...))})
	return out
}

// forgeMsg finds a message m' = msg ‖ i for which R = identity, S = 0 is a
// signature ed25519.Verify accepts under the small-order key: [k]A must be
// the identity, k = SHA-512(R ‖ A ‖ label ‖ m') mod L.
func forgeMsg(key, msg []byte) ([]byte, error) {
	a, err := new(edwards25519.Point).SetBytes(key)
	if err != nil {
		return nil, err
	}
	identity := append([]byte{0x01}, make([]byte, 31)...)
	for i := range 256 {
		m := append(append([]byte{}, msg...), byte(i))
		d := sha512.Sum512(append(append(append(append([]byte{}, identity...), key...), LabelBallot...), m...))
		k, err := new(edwards25519.Scalar).SetUniformBytes(d[:])
		if err != nil {
			return nil, err
		}
		if new(edwards25519.Point).ScalarMult(k, a).Equal(edwards25519.NewIdentityPoint()) == 1 {
			return m, nil
		}
	}
	return nil, errors.New("no message found")
}

// smallOrderPoints returns the canonical encodings of the eight points of
// order dividing 8: the torsion parts [L]P of points P from fixed hashes.
func smallOrderPoints(t *testing.T) [][]byte {
	t.Helper()
	lMinus1 := make([]byte, 32)
	l := lOrder()
	new(big.Int).Sub(l, big.NewInt(1)).FillBytes(lMinus1)
	reverse(lMinus1)
	k, err := new(edwards25519.Scalar).SetCanonicalBytes(lMinus1)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; len(seen) < 8 && i < 10000; i++ {
		p, err := new(edwards25519.Point).SetBytes(digest(string(rune(i)) + "torsion"))
		if err != nil {
			continue
		}
		torsion := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(k, p), p) // [L]P
		seen[string(torsion.Bytes())] = true
	}
	if len(seen) != 8 {
		t.Fatalf("found %d small-order points", len(seen))
	}
	out := make([][]byte, 0, 8)
	for s := range seen {
		out = append(out, []byte(s))
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func lOrder() *big.Int {
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	return l
}

func reverse(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// addL returns the little-endian 32-byte S + L.
func addL(s []byte) []byte {
	be := append([]byte{}, s...)
	reverse(be)
	n := new(big.Int).Add(new(big.Int).SetBytes(be), lOrder())
	out := n.FillBytes(make([]byte, 32))
	reverse(out)
	return out
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

// Verify accepts exactly the valid vector, and Go's ed25519.Verify alone
// would accept some of the refused ones, which is why the rules exist.
func TestVerifyRules(t *testing.T) {
	v := makeVectors(t)
	goAccepts := 0
	for _, c := range v.Ed25519 {
		key, _ := hex.DecodeString(c.Key)
		msg, _ := hex.DecodeString(c.Msg)
		sig, _ := hex.DecodeString(c.Sig)
		if err := Verify(key, LabelBallot, msg, sig); (err == nil) != c.Valid {
			t.Errorf("%s: Verify = %v, want valid %v", c.Case, err, c.Valid)
		}
		if !c.Valid && len(key) == 32 && ed25519.Verify(key, append([]byte(LabelBallot), msg...), sig) {
			goAccepts++
		}
	}
	if goAccepts == 0 {
		t.Error("no refused case is one ed25519.Verify accepts: the vectors don't exercise the extra rules")
	}
	// A signature over another label or message fails.
	sig, _ := hex.DecodeString(v.BallotSig)
	vk, _ := hex.DecodeString(v.VK)
	msg, _ := hex.DecodeString(v.BallotMsg)
	if Verify(vk, LabelBallot, msg, sig) != nil {
		t.Fatal("ballot signature refused")
	}
	if Verify(vk, LabelCast, msg, sig) == nil || Verify(vk, LabelBallot, msg[1:], sig) == nil {
		t.Fatal("signature accepted under another label or message")
	}
}

// The encodings refuse fields out of bounds.
func TestEncodingBounds(t *testing.T) {
	ph, tag := digest("p"), digest("t")
	for _, c := range []string{"", "Yes", "a b", string(bytes.Repeat([]byte{'a'}, 33))} {
		if _, err := BallotMsg(ph, tag, c); err == nil {
			t.Fatalf("choice %q accepted", c)
		}
	}
	if _, err := BallotMsg(ph[:31], tag, "yes"); err == nil {
		t.Fatal("short proposal hash")
	}
	if _, err := BallotMsg(ph, tag[:31], "yes"); err == nil {
		t.Fatal("short tag")
	}
	for _, id := range []string{"01jbqz0000000000000000000a", "81JBQZ0000000000000000000A", "01JBQZ000000000000000000IA", "01JBQZ"} {
		if ValidProposalID(id) {
			t.Fatalf("proposal id %q accepted", id)
		}
		if _, err := RecordTag(id, make([]byte, SecretLen)); err == nil {
			t.Fatalf("tag for %q", id)
		}
	}
	good := Ballot{RecordTag: tag, VK: make([]byte, VKLen), ChoiceID: "yes", BallotSig: make([]byte, SigLen)}
	for name, bad := range map[string]Ballot{
		"short tag": {RecordTag: tag[:31], VK: good.VK, ChoiceID: "yes", BallotSig: good.BallotSig},
		"short vk":  {RecordTag: tag, VK: good.VK[:31], ChoiceID: "yes", BallotSig: good.BallotSig},
		"short sig": {RecordTag: tag, VK: good.VK, ChoiceID: "yes", BallotSig: good.BallotSig[:63]},
		"choice":    {RecordTag: tag, VK: good.VK, ChoiceID: "Yes", BallotSig: good.BallotSig},
	} {
		if _, err := bad.Leaf(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := good.Leaf(); err != nil {
		t.Fatal(err)
	}
	if _, err := RefusalMsg("01JBQZ0000000000000000000A", ph, nil, "vote.cast", "", 0, ph); err == nil {
		t.Fatal("empty code accepted")
	}
	if _, err := StatusMsg("01JBQZ0000000000000000000A", tag[:5], nil); err == nil {
		t.Fatal("short tag accepted")
	}
}
