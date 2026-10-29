package ballot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/vettid/service-vault/vote"
	"sync"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/vettid-vault/vms/suite"
)

// memStore is an in-memory BoxStore.
type memStore struct {
	mu        sync.Mutex
	proposals map[string]*OpenProposal
	ballots   map[string]*BallotRecord
}

func (s *memStore) OpenProposal(_ context.Context, id string) (*OpenProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proposals[id], nil
}

func (s *memStore) Ballot(_ context.Context, id string, tag []byte) (*BallotRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ballots[id+"|"+string(tag)], nil
}

func (s *memStore) PutBallot(_ context.Context, id string, rec *BallotRecord) (*BallotRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := id + "|" + string(rec.Ballot.RecordTag)
	if prev := s.ballots[k]; prev != nil {
		return prev, nil
	}
	s.ballots[k] = rec
	return rec, nil
}

// boxFixture is a three-member proposal (connections c0–c2), its box,
// and each member's keys.
type boxFixture struct {
	t     *testing.T
	v     *testVote
	box   *Box
	store *memStore
	p     *vote.Proposal
	open  *OpenProposal
	creds map[string]ed25519.PrivateKey
	vks   map[string]ed25519.PrivateKey
}

func newBoxFixture(t *testing.T) *boxFixture {
	t.Helper()
	v := newTestVote(t, 3)
	p, _ := vote.ParseProposal(v.propDoc)
	sorted := append([][]byte{}, v.tags...)
	sortTags(sorted)
	f := &boxFixture{t: t, v: v, p: p, creds: map[string]ed25519.PrivateKey{}, vks: map[string]ed25519.PrivateKey{}}
	f.open = &OpenProposal{Doc: v.propDoc, Sig: v.sign(t, vote.LabelProposal, vote.ProposalSigMsg(v.propDoc)),
		Bundle: json.RawMessage(`{}`), ClosesAt: p.ClosesAt, Members: map[string]Member{}}
	for i, tag := range v.tags {
		id := "c" + string(rune('0'+i))
		f.open.Members[id] = Member{Tag: tag, Secret: digest(string(rune('a' + i)))}
		f.creds[id] = ed25519.NewKeyFromSeed(digest("credential " + id))
		f.vks[id] = ed25519.NewKeyFromSeed(digest("vk " + id))
	}
	f.store = &memStore{proposals: map[string]*OpenProposal{p.ProposalID: f.open}, ballots: map[string]*BallotRecord{}}
	f.box = &Box{Store: f.store, Sign: func(label string, msg []byte) ([]byte, error) { return suite.Sign(v.ik, label, msg) }}
	return f
}

func (f *boxFixture) ik() ed25519.PublicKey { return f.v.ik.Public().(ed25519.PublicKey) }

// castBody is a member's vote.cast, signed with its keys.
func (f *boxFixture) castBody(conn, choice string) (map[string]string, []byte) {
	f.t.Helper()
	m := f.open.Members[conn]
	vk := f.vks[conn]
	b := vote.Ballot{RecordTag: m.Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: choice}
	msg, _ := b.Msg(f.v.ph)
	b.BallotSig, _ = suite.Sign(vk, vote.LabelBallot, msg)
	leaf, _ := b.Leaf()
	cmsg, _ := vote.CastMsg(f.v.ph, leaf)
	csig, _ := suite.Sign(f.creds[conn], vote.LabelCast, cmsg)
	e := base64.StdEncoding.EncodeToString
	return map[string]string{"proposal_id": f.p.ProposalID, "record_tag": e(m.Tag), "vk": e(b.VK),
		"choice_id": choice, "ballot_sig": e(b.BallotSig), "cast_sig": e(csig)}, leaf
}

func (f *boxFixture) send(conn, typ string, body any, ms uint64, active bool) peer.VoteAnswer {
	f.t.Helper()
	j, _ := json.Marshal(body)
	var cred []byte
	if k, ok := f.creds[conn]; ok {
		cred = k.Public().(ed25519.PublicKey)
	}
	a, err := f.box.Vote(context.Background(), &peer.VoteRequest{ConnectionID: conn,
		PeerIK:        ed25519.NewKeyFromSeed(digest("peer " + conn)).Public().(ed25519.PublicKey),
		CredentialKey: cred, Active: active, Type: typ, Body: j, MsgMS: ms})
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

func (f *boxFixture) during() uint64 { return uint64(f.p.OpensAt)*1000 + 5000 }

type answer struct {
	ProposalID  string          `json:"proposal_id"`
	MsgMS       uint64          `json:"msg_ms"`
	ReceiptSig  []byte          `json:"receipt_sig"`
	RefusalSig  []byte          `json:"refusal_sig"`
	Connection  []byte          `json:"connection"`
	RecordTag   []byte          `json:"record_tag"`
	Ballot      *rowBallotJSON  `json:"ballot"`
	BallotMsgMS uint64          `json:"ballot_msg_ms"`
	Proposal    []byte          `json:"proposal"`
	Secret      []byte          `json:"record_secret"`
	RecordProof recordProof     `json:"record_proof"`
	StatusSig   []byte          `json:"status_sig"`
	Bundle      json.RawMessage `json:"bundle"`
}

func parseAnswer(t *testing.T, a peer.VoteAnswer) answer {
	t.Helper()
	var x answer
	if err := json.Unmarshal(a.Body, &x); err != nil {
		t.Fatal(err)
	}
	return x
}

// The refusal's signature holds, for this connection, tag, code and time.
func (f *boxFixture) checkRefusal(a peer.VoteAnswer, conn, code string, tag, reqHash []byte) {
	f.t.Helper()
	if a.Code != code {
		f.t.Fatalf("code %q, want %q", a.Code, code)
	}
	x := parseAnswer(f.t, a)
	peerIK := ed25519.NewKeyFromSeed(digest("peer " + conn)).Public().(ed25519.PublicKey)
	c := sha256.Sum256(peerIK)
	if !bytes.Equal(x.Connection, c[:]) || !bytes.Equal(x.RecordTag, tag) {
		f.t.Fatalf("%s: refusal names another connection or tag", code)
	}
	msg, _ := vote.RefusalMsg(f.p.ProposalID, c[:], tag, TypeCast, code, x.MsgMS, reqHash)
	if vote.Verify(f.ik(), vote.LabelRefusal, msg, x.RefusalSig) != nil {
		f.t.Fatalf("%s: refusal signature", code)
	}
}

func TestCastAndReceipt(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	a := f.send("c0", TypeCast, body, f.during(), true)
	if a.Code != "" {
		t.Fatalf("refused: %s", a.Code)
	}
	x := parseAnswer(t, a)
	rmsg, _ := vote.ReceiptMsg(f.v.ph, leaf, f.during())
	if x.MsgMS != f.during() || vote.Verify(f.ik(), vote.LabelReceipt, rmsg, x.ReceiptSig) != nil {
		t.Fatal("receipt doesn't verify")
	}
	rec, _ := f.store.Ballot(context.Background(), f.p.ProposalID, f.open.Members["c0"].Tag)
	if rec == nil || rec.ConnectionID != "c0" || len(rec.CastSig) != vote.SigLen {
		t.Fatal("the record lacks the connection or the credential signature")
	}
	// The same bytes again, even after the close, get the same receipt.
	again := f.send("c0", TypeCast, body, uint64(f.p.ClosesAt)*1000+60000, true)
	if again.Code != "" || !bytes.Equal(parseAnswer(t, again).ReceiptSig, x.ReceiptSig) {
		t.Fatal("a retry wasn't answered with the stored receipt")
	}
	// A different ballot is already_voted, with the recorded one.
	other, otherLeaf := f.castBody("c0", "no")
	av := f.send("c0", TypeCast, other, f.during()+1, true)
	f.checkRefusal(av, "c0", CodeAlreadyVoted, f.open.Members["c0"].Tag, sum(otherLeaf))
	if y := parseAnswer(t, av); y.Ballot == nil || y.Ballot.ChoiceID != "yes" || !bytes.Equal(y.ReceiptSig, x.ReceiptSig) {
		t.Fatal("already_voted doesn't carry the recorded ballot")
	}
}

func TestCastRefusals(t *testing.T) {
	f := newBoxFixture(t)
	tag := func(c string) []byte { return f.open.Members[c].Tag }
	body, leaf := f.castBody("c1", "yes")
	h := sum(leaf)

	f.checkRefusal(f.send("c1", TypeCast, body, uint64(f.p.OpensAt)*1000-1, true), "c1", CodeNotOpen, tag("c1"), h)
	f.checkRefusal(f.send("c1", TypeCast, body, uint64(f.p.ClosesAt)*1000, true), "c1", CodeClosed, tag("c1"), h)
	f.checkRefusal(f.send("c1", TypeCast, body, f.during(), false), "c1", CodeNotActive, tag("c1"), h)
	f.checkRefusal(f.send("x9", TypeCast, body, f.during(), true), "x9", CodeNotEligible, []byte{}, h)
	// c2 sending c1's tag.
	f.checkRefusal(f.send("c2", TypeCast, body, f.during(), true), "c2", CodeBadBallot, tag("c2"), h)

	bad := func(mut func(map[string]string)) peer.VoteAnswer {
		b, _ := f.castBody("c1", "yes")
		mut(b)
		return f.send("c1", TypeCast, b, f.during(), true)
	}
	for name, mut := range map[string]func(map[string]string){
		"ballot signature": func(b map[string]string) { b["ballot_sig"] = b["cast_sig"] },
		"cast signature":   func(b map[string]string) { b["cast_sig"] = b["ballot_sig"] },
		"unknown choice":   func(b map[string]string) { b["choice_id"] = "maybe" },
		"short vk":         func(b map[string]string) { b["vk"] = "AAAA" },
		"unpadded":         func(b map[string]string) { b["record_tag"] = b["record_tag"][:43] },
	} {
		if a := bad(mut); a.Code != CodeBadBallot {
			t.Errorf("%s: %q", name, a.Code)
		}
	}
	// None of those recorded anything; a good cast still goes through.
	if a := f.send("c1", TypeCast, body, f.during(), true); a.Code != "" {
		t.Fatalf("good cast refused: %s", a.Code)
	}
	// After the results: late.
	f.open.Published = true
	b2, l2 := f.castBody("c2", "no")
	f.checkRefusal(f.send("c2", TypeCast, b2, f.during(), true), "c2", CodeLate, tag("c2"), sum(l2))
}

func TestCastExtensionAndRemoval(t *testing.T) {
	f := newBoxFixture(t)
	f.open.ClosesAt = f.p.ClosesAt + 3600
	body, _ := f.castBody("c0", "no")
	if a := f.send("c0", TypeCast, body, uint64(f.p.ClosesAt)*1000+1000, true); a.Code != "" {
		t.Fatalf("a cast inside the extension refused: %s", a.Code)
	}
	// removed_may_vote lets an inactive connection vote.
	f.p.RemovedMayVote = true
	f.open.p = f.p
	b1, _ := f.castBody("c1", "yes")
	if a := f.send("c1", TypeCast, b1, f.during(), false); a.Code != "" {
		t.Fatalf("removed member refused: %s", a.Code)
	}
}

// A member who has never signed in has no pinned credential key, and is
// refused even if the ballot names a key that signs it: the service could
// make up both, so such a ballot would prove nothing (BALLOT-PROTOCOL §5).
func TestCastNeedsSignIn(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	body["credential_key"] = base64.StdEncoding.EncodeToString(f.creds["c0"].Public().(ed25519.PublicKey))
	j, _ := json.Marshal(body)
	a, err := f.box.Vote(context.Background(), &peer.VoteRequest{ConnectionID: "c0",
		PeerIK: ed25519.NewKeyFromSeed(digest("peer c0")).Public().(ed25519.PublicKey), Active: true, Type: TypeCast, Body: j, MsgMS: f.during()})
	if err != nil {
		t.Fatal(err)
	}
	f.checkRefusal(a, "c0", CodeNotSignedIn, f.open.Members["c0"].Tag, sum(leaf))
	if rec, _ := f.store.Ballot(context.Background(), f.p.ProposalID, f.open.Members["c0"].Tag); rec != nil {
		t.Fatal("a ballot was recorded")
	}
}

func TestStatus(t *testing.T) {
	f := newBoxFixture(t)
	q := map[string]string{"proposal_id": f.p.ProposalID}
	check := func(a peer.VoteAnswer, wantBallot bool) answer {
		t.Helper()
		if a.Code != "" {
			t.Fatalf("status refused: %s", a.Code)
		}
		x := parseAnswer(t, a)
		m := f.open.Members["c0"]
		if !bytes.Equal(x.Proposal, f.v.propDoc) || !bytes.Equal(x.Secret, m.Secret) {
			t.Fatal("status lacks the proposal or the tag's secret")
		}
		if !vote.VerifyProof(f.p.RecordRoot, m.Tag, x.RecordProof.Index, int(x.RecordProof.TreeSize), x.RecordProof.Path) {
			t.Fatal("record proof")
		}
		var leaf []byte
		if wantBallot {
			if x.Ballot == nil {
				t.Fatal("no ballot")
			}
			leaf, _ = (&vote.Ballot{RecordTag: m.Tag, VK: x.Ballot.VK, ChoiceID: x.Ballot.ChoiceID, BallotSig: x.Ballot.BallotSig}).Leaf()
		} else if x.Ballot != nil {
			t.Fatal("a ballot before any cast")
		}
		smsg, _ := vote.StatusMsg(f.p.ProposalID, m.Tag, leaf)
		if vote.Verify(f.ik(), vote.LabelStatus, smsg, x.StatusSig) != nil {
			t.Fatal("status signature")
		}
		return x
	}
	check(f.send("c0", TypeStatus, q, f.during(), true), false)
	body, _ := f.castBody("c0", "abstain")
	f.send("c0", TypeCast, body, f.during(), true)
	if x := check(f.send("c0", TypeStatus, q, f.during(), true), true); x.Ballot.ChoiceID != vote.AbstainID {
		t.Fatal("status names another ballot")
	}
	if a := f.send("x9", TypeStatus, q, f.during(), true); a.Code != CodeNotEligible {
		t.Fatalf("stranger: %q", a.Code)
	}
	if a := f.send("c0", TypeStatus, map[string]string{"proposal_id": "01JBQZ0000000000000000000B"}, f.during(), true); a.Code != CodeUnknownProposal {
		t.Fatalf("unknown proposal: %q", a.Code)
	}
}

// A proposal not yet published (no bundle, §3.3) is no member's to cast
// on or ask about.
func TestUnpublishedProposal(t *testing.T) {
	f := newBoxFixture(t)
	f.open.Bundle = nil
	body, _ := f.castBody("c0", "yes")
	if a := f.send("c0", TypeCast, body, f.during(), true); a.Code != CodeNotEligible {
		t.Fatalf("cast: %q", a.Code)
	}
	q := map[string]string{"proposal_id": f.p.ProposalID}
	if a := f.send("c0", TypeStatus, q, f.during(), true); a.Code != CodeUnknownProposal {
		t.Fatalf("status: %q", a.Code)
	}
	f.open.Bundle = json.RawMessage(`{}`)
	if a := f.send("c0", TypeStatus, q, f.during(), true); a.Code != "" {
		t.Fatalf("status once published: %q", a.Code)
	}
}
