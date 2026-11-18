package ballot

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/vote"
)

// verifyRefusal checks a refusal's v2 signature over the hash and request
// hash given, and that its body carries that hash.
func (f *boxFixture) verifyRefusal(a peer.VoteAnswer, conn, typ, code, id string, ph, reqHash []byte) {
	f.t.Helper()
	if a.Code != code {
		f.t.Fatalf("code %q, want %q", a.Code, code)
	}
	x := parseAnswer(f.t, a)
	c := sha256.Sum256(ed25519.NewKeyFromSeed(digest("peer " + conn)).Public().(ed25519.PublicKey))
	if !bytes.Equal(x.ProposalHash, ph) {
		f.t.Fatalf("%s: body proposal_hash %x, want %x", code, x.ProposalHash, ph)
	}
	msg, err := vote.RefusalMsg(ph, id, c[:], x.RecordTag, typ, code, x.MsgMS, reqHash)
	if err != nil || vote.Verify(f.ik(), vote.LabelRefusal, msg, x.RefusalSig) != nil {
		f.t.Fatalf("%s: refusal signature (%v)", code, err)
	}
}

// A cast for a proposal not held is refused under the zero hash, signing
// H(ballot_leaf) (§4.2, 0.15.0), not H(body).
func TestCastNotHeldSignsLeaf(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	body["proposal_id"] = "01JBQZ0000000000000000000Z"
	f.verifyRefusal(f.send("c0", TypeCast, body, f.during(), true), "c0", TypeCast, CodeNotEligible, body["proposal_id"], vote.NoProposal(), sum(leaf))
}

// A cast for a proposal held but not published, from a non-member, is
// refused under the zero hash too (no published proposal under the id).
func TestCastHeldUnpublishedNonMember(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	f.open.Bundle = nil
	f.verifyRefusal(f.send("x9", TypeCast, body, f.during(), true), "x9", TypeCast, CodeNotEligible, f.p.ProposalID, vote.NoProposal(), sum(leaf))
}

// A published proposal's refusal binds its hash.
func TestCastRefusalBindsHash(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	f.verifyRefusal(f.send("x9", TypeCast, body, f.during(), true), "x9", TypeCast, CodeNotEligible, f.p.ProposalID, f.v.ph, sum(leaf))
}

// A status for an unknown proposal is refused under the zero hash, with
// request_hash = H(proposal_id); for a published one from a non-member,
// under its hash.
func TestStatusRefusals(t *testing.T) {
	f := newBoxFixture(t)
	other := "01JBQZ0000000000000000000Z"
	f.verifyRefusal(f.send("c0", TypeStatus, map[string]string{"proposal_id": other}, f.during(), true), "c0", TypeStatus,
		CodeUnknownProposal, other, vote.NoProposal(), sum([]byte(other)))
	f.verifyRefusal(f.send("x9", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, f.during(), true), "x9", TypeStatus,
		CodeNotEligible, f.p.ProposalID, f.v.ph, sum([]byte(f.p.ProposalID)))
	// Held but unpublished, from a non-member: the zero hash and H(id).
	f.open.Bundle = nil
	f.verifyRefusal(f.send("x9", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, f.during(), true), "x9", TypeStatus,
		CodeUnknownProposal, f.p.ProposalID, vote.NoProposal(), sum([]byte(f.p.ProposalID)))
}

// A member's valid ballot of one proposal, sent naming another published
// proposal, is refused under that other proposal's hash and id: the
// signed id ties the refusal to the proposal the request named, so it
// can't be read as a refusal of another version of the first (§4.2).
func TestCrossProposalRefusalNamesItsID(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	// A second published proposal, Y, held by the same service.
	yID := "01JBQZ0000000000000000000Y"
	yp := *f.p
	yp.ProposalID = yID
	ydoc, err := vote.EncodeProposal(&yp)
	if err != nil {
		t.Fatal(err)
	}
	y := *f.open
	y.Doc, y.p = ydoc, nil
	f.store.proposals[yID] = &y
	body["proposal_id"] = yID
	a := f.send("x9", TypeCast, body, f.during(), true)
	x := parseAnswer(t, a)
	c := sha256.Sum256(ed25519.NewKeyFromSeed(digest("peer x9")).Public().(ed25519.PublicKey))
	ok := func(id string, ph []byte) bool {
		msg, err := vote.RefusalMsg(ph, id, c[:], x.RecordTag, TypeCast, a.Code, x.MsgMS, sum(leaf))
		return err == nil && vote.Verify(f.ik(), vote.LabelRefusal, msg, x.RefusalSig) == nil
	}
	if !ok(yID, x.ProposalHash) {
		t.Fatal("the refusal doesn't verify under the id it named")
	}
	if ok(f.p.ProposalID, x.ProposalHash) {
		t.Fatal("the refusal verifies under the ballot's own proposal id")
	}
}

// A body that forms a leaf but whose cast_sig is malformed is refused
// signing H(ballot_leaf): cast_sig is not part of the leaf.
func TestMalformedCastSigSignsLeaf(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	body["cast_sig"] = "AAAA"
	f.verifyRefusal(f.send("c0", TypeCast, body, f.during(), true), "c0", TypeCast, CodeBadBallot, f.p.ProposalID, f.v.ph, sum(leaf))
}

// The status's signed time is the request's, not the ballot's receipt time.
func TestStatusTimeIsTheRequests(t *testing.T) {
	f := newBoxFixture(t)
	body, _ := f.castBody("c0", "yes")
	if a := f.send("c0", TypeCast, body, f.during(), true); a.Code != "" {
		t.Fatalf("cast: %s", a.Code)
	}
	asked := f.during() + 7000
	x := parseAnswer(t, f.send("c0", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, asked, true))
	if x.StatusMsgMS != asked || x.MsgMS != f.during() {
		t.Fatalf("status_msg_ms %d (want %d), msg_ms %d (want %d)", x.StatusMsgMS, asked, x.MsgMS, f.during())
	}
}

// The status signature binds the proposal's hash, the connection and the
// request's time: another time or connection doesn't verify.
func TestStatusBindsTimeAndConnection(t *testing.T) {
	f := newBoxFixture(t)
	a := f.send("c0", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, f.during(), true)
	x := parseAnswer(t, a)
	tag := f.open.Members["c0"].Tag
	ok := func(ph, conn []byte, ms uint64) bool {
		msg, err := vote.StatusMsg(ph, conn, tag, nil, ms)
		return err == nil && vote.Verify(f.ik(), vote.LabelStatus, msg, x.StatusSig) == nil
	}
	if !ok(f.v.ph, x.Connection, x.StatusMsgMS) {
		t.Fatal("status signature")
	}
	other := sha256.Sum256([]byte("another"))
	if ok(f.v.ph, x.Connection, x.StatusMsgMS+1) || ok(f.v.ph, other[:], x.StatusMsgMS) || ok(other[:], x.Connection, x.StatusMsgMS) {
		t.Fatal("the status signature verifies for another time, connection or proposal")
	}
}
