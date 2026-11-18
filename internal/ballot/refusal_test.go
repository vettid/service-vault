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
func (f *boxFixture) verifyRefusal(a peer.VoteAnswer, conn, typ, code string, ph, reqHash []byte) {
	f.t.Helper()
	if a.Code != code {
		f.t.Fatalf("code %q, want %q", a.Code, code)
	}
	x := parseAnswer(f.t, a)
	c := sha256.Sum256(ed25519.NewKeyFromSeed(digest("peer " + conn)).Public().(ed25519.PublicKey))
	if !bytes.Equal(x.ProposalHash, ph) {
		f.t.Fatalf("%s: body proposal_hash %x, want %x", code, x.ProposalHash, ph)
	}
	msg, err := vote.RefusalMsg(ph, c[:], x.RecordTag, typ, code, x.MsgMS, reqHash)
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
	f.verifyRefusal(f.send("c0", TypeCast, body, f.during(), true), "c0", TypeCast, CodeNotEligible, vote.NoProposal, sum(leaf))
}

// A cast for a proposal held but not published, from a non-member, is
// refused under the zero hash too (no published proposal under the id).
func TestCastHeldUnpublishedNonMember(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	f.open.Bundle = nil
	f.verifyRefusal(f.send("x9", TypeCast, body, f.during(), true), "x9", TypeCast, CodeNotEligible, vote.NoProposal, sum(leaf))
}

// A published proposal's refusal binds its hash.
func TestCastRefusalBindsHash(t *testing.T) {
	f := newBoxFixture(t)
	body, leaf := f.castBody("c0", "yes")
	f.verifyRefusal(f.send("x9", TypeCast, body, f.during(), true), "x9", TypeCast, CodeNotEligible, f.v.ph, sum(leaf))
}

// A status for an unknown proposal is refused under the zero hash, with
// request_hash = H(proposal_id); for a published one from a non-member,
// under its hash.
func TestStatusRefusals(t *testing.T) {
	f := newBoxFixture(t)
	other := "01JBQZ0000000000000000000Z"
	f.verifyRefusal(f.send("c0", TypeStatus, map[string]string{"proposal_id": other}, f.during(), true), "c0", TypeStatus,
		CodeUnknownProposal, vote.NoProposal, sum([]byte(other)))
	f.verifyRefusal(f.send("x9", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, f.during(), true), "x9", TypeStatus,
		CodeNotEligible, f.v.ph, sum([]byte(f.p.ProposalID)))
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
