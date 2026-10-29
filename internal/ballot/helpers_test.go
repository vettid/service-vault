package ballot

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/suite"
)

func digest(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }

// testVote is a signed proposal over n eligible tags, as the service
// makes one.
type testVote struct {
	ik      ed25519.PrivateKey
	propDoc []byte
	ph      []byte
	tags    [][]byte
}

func newTestVote(t *testing.T, n int) *testVote {
	t.Helper()
	v := &testVote{ik: ed25519.NewKeyFromSeed(digest("service ik"))}
	for i := range n {
		tag, _ := vote.RecordTag("01JBQZ0000000000000000000A", digest(string(rune('a'+i))))
		v.tags = append(v.tags, tag)
	}
	sorted := append([][]byte{}, v.tags...)
	sortTags(sorted)
	p := &vote.Proposal{
		V: 1, ProposalID: "01JBQZ0000000000000000000A", Service: v.ik.Public().(ed25519.PublicKey),
		Title: "Adopt the 2027 budget", Text: "The budget as circulated on 1 November.",
		Choices:  []vote.Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}, {ID: vote.AbstainID, Label: "Abstain"}},
		Quorum:   vote.Quorum{Text: "A third of the members", MinBallots: 1},
		RecordAt: 1793500000, OpensAt: 1793520000, ClosesAt: 1793520000 + 3*86400,
		Eligible: int64(len(sorted)), RecordRoot: vote.Root(sorted), OutageRule: "Extended by a relay outage over 1 hour, 24 h at most.",
	}
	var err error
	if v.propDoc, err = vote.EncodeProposal(p); err != nil {
		t.Fatal(err)
	}
	v.ph = sum(v.propDoc)
	return v
}

func (v *testVote) sign(t *testing.T, label string, msg []byte) []byte {
	t.Helper()
	s, err := suite.Sign(v.ik, label, msg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
