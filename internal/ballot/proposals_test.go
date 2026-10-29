package ballot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

type fakeRoster []string

func (r fakeRoster) Eligible() []string { return append([]string{}, r...) }

type sent struct {
	conn, typ string
	body      json.RawMessage
}

type fakeSender struct {
	sent []sent
	down map[string]bool
}

func (s *fakeSender) SendMessage(_ context.Context, conn, typ string, body json.RawMessage) (string, error) {
	if s.down[conn] {
		return "", peer.ErrNotFound
	}
	s.sent = append(s.sent, sent{conn, typ, body})
	return "id", nil
}

type fakePublisher struct {
	fail  bool
	calls int
}

func (p *fakePublisher) PublishProposal(_ context.Context, id string, doc, sig []byte) (json.RawMessage, error) {
	p.calls++
	if p.fail {
		return nil, errors.New("rekor down")
	}
	return json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), nil
}

func newManager(t *testing.T) (*Manager, *fakeSender, *fakePublisher) {
	t.Helper()
	ik := ed25519.NewKeyFromSeed(digest("service ik"))
	clock := time.Unix(1793500000, 0)
	s, p := &fakeSender{down: map[string]bool{}}, &fakePublisher{}
	return &Manager{
		Store: &RecordStore{Records: peer.NewMemStore(), Copy: &MemCopy{}},
		Sign:  func(label string, msg []byte) ([]byte, error) { return suite.Sign(ik, label, msg) },
		IK:    ik.Public().(ed25519.PublicKey), Roster: fakeRoster{"c2", "c0", "c1"}, Sender: s, Publisher: p,
		NewID: envelope.NewULID, Now: func() time.Time { return clock },
	}, s, p
}

func input() ProposalInput {
	return ProposalInput{Title: "Adopt the 2027 budget", Text: "As circulated.",
		Choices: []Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}},
		Quorum:  Quorum{Text: "A third", MinBallots: 1}, OpensAt: 1793520000, ClosesAt: 1793520000 + 86400,
		OutageRule: "Extended by a relay outage over 1 hour, 24 h at most."}
}

// Create makes a proposal from the roster, publishes it and sends each
// member its tag, as a member's vault would check it (§4.1).
func TestCreateProposal(t *testing.T) {
	ctx := context.Background()
	m, s, pub := newManager(t)
	c, err := m.Create(ctx, input())
	if err != nil {
		t.Fatal(err)
	}
	if c.Eligible != 3 || c.Sent != 3 || len(s.sent) != 3 || pub.calls != 1 {
		t.Fatalf("created %+v, sent %d, published %d", c, len(s.sent), pub.calls)
	}
	tags := map[string]bool{}
	for _, x := range s.sent {
		var b struct {
			Proposal     []byte          `json:"proposal"`
			ProposalSig  []byte          `json:"proposal_sig"`
			Bundle       json.RawMessage `json:"bundle"`
			RecordSecret []byte          `json:"record_secret"`
			RecordProof  recordProof     `json:"record_proof"`
		}
		if x.typ != TypeProposal || json.Unmarshal(x.body, &b) != nil {
			t.Fatalf("sent %s", x.typ)
		}
		p, err := ParseProposal(b.Proposal)
		if err != nil {
			t.Fatal(err)
		}
		if Verify(m.IK, LabelProposal, ProposalSigMsg(b.Proposal), b.ProposalSig) != nil || !bytes.Equal(sum(b.Proposal), c.ProposalHash) {
			t.Fatal("proposal signature")
		}
		if !p.HasChoice(AbstainID) || p.Eligible != 3 || p.RecordAt != 1793500000 || len(b.Bundle) == 0 {
			t.Fatalf("proposal %+v", p)
		}
		tag, _ := RecordTag(p.ProposalID, b.RecordSecret)
		if !VerifyProof(p.RecordRoot, tag, b.RecordProof.Index, int(b.RecordProof.TreeSize), b.RecordProof.Path) {
			t.Fatalf("%s: record proof", x.conn)
		}
		tags[string(tag)] = true
	}
	if len(tags) != 3 {
		t.Fatal("members share a tag")
	}
	st, err := m.Status(ctx, c.ProposalID)
	if err != nil || !st.Published || st.Eligible != 3 || st.ClosesAt != input().ClosesAt {
		t.Fatalf("status %+v, %v", st, err)
	}
	// The members can vote on it.
	box := &Box{Store: m.Store, Sign: m.Sign}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	mem := o.Members["c0"]
	vk := ed25519.NewKeyFromSeed(digest("vk"))
	cred := ed25519.NewKeyFromSeed(digest("cred"))
	bal := Ballot{RecordTag: mem.Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: "no"}
	msg, _ := bal.Msg(c.ProposalHash)
	bal.BallotSig, _ = suite.Sign(vk, LabelBallot, msg)
	leaf, _ := bal.Leaf()
	cmsg, _ := CastMsg(c.ProposalHash, leaf)
	csig, _ := suite.Sign(cred, LabelCast, cmsg)
	body, _ := json.Marshal(map[string][]byte{"record_tag": bal.RecordTag, "vk": bal.VK, "ballot_sig": bal.BallotSig, "cast_sig": csig})
	var asMap map[string]any
	_ = json.Unmarshal(body, &asMap)
	asMap["proposal_id"], asMap["choice_id"] = c.ProposalID, "no"
	body, _ = json.Marshal(asMap)
	a, err := box.Vote(ctx, &peer.VoteRequest{ConnectionID: "c0", PeerIK: m.IK, CredentialKey: cred.Public().(ed25519.PublicKey),
		Active: true, Type: TypeCast, Body: body, MsgMS: uint64(input().OpensAt)*1000 + 1})
	if err != nil || a.Code != "" {
		t.Fatalf("cast: %q, %v", a.Code, err)
	}
}

func TestCreateRefusals(t *testing.T) {
	ctx := context.Background()
	m, s, pub := newManager(t)
	bad := input()
	bad.ClosesAt = bad.OpensAt + MaxWindow + 1
	var ei *ErrInput
	if _, err := m.Create(ctx, bad); !errors.As(err, &ei) {
		t.Fatalf("a window over 7 days: %v", err)
	}
	m.Publisher = nil
	if _, err := m.Create(ctx, input()); !errors.Is(err, ErrNoPublisher) {
		t.Fatalf("no publisher: %v", err)
	}
	// Publishing fails: nothing is sent; a later Publish finishes.
	m.Publisher = pub
	pub.fail = true
	if _, err := m.Create(ctx, input()); err == nil {
		t.Fatal("created while Rekor is down")
	}
	if len(s.sent) != 0 {
		t.Fatal("sent an unpublished proposal")
	}
	var id string
	recs, _ := m.Store.Records.Load(ctx, KindProposal)
	if len(recs) != 1 {
		t.Fatalf("%d stored proposals", len(recs))
	}
	id = recs[0].ID
	if st, _ := m.Status(ctx, id); st.Published {
		t.Fatal("marked published")
	}
	pub.fail = false
	s.down["c1"] = true
	n, err := m.Publish(ctx, id)
	if err != nil || n != 2 {
		t.Fatalf("Publish: %d, %v", n, err)
	}
}

func (p *fakePublisher) PublishResults(_ context.Context, id string, results, sig, rows []byte) (json.RawMessage, error) {
	p.calls++
	if p.fail {
		return nil, errors.New("rekor down")
	}
	return json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), nil
}

type fakeCatcher struct{ caught bool }

func (c *fakeCatcher) Caught(time.Time) bool { return c.caught }

// castFor votes for a member of a created proposal through the box.
func castFor(t *testing.T, m *Manager, id, conn, choice string, ms uint64) string {
	t.Helper()
	ctx := context.Background()
	o, _ := m.Store.OpenProposal(ctx, id)
	ph := sum(o.Doc)
	vk := ed25519.NewKeyFromSeed(digest("vk " + conn))
	cred := ed25519.NewKeyFromSeed(digest("cred " + conn))
	bal := Ballot{RecordTag: o.Members[conn].Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: choice}
	msg, _ := bal.Msg(ph)
	bal.BallotSig, _ = suite.Sign(vk, LabelBallot, msg)
	leaf, _ := bal.Leaf()
	cmsg, _ := CastMsg(ph, leaf)
	csig, _ := suite.Sign(cred, LabelCast, cmsg)
	body, _ := json.Marshal(map[string]any{"proposal_id": id, "record_tag": bal.RecordTag, "vk": bal.VK, "choice_id": choice,
		"ballot_sig": bal.BallotSig, "cast_sig": csig})
	a, err := (&Box{Store: m.Store, Sign: m.Sign}).Vote(ctx, &peer.VoteRequest{ConnectionID: conn, PeerIK: m.IK,
		CredentialKey: cred.Public().(ed25519.PublicKey), Active: true, Type: TypeCast, Body: body, MsgMS: ms})
	if err != nil {
		t.Fatal(err)
	}
	return a.Code
}

func TestClose(t *testing.T) {
	ctx := context.Background()
	m, s, pub := newManager(t)
	ct := &fakeCatcher{}
	m.Catcher = ct
	c, err := m.Create(ctx, input())
	if err != nil {
		t.Fatal(err)
	}
	during := uint64(input().OpensAt)*1000 + 1
	if castFor(t, m, c.ProposalID, "c0", "yes", during) != "" || castFor(t, m, c.ProposalID, "c1", "no", during) != "" {
		t.Fatal("casts refused")
	}
	clock := time.Unix(input().ClosesAt, 0)
	m.Now = func() time.Time { return clock }
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrNotClosed) {
		t.Fatalf("at the close: %v", err)
	}
	clock = clock.Add(2 * CollectMargin)
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrNotCaught) {
		t.Fatalf("before the relay is caught up: %v", err)
	}
	ct.caught = true
	pub.fail = true
	if _, err := m.Close(ctx, c.ProposalID); err == nil {
		t.Fatal("closed while Rekor is down")
	}
	// Counting started: a cast now is late, even one inside the window.
	if code := castFor(t, m, c.ProposalID, "c2", "abstain", during); code != CodeLate {
		t.Fatalf("a cast during the count: %q", code)
	}
	pub.fail = false
	s.sent = nil
	sum1, err := m.Close(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if sum1.Counts.Ballots != 2 || sum1.Counts.Eligible != 3 || sum1.Tally["yes"] != 1 || sum1.Tally["no"] != 1 || sum1.Tally[AbstainID] != 0 {
		t.Fatalf("summary %+v", sum1)
	}
	closed := 0
	for _, x := range s.sent {
		if x.typ == TypeClosed {
			closed++
		}
	}
	if closed != 3 {
		t.Fatalf("vote.closed sent %d times", closed)
	}
	pr, _ := m.Results(ctx, c.ProposalID)
	if _, _, err := Check(m.IK, pr.Results, pr.Sig, pr.Rows); err != nil || pr.Bundle == nil {
		t.Fatalf("published results: %v", err)
	}
	// Again: the same results, announced once.
	s.sent = nil
	sum2, err := m.Close(ctx, c.ProposalID)
	if err != nil || !bytes.Equal(sum2.ResultsHash, sum1.ResultsHash) || len(s.sent) != 0 {
		t.Fatalf("second close: %v, sent %d", err, len(s.sent))
	}
}
