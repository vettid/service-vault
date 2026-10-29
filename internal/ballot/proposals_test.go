package ballot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/vettid/service-vault/vote"
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
	// started and release, when set, hold an extension's publication
	// until release is closed, after telling started.
	started, release chan struct{}
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
		Choices: []vote.Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}},
		Quorum:  vote.Quorum{Text: "A third", MinBallots: 1}, OpensAt: 1793520000, ClosesAt: 1793520000 + 86400,
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
		p, err := vote.ParseProposal(b.Proposal)
		if err != nil {
			t.Fatal(err)
		}
		if vote.Verify(m.IK, vote.LabelProposal, vote.ProposalSigMsg(b.Proposal), b.ProposalSig) != nil || !bytes.Equal(sum(b.Proposal), c.ProposalHash) {
			t.Fatal("proposal signature")
		}
		if !p.HasChoice(vote.AbstainID) || p.Eligible != 3 || p.RecordAt != 1793500000 || len(b.Bundle) == 0 {
			t.Fatalf("proposal %+v", p)
		}
		tag, _ := vote.RecordTag(p.ProposalID, b.RecordSecret)
		if !vote.VerifyProof(p.RecordRoot, tag, b.RecordProof.Index, int(b.RecordProof.TreeSize), b.RecordProof.Path) {
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
	bal := vote.Ballot{RecordTag: mem.Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: "no"}
	msg, _ := bal.Msg(c.ProposalHash)
	bal.BallotSig, _ = suite.Sign(vk, vote.LabelBallot, msg)
	leaf, _ := bal.Leaf()
	cmsg, _ := vote.CastMsg(c.ProposalHash, leaf)
	csig, _ := suite.Sign(cred, vote.LabelCast, cmsg)
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
	bad.ClosesAt = bad.OpensAt + vote.MaxWindow + 1
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
	c, err := m.Create(ctx, input())
	var np *ErrNotPublished
	if !errors.As(err, &np) || c == nil || np.ProposalID != c.ProposalID {
		t.Fatalf("created while Rekor is down: %v", err)
	}
	if len(s.sent) != 0 {
		t.Fatal("sent an unpublished proposal")
	}
	var id string
	recs, _ := m.Store.Records.Load(ctx, KindProposal)
	if len(recs) != 1 {
		t.Fatalf("%d stored proposals", len(recs))
	}
	if id = recs[0].ID; id != c.ProposalID {
		t.Fatal("the error names another proposal")
	}
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

func (c *fakeCatcher) Caught(context.Context, time.Time) (bool, error) { return c.caught, nil }

// castFor votes for a member of a created proposal through the box.
func castFor(t *testing.T, m *Manager, id, conn, choice string, ms uint64) string {
	t.Helper()
	ctx := context.Background()
	o, _ := m.Store.OpenProposal(ctx, id)
	ph := sum(o.Doc)
	vk := ed25519.NewKeyFromSeed(digest("vk " + conn))
	cred := ed25519.NewKeyFromSeed(digest("cred " + conn))
	bal := vote.Ballot{RecordTag: o.Members[conn].Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: choice}
	msg, _ := bal.Msg(ph)
	bal.BallotSig, _ = suite.Sign(vk, vote.LabelBallot, msg)
	leaf, _ := bal.Leaf()
	cmsg, _ := vote.CastMsg(ph, leaf)
	csig, _ := suite.Sign(cred, vote.LabelCast, cmsg)
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
	if sum1.Counts.Ballots != 2 || sum1.Counts.Eligible != 3 || sum1.Tally["yes"] != 1 || sum1.Tally["no"] != 1 || sum1.Tally[vote.AbstainID] != 0 {
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
	if _, _, err := vote.Check(m.IK, pr.Results, pr.Sig, pr.Rows); err != nil || pr.Bundle == nil {
		t.Fatalf("published results: %v", err)
	}
	// Again: the same results, announced once.
	s.sent = nil
	sum2, err := m.Close(ctx, c.ProposalID)
	if err != nil || !bytes.Equal(sum2.ResultsHash, sum1.ResultsHash) || len(s.sent) != 0 {
		t.Fatalf("second close: %v, sent %d", err, len(s.sent))
	}
}

func (p *fakePublisher) PublishExtension(_ context.Context, id string, n int64, doc, sig []byte) (json.RawMessage, error) {
	if p.release != nil {
		p.started <- struct{}{}
		<-p.release
	}
	p.calls++
	if p.fail {
		return nil, errors.New("rekor down")
	}
	return json.RawMessage(`{}`), nil
}

func TestExtend(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	clock := time.Unix(in.ClosesAt-600, 0)
	m.Now = func() time.Time { return clock }
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"} // 1.5 h
	var ei *ErrInput
	for name, x := range map[string]ExtensionInput{
		"short outage":   {ClosesAt: in.ClosesAt + 3600, Outage: vote.Outage{From: outage.From, To: outage.From + 3600, Source: outage.Source}},
		"too long":       {ClosesAt: in.ClosesAt + 3*3600, Outage: outage},
		"not later":      {ClosesAt: in.ClosesAt, Outage: outage},
		"outside window": {ClosesAt: in.ClosesAt + 3600, Outage: vote.Outage{From: in.OpensAt - 7200, To: in.OpensAt - 1800, Source: "x"}},
	} {
		if _, err := m.Extend(ctx, c.ProposalID, x); !errors.As(err, &ei) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s.sent = nil
	e, err := m.Extend(ctx, c.ProposalID, ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage})
	if err != nil || e.N != 1 {
		t.Fatalf("Extend: %v", err)
	}
	if len(s.sent) != 3 || s.sent[0].typ != TypeExtended {
		t.Fatalf("vote.extended sent %d", len(s.sent))
	}
	// A cast after the first close, inside the extension, counts.
	if code := castFor(t, m, c.ProposalID, "c0", "yes", uint64(in.ClosesAt)*1000+60000); code != "" {
		t.Fatalf("a cast inside the extension: %q", code)
	}
	// After the extended close: too late to extend.
	clock = time.Unix(in.ClosesAt+7200+120, 0)
	if _, err := m.Extend(ctx, c.ProposalID, ExtensionInput{ClosesAt: in.ClosesAt + 4*3600, Outage: outage}); !errors.Is(err, ErrTooLate) {
		t.Fatalf("after the close: %v", err)
	}
	sum, err := m.Close(ctx, c.ProposalID)
	if err != nil || sum.Counts.Ballots != 1 {
		t.Fatalf("Close: %v", err)
	}
	pr, _ := m.Results(ctx, c.ProposalID)
	_, res, err := vote.Check(m.IK, pr.Results, pr.Sig, pr.Rows)
	if err != nil || len(res.Extensions) != 1 {
		t.Fatalf("results with the extension: %v", err)
	}
}

// While an extension is being published, the proposal's other writers
// wait for it, so neither saves over the other's change.
func TestExtendHoldsTheProposal(t *testing.T) {
	ctx := context.Background()
	m, _, pub := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	m.Now = func() time.Time { return time.Unix(in.ClosesAt-600, 0) }
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
	pub.started, pub.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := m.Extend(ctx, c.ProposalID, ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage})
		done <- err
	}()
	<-pub.started
	for name, f := range map[string]func(context.Context) error{
		"close":   func(ctx context.Context) error { _, err := m.Close(ctx, c.ProposalID); return err },
		"publish": func(ctx context.Context) error { _, err := m.Publish(ctx, c.ProposalID); return err },
		"extend": func(ctx context.Context) error {
			_, err := m.Extend(ctx, c.ProposalID, ExtensionInput{ClosesAt: in.ClosesAt + 3600, Outage: outage})
			return err
		},
	} {
		short, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		if err := f(short); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s during the extension's publication: %v", name, err)
		}
		cancel()
	}
	close(pub.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	pub.started, pub.release = nil, nil
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	if o.ClosesAt != in.ClosesAt+7200 || len(o.Extensions) != 1 || o.Published {
		t.Fatalf("after the extension: closes %d, %d extensions, published %v", o.ClosesAt, len(o.Extensions), o.Published)
	}
}

func TestRebuildAll(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	c, err := m.Create(ctx, input())
	if err != nil {
		t.Fatal(err)
	}
	castFor(t, m, c.ProposalID, "c1", "no", uint64(input().OpensAt)*1000+1)
	// The table loses the ballot (a restore); the proposal stays.
	recs, _ := m.Store.Records.Load(ctx, KindProposal)
	fresh := peer.NewMemStore()
	_ = fresh.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: recs[0].ID, Data: recs[0].Data}})
	m.Store.Records = fresh
	if n, err := m.RebuildAll(ctx); err != nil || n != 1 {
		t.Fatalf("RebuildAll: %d, %v", n, err)
	}
}
