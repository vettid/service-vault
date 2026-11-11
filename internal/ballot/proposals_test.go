package ballot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/internal/ballot/ballottest"
	"github.com/vettid/service-vault/vote"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

type fakeRoster []string

func (r fakeRoster) Eligible() []string { return append([]string{}, r...) }
func (r fakeRoster) Active() []string   { return append([]string{}, r...) }

// EligibleUnsigned: the fake roster has every key pinned.
func (r fakeRoster) EligibleUnsigned() []string { return nil }

// unsignedRoster is a roster some of whose members have no pinned key,
// and an id that is not eligible among them.
type unsignedRoster struct {
	fakeRoster
	unsigned []string
}

func (r unsignedRoster) EligibleUnsigned() []string { return r.unsigned }

type sent struct {
	conn, typ string
	body      json.RawMessage
}

// fakeSender records what was sent. Sends run in the background
// (sends.go), so a test reads sent only after m.Wait().
type fakeSender struct {
	mu   sync.Mutex
	sent []sent
	down map[string]bool
	// block, when set, holds every send until it is closed.
	block chan struct{}
	// cancelled counts the calls made with a context already done; hold,
	// set before any send, holds the sends to a connection until closed.
	cancelled int
	hold      map[string]chan struct{}
	// failWith, set before any send, fails the sends to a connection
	// with that error (the relay down, say).
	failWith map[string]error
	// left is how long the last send's context had before its deadline;
	// notAfter is the last send's.
	left     time.Duration
	notAfter time.Time
}

func (s *fakeSender) SendMessage(ctx context.Context, conn, typ string, body json.RawMessage, notAfter time.Time) (string, error) {
	if ctx.Err() != nil {
		s.mu.Lock()
		s.cancelled++
		s.mu.Unlock()
		return "", ctx.Err()
	}
	if h := s.hold[conn]; h != nil {
		<-h
	}
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notAfter = notAfter
	if d, ok := ctx.Deadline(); ok {
		s.left = time.Until(d)
	} else {
		s.left = -1
	}
	if s.down[conn] {
		return "", peer.ErrNotFound
	}
	if err := s.failWith[conn]; err != nil {
		return "", err
	}
	s.sent = append(s.sent, sent{conn, typ, body})
	return "id", nil
}

type fakePublisher struct {
	fail  bool
	calls int
	// notBefore is each results upload's notBefore; stampedEarly answers
	// the next results upload with ErrStampedEarly.
	notBefore    []int64
	stampedEarly bool
	// started and release, when set, hold an extension's publication
	// until release is closed, after telling started.
	started, release chan struct{}
	// integrated and tsa are the times of a bundle made; failAfter writes
	// to the site and then reports an error (a lost answer); site is what
	// the site holds; own is the bundles kept, by document; refuse is what
	// the site answers an upload with.
	integrated, tsa func() int64
	failAfter       bool
	site            map[int64]*SiteExtension
	own             map[string]json.RawMessage
	refuse          *ErrPublishRefused
	published       [][]byte // the extension documents sent, in order
	indexStale      bool     // the extension answers say the index isn't updated
	resultsStale    bool
	resultsUploads  int
	republished     int // RepublishResults calls (a stale site index)
}

func (p *fakePublisher) bundle(doc []byte) json.RawMessage {
	if b := p.own[string(doc)]; b != nil {
		return b
	}
	tsa := p.integrated()
	if p.tsa != nil {
		tsa = p.tsa()
	}
	if p.own == nil {
		p.own = map[string]json.RawMessage{}
	}
	p.own[string(doc)] = ballottest.Bundle(tsa, p.integrated())
	return p.own[string(doc)]
}

func (p *fakePublisher) StoredBundle(_ context.Context, doc []byte) (json.RawMessage, error) {
	return p.own[string(doc)], nil
}

func (p *fakePublisher) Extension(_ context.Context, _ string, n int64) (*SiteExtension, error) {
	return p.site[n], nil
}

func (p *fakePublisher) PublishProposal(_ context.Context, id string, doc, sig []byte) (json.RawMessage, error) {
	p.calls++
	if p.fail {
		return nil, errors.New("rekor down")
	}
	return json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), nil
}

// fakeApprovals stands for the approval manager: with auto it accepts
// any approval once per call; otherwise only the approvals added, each
// once, as approval.Manager.Consume does.
type fakeApprovals struct {
	mu       sync.Mutex
	auto     bool
	approved map[string]fakeApproval
	used     map[string]bool
	consumed int
	uses     []Use
	seen     map[Use]bool
	fail     error // Consume fails with it
}

type fakeApproval struct {
	action  string
	payload []byte
	status  string // "" is approved
}

func (f *fakeApprovals) Consume(_ context.Context, id, action string, payload []byte, use Use) error {
	retry := use.Retry
	if use.ProposalID == "" {
		return errors.New("no use")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.seen == nil {
		f.seen = map[Use]bool{}
	}
	use.Retry = false
	if f.seen[use] && retry { // a repeat of the same use
		return nil
	}
	if f.auto {
		f.seen[use] = true
		f.consumed++
		return nil
	}
	a, ok := f.approved[id]
	switch {
	case !ok || a.status != "":
		return errors.New("not approved")
	case a.action != action || !bytes.Equal(a.payload, payload):
		return errors.New("mismatch")
	case f.used[id]:
		return errors.New("used")
	}
	f.used[id] = true
	f.seen[use] = true
	f.consumed++
	f.uses = append(f.uses, use)
	return nil
}

func (f *fakeApprovals) add(id, action string, payload []byte, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approved[id] = fakeApproval{action, payload, status}
}

func newManager(t *testing.T) (*Manager, *fakeSender, *fakePublisher) {
	t.Helper()
	ik := ed25519.NewKeyFromSeed(digest("service ik"))
	clock := time.Unix(1793500000, 0)
	s, p := &fakeSender{down: map[string]bool{}}, &fakePublisher{}
	records := peer.NewMemStore()
	m := &Manager{
		// The copy enforces the cast's guard against the records, as the
		// DynamoDB transaction does.
		Store: &RecordStore{Records: records, Copy: &MemCopy{Records: records}},
		Sign:  func(label string, msg []byte) ([]byte, error) { return suite.Sign(ik, label, msg) },
		IK:    ik.Public().(ed25519.PublicKey), Roster: fakeRoster{"c2", "c0", "c1"}, Sender: s, Publisher: p,
		NewID: envelope.NewULID, Now: func() time.Time { return clock }, Approvals: &fakeApprovals{auto: true}, Timestamp: ballottest.Time,
	}
	m.AuthorityTime = func(context.Context) (int64, error) { return m.Now().Unix(), nil } // an authority agreeing with the clock
	p.integrated = func() int64 { return m.Now().Unix() }
	return m, s, p
}

func input() ProposalInput {
	return ProposalInput{Title: "Adopt the 2027 budget", Text: "",
		Choices: []ChoiceInput{{Label: "Yes"}, {Label: "No"}},
		Quorum:  vote.Quorum{MinBallots: 1}, OpensAt: 1793520000, ClosesAt: 1793520000 + 86400,
		OutageRule: DefaultOutageRule}
}

// Create makes a proposal from the roster, publishes it and sends each
// member its tag, as a member's vault would check it (§4.1).
func TestCreateProposal(t *testing.T) {
	ctx := context.Background()
	m, s, pub := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if c.Eligible != 3 || c.Sending != 3 || len(s.sent) != 3 || pub.calls != 1 {
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
	bal := vote.Ballot{RecordTag: mem.Tag, VK: vk.Public().(ed25519.PublicKey), ChoiceID: "c2"}
	msg, _ := bal.Msg(c.ProposalHash)
	bal.BallotSig, _ = suite.Sign(vk, vote.LabelBallot, msg)
	leaf, _ := bal.Leaf()
	cmsg, _ := vote.CastMsg(c.ProposalHash, leaf)
	csig, _ := suite.Sign(cred, vote.LabelCast, cmsg)
	body, _ := json.Marshal(map[string][]byte{"record_tag": bal.RecordTag, "vk": bal.VK, "ballot_sig": bal.BallotSig, "cast_sig": csig})
	var asMap map[string]any
	_ = json.Unmarshal(body, &asMap)
	asMap["proposal_id"], asMap["choice_id"] = c.ProposalID, "c2"
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
	if _, err := m.Create(ctx, "apv", bad); !errors.As(err, &ei) {
		t.Fatalf("a window over 7 days: %v", err)
	}
	roster := m.Roster
	m.Roster = fakeRoster{}
	if _, err := m.Create(ctx, "apv", input()); !errors.As(err, &ei) {
		t.Fatalf("no eligible members: %v", err)
	}
	big := make(fakeRoster, MaxEligible+1)
	for i := range big {
		big[i] = fmt.Sprintf("c%05d", i)
	}
	m.Roster = big
	if _, err := m.Create(ctx, "apv", input()); !errors.Is(err, ErrTooManyEligible) {
		t.Fatalf("more than %d eligible members: %v", MaxEligible, err)
	}
	m.Roster = roster
	m.Publisher = nil
	if _, err := m.Create(ctx, "apv", input()); !errors.Is(err, ErrNoPublisher) {
		t.Fatalf("no publisher: %v", err)
	}
	// Publishing fails: nothing is sent; a later Publish finishes.
	m.Publisher = pub
	pub.fail = true
	c, err := m.Create(ctx, "apv", input())
	var np *ErrNotPublished
	if !errors.As(err, &np) || c == nil || np.ProposalID != c.ProposalID {
		t.Fatalf("created while Rekor is down: %v", err)
	}
	m.Wait()
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
	m.Wait()
	if err != nil || n != 3 || len(s.sent) != 2 {
		t.Fatalf("Publish: sending %d, sent %d, %v", n, len(s.sent), err)
	}
}

func (p *fakePublisher) PublishResults(_ context.Context, id string, results, sig, rows []byte, notBefore int64) (Receipt, error) {
	p.calls++
	p.notBefore = append(p.notBefore, notBefore)
	if p.stampedEarly {
		p.stampedEarly = false
		return Receipt{}, ErrStampedEarly
	}
	p.resultsUploads++
	if p.fail {
		return Receipt{}, errors.New("rekor down")
	}
	return Receipt{Bundle: json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), IndexStale: p.resultsStale}, nil
}

func (p *fakePublisher) RepublishResults(ctx context.Context, id string, results, sig, rows []byte, _ json.RawMessage, notBefore int64) (Receipt, error) {
	p.republished++
	return p.PublishResults(ctx, id, results, sig, rows, notBefore)
}

type fakeCatcher struct {
	caught     bool
	unhandled  int64
	emptyAfter []time.Time // per call
}

func (c *fakeCatcher) Caught(_ context.Context, _, emptyAfter, _, _ time.Time) (bool, int64, error) {
	c.emptyAfter = append(c.emptyAfter, emptyAfter)
	return c.caught, c.unhandled, nil
}

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
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	during := uint64(input().OpensAt)*1000 + 1
	if castFor(t, m, c.ProposalID, "c0", "c1", during) != "" || castFor(t, m, c.ProposalID, "c1", "c2", during) != "" {
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
	ct.caught, ct.unhandled = true, 2
	pub.fail = true
	if _, err := m.Close(ctx, c.ProposalID); err == nil {
		t.Fatal("closed while Rekor is down")
	}
	// Counting started: a cast now is late, even one inside the window.
	if code := castFor(t, m, c.ProposalID, "c2", "abstain", during); code != CodeLate {
		t.Fatalf("a cast during the count: %q", code)
	}
	pub.fail = false
	m.Wait()
	s.sent = nil
	sum1, err := m.Close(ctx, c.ProposalID)
	m.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sum1.Counts.Unhandled != 2 {
		t.Fatalf("unhandled %d", sum1.Counts.Unhandled)
	}
	if sum1.Counts.Ballots != 2 || sum1.Counts.Eligible != 3 || sum1.Tally["c1"] != 1 || sum1.Tally["c2"] != 1 || sum1.Tally[vote.AbstainID] != 0 {
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
	m.Wait()
	if err != nil || !bytes.Equal(sum2.ResultsHash, sum1.ResultsHash) || len(s.sent) != 0 {
		t.Fatalf("second close: %v, sent %d", err, len(s.sent))
	}
}

func (p *fakePublisher) PublishExtension(_ context.Context, id string, n int64, doc, sig []byte) (Receipt, error) {
	if p.release != nil {
		p.started <- struct{}{}
		<-p.release
	}
	p.calls++
	if p.fail {
		return Receipt{}, errors.New("rekor down")
	}
	b := p.bundle(doc)
	p.published = append(p.published, doc)
	if p.refuse != nil {
		return Receipt{}, p.refuse
	}
	if old := p.site[n]; old != nil && !bytes.Equal(old.Doc, doc) {
		return Receipt{}, errors.New("409")
	}
	if p.site == nil {
		p.site = map[int64]*SiteExtension{}
	}
	if p.site[n] == nil {
		p.site[n] = &SiteExtension{Doc: doc, Sig: sig, Bundle: b}
	}
	if p.failAfter {
		return Receipt{}, errors.New("answer lost")
	}
	return Receipt{Bundle: b, IndexStale: p.indexStale}, nil
}

func TestExtend(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
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
		if _, err := m.Extend(ctx, c.ProposalID, "apv", x); !errors.As(err, &ei) {
			t.Errorf("%s: %v", name, err)
		}
	}
	m.Wait()
	s.sent = nil
	// An outage still going on: its length is not known yet.
	now := m.Now().Unix()
	going := vote.Outage{From: now - 5400, To: now + 60, Source: outage.Source}
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: going}); !errors.As(err, &ei) ||
		!strings.Contains(err.Error(), "hasn't ended") {
		t.Fatalf("an outage not over: %v", err)
	}
	e, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage})
	if err != nil || e.N != 1 {
		t.Fatalf("Extend: %v", err)
	}
	m.Wait()
	if len(s.sent) != 3 || s.sent[0].typ != TypeExtended {
		t.Fatalf("vote.extended sent %d", len(s.sent))
	}
	// A cast after the first close, inside the extension, counts.
	if code := castFor(t, m, c.ProposalID, "c0", "c1", uint64(in.ClosesAt)*1000+60000); code != "" {
		t.Fatalf("a cast inside the extension: %q", code)
	}
	// After the extended close: too late to extend.
	clock = time.Unix(in.ClosesAt+7200+120, 0)
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 4*3600, Outage: outage}); !errors.Is(err, ErrTooLate) {
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
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	m.Now = func() time.Time { return time.Unix(in.ClosesAt-600, 0) }
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
	pub.started, pub.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage})
		done <- err
	}()
	<-pub.started
	for name, f := range map[string]func(context.Context) error{
		"close":   func(ctx context.Context) error { _, err := m.Close(ctx, c.ProposalID); return err },
		"publish": func(ctx context.Context) error { _, err := m.Publish(ctx, c.ProposalID); return err },
		"extend": func(ctx context.Context) error {
			_, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 3600, Outage: outage})
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
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	castFor(t, m, c.ProposalID, "c1", "c2", uint64(input().OpensAt)*1000+1)
	// The table loses the ballot (a restore); the proposal stays.
	recs, _ := m.Store.Records.Load(ctx, KindProposal)
	fresh := peer.NewMemStore()
	_ = fresh.Apply(ctx, []peer.Change{{Kind: KindProposal, ID: recs[0].ID, Data: recs[0].Data}})
	m.Store.Records = fresh
	if n, err := m.RebuildAll(ctx); err != nil || n != 1 {
		t.Fatalf("RebuildAll: %d, %v", n, err)
	}
}

// Two tasks running at once (a deploy's overlap) don't share the lock:
// the record's version stops a save over the other's. An Extend that
// published while the other task closed the vote doesn't reopen it.
func TestTwoTasksSaveByVersion(t *testing.T) {
	ctx := context.Background()
	m1, _, pub := newManager(t)
	m1.Catcher = &fakeCatcher{caught: true}
	c, err := m1.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	m1.Now = func() time.Time { return time.Unix(in.ClosesAt-600, 0) }
	m2 := &Manager{Store: m1.Store, Sign: m1.Sign, IK: m1.IK, Roster: m1.Roster, Sender: m1.Sender, Publisher: pub,
		Catcher: &fakeCatcher{caught: true}, NewID: m1.NewID, Now: func() time.Time { return time.Unix(in.ClosesAt, 0).Add(2 * CollectMargin) }}
	m2.AuthorityTime = func(context.Context) (int64, error) { return m2.Now().Unix(), nil }
	pub.started, pub.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
		_, err := m1.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage})
		done <- err
	}()
	<-pub.started
	if _, err := m2.Close(ctx, c.ProposalID); err != nil {
		t.Fatalf("the other task's close: %v", err)
	}
	close(pub.release)
	if err := <-done; !errors.Is(err, ErrProposalChanged) {
		t.Fatalf("the extension saved over the close: %v", err)
	}
	o, _ := m1.Store.OpenProposal(ctx, c.ProposalID)
	if !o.Published || o.ClosesAt != in.ClosesAt || len(o.Extensions) != 0 {
		t.Fatalf("after both: published %v, closes %d, %d extensions", o.Published, o.ClosesAt, len(o.Extensions))
	}
}

// An extension whose publication ran past the close it extends doesn't
// take effect (§10.2).
func TestExtendPublishedTooLate(t *testing.T) {
	ctx := context.Background()
	m, _, pub := newManager(t)
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	now := time.Unix(in.ClosesAt-600, 0)
	m.Now = func() time.Time { return now }
	pub.started, pub.release = make(chan struct{}, 1), make(chan struct{})
	go func() { <-pub.started; now = time.Unix(in.ClosesAt, 0); close(pub.release) }()
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage}); !errors.Is(err, ErrTooLate) {
		t.Fatalf("published past the close: %v", err)
	}
	if o, _ := m.Store.OpenProposal(ctx, c.ProposalID); o.ClosesAt != in.ClosesAt || len(o.Extensions) != 0 {
		t.Fatal("the late extension was saved")
	}
}

// Create reports how many of the eligible connections have no pinned
// credential key; one that is not eligible is not counted.
func TestCreateCountsUnsigned(t *testing.T) {
	m, _, _ := newManager(t)
	m.Roster = unsignedRoster{fakeRoster{"c0", "c1", "c2"}, []string{"c1", "c2", "gone"}}
	c, err := m.Create(context.Background(), "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	if c.Eligible != 3 || c.Unsigned != 2 {
		t.Fatalf("eligible %d unsigned %d, want 3 and 2", c.Eligible, c.Unsigned)
	}
	m2, _, _ := newManager(t)
	if c, err = m2.Create(context.Background(), "apv", input()); err != nil || c.Unsigned != 0 {
		t.Fatalf("all pinned: %+v, %v", c, err)
	}
}

// The count re-checks each stored ballot: one whose tag differs from its
// item's, whose cast_sig is bad, or whose relay time is outside the window
// isn't counted; the others are.
func TestCountSkipsBadStoredBallots(t *testing.T) {
	cases := map[string]func(it *CopyItem, r *BallotRecord){
		"tag":      func(it *CopyItem, _ *BallotRecord) { it.Tag = append([]byte{0xff}, it.Tag[1:]...) },
		"cast_sig": func(_ *CopyItem, r *BallotRecord) { r.CastSig = bytes.Repeat([]byte{1}, vote.SigLen) },
		"after":    func(_ *CopyItem, r *BallotRecord) { r.MsgMS = uint64(input().ClosesAt) * 1000 },
		"before":   func(_ *CopyItem, r *BallotRecord) { r.MsgMS = uint64(input().OpensAt)*1000 - 1 },
		"key":      func(_ *CopyItem, r *BallotRecord) { r.CredentialKey = bytes.Repeat([]byte{2}, 32) },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			m, _, _ := newManager(t)
			m.Catcher = &fakeCatcher{caught: true}
			c, err := m.Create(ctx, "apv", input())
			if err != nil {
				t.Fatal(err)
			}
			during := uint64(input().OpensAt)*1000 + 1
			for _, conn := range []string{"c0", "c1", "c2"} {
				if code := castFor(t, m, c.ProposalID, conn, "c1", during); code != "" {
					t.Fatalf("cast refused: %s", code)
				}
			}
			cp := m.Store.Copy.(*MemCopy)
			o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
			k := ballotID(c.ProposalID, o.Members["c1"].Tag)
			it := cp.items[k]
			r, _ := decodeBallot(it.Data)
			tamper(&it, r)
			it.Data, _ = json.Marshal(r)
			cp.items[k] = it
			m.Now = func() time.Time { return time.Unix(input().ClosesAt, 0).Add(2 * CollectMargin) }
			sum1, err := m.Close(ctx, c.ProposalID)
			if err != nil {
				t.Fatal(err)
			}
			if sum1.Counts.Ballots != 2 || sum1.Tally["c1"] != 2 {
				t.Fatalf("counted %+v", sum1)
			}
		})
	}
}

// failResults makes the save of the results fail, once switched on.
type failResults struct {
	*peer.MemStore
	fail bool
}

func (s *failResults) Apply(ctx context.Context, ch []peer.Change) error {
	for _, c := range ch {
		if s.fail && c.Kind == KindResults {
			return errors.New("table unavailable")
		}
	}
	return s.MemStore.Apply(ctx, ch)
}

// The counts fixed when the vote closed survive a first attempt that fails
// before the results are saved, and a roster change and another relay
// answer after it.
func TestCloseFreezesCounts(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	fr := &failResults{MemStore: peer.NewMemStore()}
	m.Store = &RecordStore{Records: fr, Copy: &MemCopy{}}
	ct := &fakeCatcher{caught: true, unhandled: 2}
	m.Catcher = ct
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	during := uint64(input().OpensAt)*1000 + 1
	if castFor(t, m, c.ProposalID, "c0", "c1", during) != "" {
		t.Fatal("cast refused")
	}
	m.Now = func() time.Time { return time.Unix(input().ClosesAt, 0).Add(2 * CollectMargin) }
	fr.fail = true
	if _, err := m.Close(ctx, c.ProposalID); err == nil {
		t.Fatal("closed while the results can't be saved")
	}
	fr.fail = false
	m.Roster = fakeRoster{"c0"}
	ct.unhandled = 7
	res, err := m.Close(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Unhandled != 2 || res.Counts.Removed != 0 {
		t.Fatalf("counts changed between attempts: %+v", res.Counts)
	}
}

// A proposal marked published by a build that didn't fix the counts gets
// them fixed, and saved, by the next Close.
func TestCloseFixesCountsOfAnOldPublishedRecord(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true, unhandled: 3}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	o.Published = true
	if err := m.Store.SaveProposal(ctx, o, false); err != nil {
		t.Fatal(err)
	}
	m.Roster = fakeRoster{"c0"}
	m.Now = func() time.Time { return time.Unix(input().ClosesAt, 0).Add(2 * CollectMargin) }
	res, err := m.Close(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Unhandled != 3 || res.Counts.Removed != 2 {
		t.Fatalf("counts %+v", res.Counts)
	}
	o, _ = m.Store.OpenProposal(ctx, c.ProposalID)
	if o.Unhandled == nil || *o.Unhandled != 3 || o.Removed == nil || *o.Removed != 2 {
		t.Fatal("the counts weren't saved")
	}
}

// At MaxEligible members, everyone voting, with the largest inputs the
// service takes (the longest title, text and labels, 16 choices, 26-byte
// connection ids, MaxExtensions extensions and a 10 KB anchor bundle),
// every item stored (the proposal's record, the results' record and each
// of their chunks) still fits one DynamoDB item (400 KB), with room for
// the seal, the keys and the attribute names, and the rows fit the votes
// site's upload.
func TestMaxEligibleFitsOneItem(t *testing.T) {
	if testing.Short() {
		t.Skip("casts MaxEligible ballots")
	}
	const itemLimit = 400_000 - 16_000 // the seal, keys and attribute names
	ctx := context.Background()
	m, _, _ := newManager(t)
	ct := &fakeCatcher{caught: true}
	m.Catcher = ct
	roster := make(fakeRoster, MaxEligible)
	for i := range roster {
		roster[i] = fmt.Sprintf("01JBQZ%020d", i) // a ULID's length
	}
	m.Roster = roster
	// The largest input create accepts: the longest title (the text may
	// only repeat it), then the most and longest labels the admins'
	// summary still shows whole.
	in := input()
	in.Title = strings.Repeat("T", MaxTitleBytes())
	in.Text = in.Title
	var c *Created
	var err error
	for n := MaxRealChoices; n >= 2 && c == nil; n-- {
		for l := MaxLabelRunes; l >= 2 && c == nil; l-- {
			in.Choices = nil
			for i := range n {
				in.Choices = append(in.Choices, ChoiceInput{Label: fmt.Sprintf("%c", 'A'+i) + strings.Repeat("l", l-1)})
			}
			if c, err = m.Create(ctx, "apv", in); err != nil {
				c = nil
			}
		}
	}
	if c == nil {
		t.Fatalf("no input accepted: %v", err)
	}
	t.Logf("%d choices, labels of %d, title of %d", len(in.Choices), len(in.Choices[0].Label), len(in.Title))
	// MaxExtensions extensions, each moving the close by a second for an
	// outage of just over an hour that is over.
	out := vote.Outage{From: in.OpensAt + 60, To: in.OpensAt + 60 + MinOutage + 1, Source: "https://status.vettid.org/"}
	now := time.Unix(out.To+60, 0)
	m.Now = func() time.Time { return now }
	closes := in.ClosesAt
	for range MaxExtensions {
		closes++
		if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: closes, Outage: out}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: closes + 1, Outage: out}); err == nil {
		t.Fatal("an extension past MaxExtensions")
	}
	during := uint64(in.OpensAt)*1000 + 1
	for _, conn := range roster {
		if code := castFor(t, m, c.ProposalID, conn, vote.AbstainID, during); code != "" { // the longest choice id
			t.Fatalf("%s: %q", conn, code)
		}
	}
	m.Now = func() time.Time { return time.Unix(closes, 0).Add(2 * CollectMargin) }
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	bundle, _ := json.Marshal(map[string]string{"pad": strings.Repeat("b", 10<<10)})
	for _, kind := range []string{KindProposal, KindResults} {
		data, ok, err := m.Store.Records.Get(ctx, kind, c.ProposalID)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", kind, ok, err)
		}
		// A real Sigstore bundle is larger than the test's.
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatal(err)
		}
		rec["bundle"] = bundle
		data, _ = json.Marshal(rec)
		if len(data) > itemLimit {
			t.Errorf("%s record: %d bytes, over %d", kind, len(data), itemLimit)
		}
		t.Logf("%s record: %d bytes at %d members", kind, len(data), MaxEligible)
	}
	chunks, err := m.Store.Records.Load(ctx, KindChunk)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("chunks: %d, %v", len(chunks), err)
	}
	for _, r := range chunks {
		if len(r.Data) > itemLimit {
			t.Errorf("chunk %s: %d bytes, over %d", r.ID, len(r.Data), itemLimit)
		}
	}
	pr, err := m.Results(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if n := base64.StdEncoding.EncodedLen(len(pr.Rows)); n > maxRowsUpload {
		t.Errorf("rows: %d bytes as base64, over the site's %d", n, maxRowsUpload)
	}
	// The per-member bounds the chunk lists are checked against.
	o, err := m.Store.OpenProposal(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(o.Members)
	if len(md) > MaxEligible*maxMemberBytes || len(pr.Rows) > MaxEligible*maxRowBytes {
		t.Errorf("members %d bytes, rows %d bytes: over %d and %d a member", len(md), len(pr.Rows), maxMemberBytes, maxRowBytes)
	}
	t.Logf("members %d bytes, rows %d bytes at %d members", len(md), len(pr.Rows), MaxEligible)
	if len(pr.RowChunks) > maxRowChunks || len(o.MemberChunks) > maxMemberChunks {
		t.Errorf("%d row chunks, %d member chunks", len(pr.RowChunks), len(o.MemberChunks))
	}
	t.Logf("%d chunks; rows %d bytes in %d chunks at %d members", len(chunks), len(pr.Rows), len(pr.RowChunks), MaxEligible)
}

// maxRowsUpload is the most rows, as base64, the votes site takes in one
// upload: its Lambda request holds 6 MB, less the results, their
// signature and the rest of the request.
const maxRowsUpload = 5_500_000

// A proposal held but not published (its bundle lost, after a restore) is
// not counted: its members' requests go unanswered meanwhile, so a count
// would leave out ballots they send again once it is published.
func TestCloseRefusesUnpublished(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	o, err := m.Store.OpenProposal(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	o.Bundle = nil
	if err := m.Store.SaveProposal(ctx, o, false); err != nil {
		t.Fatal(err)
	}
	m.Now = func() time.Time { return time.Unix(input().ClosesAt, 0).Add(2 * CollectMargin) }
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrUnpublished) {
		t.Fatalf("close: %v", err)
	}
	if pr, _ := m.Results(ctx, c.ProposalID); pr != nil {
		t.Fatal("counted")
	}
}

// BALLOT-PROTOCOL §7 (0.13.12): a fast service clock doesn't start the
// count. Until the timestamp authority's time is past the close the vote
// is still collecting, nothing is fixed, and an in-window cast is taken,
// not refused late; probes are rationed; then it counts every ballot.
func TestCloseWaitsForTheAuthority(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	if castFor(t, m, c.ProposalID, "c0", "c1", uint64(in.OpensAt)*1000+1) != "" {
		t.Fatal("cast refused")
	}
	clock := time.Unix(in.ClosesAt, 0).Add(5 * time.Minute) // 5 min fast
	m.Now = func() time.Time { return clock }
	authority, probes := in.ClosesAt-4*60, 0 // the real time
	m.AuthorityTime = func(context.Context) (int64, error) { probes++; return authority, nil }
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 1 {
		t.Fatalf("a fast clock: %v, %d probes", err, probes)
	}
	if o, _ := m.Store.OpenProposal(ctx, c.ProposalID); o.Published || o.Unhandled != nil {
		t.Fatal("the counts were fixed")
	}
	if code := castFor(t, m, c.ProposalID, "c1", "c2", uint64(in.ClosesAt)*1000-1000); code != "" {
		t.Fatalf("an in-window cast while still collecting: %q", code)
	}
	// Rationed: no probe until the authority can be past the close.
	clock = clock.Add(4*time.Minute - time.Second)
	authority += 4*60 - 1
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 1 {
		t.Fatalf("probed too soon: %v, %d probes", err, probes)
	}
	clock, authority = clock.Add(time.Second), authority+1
	sum, err := m.Close(ctx, c.ProposalID)
	if err != nil || probes != 2 || sum.Counts.Ballots != 2 {
		t.Fatalf("at the real close: %v, %d probes, %+v", err, probes, sum)
	}
}

// A probe that fails counts nothing, never falling back to the service's
// clock; the next is at least ProbeRetry later. No probe at all: nothing
// is counted.
func TestCloseWithoutTheAuthority(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(input().ClosesAt, 0).Add(2 * CollectMargin)
	m.Now = func() time.Time { return clock }
	probes, fail := 0, true
	m.AuthorityTime = func(context.Context) (int64, error) {
		probes++
		if fail {
			return 0, errors.New("unreachable")
		}
		return clock.Unix(), nil
	}
	for i := 0; i < 2; i++ {
		if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityTime) || probes != 1 {
			t.Fatalf("try %d: %v, %d probes", i, err, probes)
		}
	}
	if o, _ := m.Store.OpenProposal(ctx, c.ProposalID); o.Published {
		t.Fatal("counted without the authority's time")
	}
	clock, fail = clock.Add(ProbeRetry), false
	if _, err := m.Close(ctx, c.ProposalID); err != nil || probes != 2 {
		t.Fatalf("after the retry time: %v, %d probes", err, probes)
	}
	m2, _, _ := newManager(t)
	m2.Catcher = &fakeCatcher{caught: true}
	c2, err := m2.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m2.Now, m2.AuthorityTime = m.Now, nil
	if _, err := m2.Close(ctx, c2.ProposalID); !errors.Is(err, ErrAuthorityTime) {
		t.Fatalf("no probe: %v", err)
	}
	if o, _ := m2.Store.OpenProposal(ctx, c2.ProposalID); o.Published {
		t.Fatal("counted with no probe")
	}
}

// The probe's rules (§7, 0.13.12): the close itself is the boundary; a
// passing probe holds for that close across collecting retries, and the
// empty-collect evidence must follow it plus the margin; a wait is void
// when the clock went back, and none lasts over ProbeMaxWait; a cancelled
// request is not a failure.
func TestAuthorityProbeRules(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	ct := &fakeCatcher{}
	m.Catcher = ct
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	clock := time.Unix(in.ClosesAt, 0).Add(2 * CollectMargin)
	m.Now = func() time.Time { return clock }
	authority, probes := in.ClosesAt-1, 0
	var probeErr error
	m.AuthorityTime = func(ctx context.Context) (int64, error) {
		probes++
		if probeErr != nil {
			return 0, probeErr
		}
		return authority, ctx.Err()
	}
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 1 {
		t.Fatalf("one second before the close: %v, %d probes", err, probes)
	}
	// The clock went back: the wait is void.
	clock = clock.Add(-30 * time.Second) // still past the close + margin
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 2 {
		t.Fatalf("after the clock went back: %v, %d probes", err, probes)
	}
	// A wait never lasts over ProbeMaxWait, whatever the estimate.
	clock, authority = time.Unix(in.ClosesAt, 0).Add(2*CollectMargin), in.ClosesAt-6*3600
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 3 {
		t.Fatalf("a far-behind authority: %v, %d probes", err, probes)
	}
	clock = clock.Add(ProbeMaxWait - time.Second)
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrAuthorityEarly) || probes != 3 {
		t.Fatalf("within the cap: %v, %d probes", err, probes)
	}
	clock = clock.Add(time.Second)
	// A request its caller cancelled still gets the whole probe (its own
	// timeout, apart from the request's): an answer, not a failure.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.authorityPast(cctx, c.ProposalID, in.ClosesAt); !errors.Is(err, ErrAuthorityEarly) || probes != 4 {
		t.Fatalf("a cancelled request's probe: %v, %d probes", err, probes)
	}
	clock = clock.Add(ProbeMaxWait)
	// At the close itself it passes; the relay isn't caught up yet, and the
	// passing probe holds for the retries (not probed again).
	authority, before := in.ClosesAt, probes
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrNotCaught) || probes != before+1 {
		t.Fatalf("at the close: %v, %d probes", err, probes-before)
	}
	probedAt := clock
	clock = clock.Add(time.Minute)
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrNotCaught) || probes != before+1 {
		t.Fatalf("a retry probed again: %v, %d probes", err, probes-before)
	}
	for i, at := range ct.emptyAfter {
		if !at.Equal(probedAt.Add(CollectMargin)) {
			t.Fatalf("Caught %d: emptyAfter %v, want the probe %v plus the margin", i, at, probedAt)
		}
	}
	if o, _ := m.Store.OpenProposal(ctx, c.ProposalID); o.Published {
		t.Fatal("the counts were fixed before the relay was caught up")
	}
}

// The probe is judged against the close in force: past the original close
// but before the extended one, the vote is still collecting.
func TestAuthorityProbeExtendedClose(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err != nil {
		t.Fatal(err)
	}
	*e.clock = time.Unix(e.in.ClosesAt+7200, 0).Add(2 * CollectMargin)
	e.m.AuthorityTime = func(context.Context) (int64, error) { return e.in.ClosesAt + 3600, nil }
	if _, err := e.m.Close(ctx, e.id); !errors.Is(err, ErrAuthorityEarly) {
		t.Fatalf("between the closes: %v", err)
	}
	e.m.probes.Delete(e.id)
	e.m.AuthorityTime = func(context.Context) (int64, error) { return e.in.ClosesAt + 7200, nil }
	if _, err := e.m.Close(ctx, e.id); err != nil {
		t.Fatalf("at the extended close: %v", err)
	}
}

// A cached pass keeps the probe's monotonic reading: the empty-collect
// evidence is compared on that clock, which a wall-clock step (NTP
// correcting a fast clock) doesn't move.
func TestAuthorityProbeCacheIsMonotonic(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	m.Now = time.Now
	m.AuthorityTime = func(context.Context) (int64, error) { return time.Now().Unix(), nil }
	first, err := m.authorityPast(ctx, "p", time.Now().Unix()-60)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := m.authorityPast(ctx, "p", time.Now().Unix()-60)
	if err != nil || !cached.Equal(first) {
		t.Fatalf("%v %v", cached, err)
	}
	if !strings.Contains(cached.String(), " m=") {
		t.Fatalf("the cached pass lost its monotonic reading: %v", cached)
	}
}

// A cached pass holds only for its close: a moved close (here judged
// directly) is probed again. seen is taken when the probe came back. The
// probe has its own deadline, apart from a cancelled request.
func TestAuthorityProbeCacheAndDeadline(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	clock := time.Unix(1_800_000_000, 0)
	m.Now = func() time.Time { return clock }
	probes, authority := 0, int64(1_800_000_000)
	m.AuthorityTime = func(pctx context.Context) (int64, error) {
		probes++
		if d, ok := pctx.Deadline(); !ok || time.Until(d) > ProbeTimeout || pctx.Err() != nil {
			t.Errorf("the probe's context: deadline %v %v, err %v", d, ok, pctx.Err())
		}
		clock = clock.Add(time.Minute) // the probe took a while
		return authority, nil
	}
	at, err := m.authorityPast(ctx, "p", 1_800_000_000-60)
	if err != nil || probes != 1 || !at.Equal(clock) {
		t.Fatalf("seen %v, want when the probe came back %v; %v", at, clock, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.authorityPast(cctx, "p", 1_800_000_000+3600); !errors.Is(err, ErrAuthorityEarly) || probes != 2 {
		t.Fatalf("a moved close: %v, %d probes", err, probes)
	}
}

// The monotonic reading reaches Caught: with this process's clock, the
// emptyAfter Close passes carries it, and the probe record goes once the
// counts are saved.
func TestCloseEmptyAfterIsMonotonic(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	ct := &fakeCatcher{caught: true}
	m.Catcher = ct
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	m.Now = time.Now // past the close: the test input's dates are before today
	m.AuthorityTime = func(context.Context) (int64, error) { return time.Now().Unix(), nil }
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	if len(ct.emptyAfter) != 1 || !strings.Contains(ct.emptyAfter[0].String(), " m=") {
		t.Fatalf("emptyAfter without a monotonic reading: %v", ct.emptyAfter)
	}
	if _, ok := m.probes.Load(c.ProposalID); ok {
		t.Fatal("the probe record was kept after the count")
	}
}
