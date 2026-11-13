package ballot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/vote"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Proposals (BALLOT-PROTOCOL §3, §4.1): creating a proposal from the
// roster, publishing it, and sending it to every eligible member.

// Roster lists the connections at this moment.
type Roster interface {
	// Eligible lists those eligible (§3.2): active, and with a vault
	// that takes votes.
	Eligible() []string
	// EligibleUnsigned lists those of them whose credential key is not
	// pinned: their vault refuses a vote until the member has signed in
	// on the connection (VAULT-MESSAGING §10.19.5).
	EligibleUnsigned() []string
	// Active lists the active ones, whether or not their vault takes
	// votes: a member not among them is removed or suspended (§10.1).
	Active() []string
}

// Sender sends a message to a member's vault over its connection.
type Sender interface {
	SendMessage(ctx context.Context, connID, typ string, body json.RawMessage, notAfter time.Time) (string, error)
}

// Publisher anchors a proposal and publishes it on votes.vettid.org
// (§3.3), and returns its Sigstore bundle.
type Publisher interface {
	PublishProposal(ctx context.Context, proposalID string, doc, sig []byte) (json.RawMessage, error)
}

// ErrNoPublisher is creating a proposal with no way to publish it: the
// protocol sends no proposal that isn't published (§3.3).
var ErrNoPublisher = errors.New("ballot: proposals can't be published here")

// ErrUnknownProposal is a proposal id the service doesn't hold.
var ErrUnknownProposal = errors.New("ballot: unknown proposal")

// MaxEligible is the most eligible members this service lets a proposal
// have (chosen; not in the spec; BALLOT-PROTOCOL §3.2), below the
// protocol's vote.MaxEligible (100,000). It stays 1,000 until a staging
// run at PlannedMaxEligible passes (the owner's choice, GC #8336), then
// is raised to it.
const MaxEligible = 1000

// PlannedMaxEligible is the cap this service is built and tested for:
// verified to fit, and MaxEligible is raised to it after the staging run.
// The stored values' bounds (chunk.go) already allow it. At 15,000
// (#6946, TestMaxEligibleFitsOneItem):
//   - the members (about 140 bytes each, 2.1 MB) and the results' rows
//     (about 251 bytes each, 3.8 MB) are stored in chunks (KindChunk) of
//     ChunkSize, 8 and 13 of them, so DynamoDB's 400 KB item doesn't
//     bound them;
//   - every member's record proof comes from one tree (about 14 ms);
//   - the sends go out in the background (sends.go), not in the request;
//   - the rows, 5.0 MB as base64, fit the results' single upload to the
//     votes site (6,225,920 bytes, less at most 512 KB of results as
//     base64 and a 64 KB bundle: SiteRowsUpload), and so would rows of
//     maxRowBytes;
//   - create answers in tens of milliseconds and close in about 1.5 s
//     of the API's 30 s, with fakes for the site and the peer.
//
// The upload is the binding bound: past about 16,000 members the rows no
// longer fit it, and the results would need to go up in parts.
const PlannedMaxEligible = 15000

// ResendCover is how long before its close a held proposal must be
// published for every member's vault to send its cast again in time: the
// vaults send again at 1, 5 and 30 minutes, then hourly, and stop at the
// close (VAULT-MESSAGING §10.19.5), so up to an hour and some minutes may
// pass before a vault's next send (BALLOT-PROTOCOL §4.2).
const ResendCover = 70 * time.Minute

// ErrTooManyEligible refuses a proposal whose roster has more than
// MaxEligible eligible members, before its approval is used.
var ErrTooManyEligible = fmt.Errorf("ballot: this service supports at most %d eligible members per vote", MaxEligible)

// Manager creates and publishes proposals.
type Manager struct {
	Store     *RecordStore
	Sign      func(label string, msg []byte) ([]byte, error)
	IK        ed25519.PublicKey
	Roster    Roster
	Sender    Sender
	Publisher Publisher
	Catcher   Catcher
	// Approvals checks and uses the admins' approvals; nil creates and
	// extends nothing.
	Approvals Approvals
	// Timestamp returns the verified RFC 3161 time (Unix seconds) of the
	// bundle this service anchored for doc, or an error
	// (anchor.TimestampTime). It decides whether an extension came before
	// the close it extends; nil decides nothing in effect (fail closed).
	Timestamp func(bundle json.RawMessage, doc []byte) (int64, error)
	// AuthorityTime asks the timestamp authority for the time, verified
	// (anchor.AuthorityTime): a vote is counted only once it is at or
	// after the close in force (BALLOT-PROTOCOL §7, 0.13.12). Nil counts
	// nothing (fail closed).
	AuthorityTime func(ctx context.Context) (int64, error)
	// CheckBundle checks a proposal's or an extension's Sigstore bundle as
	// a member vault will, against the trusted roots every supported vault
	// release pins (internal/vaultroots), before members are sent it, with
	// the latest time the bundle's stamp may have (zero: the vaults' limit
	// for a message sent now). Nil sends nothing (fail closed), and Create
	// refuses before the approval is used.
	CheckBundle func(doc []byte, bundle json.RawMessage, notAfter time.Time) error
	NewID       func(time.Time) (string, error)
	Now         func() time.Time
	Log         *slog.Logger
	// Background is the context member sends run under, after the request
	// that started them (sends.go); they stop when it ends. The daemon's
	// lasts until its shutdown has waited for them. Nil:
	// context.Background().
	Background context.Context

	// locks holds a proposal's lock (a chan struct{} of one) while it is
	// read, published and saved: Publish, Extend and Close each replace
	// the whole record, so one mustn't save a copy read before another's
	// save. One task runs the service vault, so a process lock suffices.
	locks sync.Map
	// probes holds, by proposal, an authority time before the close
	// (probeWait): no probe until the authority's time can have reached it.
	probes sync.Map
	sends  sends
	// eligibleCap, when set (tests, at most PlannedMaxEligible), is the cap
	// in place of MaxEligible.
	eligibleCap int
}

// maxEligible is the cap Create applies.
func (m *Manager) maxEligible() int {
	if m.eligibleCap > 0 {
		return min(m.eligibleCap, PlannedMaxEligible)
	}
	return MaxEligible
}

// ErrNoTimestamps is a service vault with no way to verify the time of an
// anchor bundle: it applies no extension.
var ErrNoTimestamps = errors.New("ballot: anchor timestamps can't be verified here")

// ErrBundleUnverified is a bundle a member vault would not accept: its
// proposal or extension is not sent (the alarm proposal_bundle_unverified).
var ErrBundleUnverified = errors.New("ballot: the anchor bundle does not verify against the vaults' pinned roots")

// ErrNoBundleCheck is a service vault with no bundle check (no vault
// release of its Sigstore instance pins vote trust roots): Create refuses
// before the approval is used, since nothing it published could be sent.
var ErrNoBundleCheck = fmt.Errorf("%w: no bundle check configured", ErrBundleUnverified)

// checkBundle checks doc's bundle before members are sent it (CheckBundle),
// and raises proposal_bundle_unverified when it fails.
func (m *Manager) checkBundle(what, id string, doc []byte, bundle json.RawMessage, notAfter time.Time) error {
	err := ErrNoBundleCheck
	if m.CheckBundle != nil {
		err = m.CheckBundle(doc, bundle, notAfter)
	}
	if err == nil {
		return nil
	}
	m.log().Error("an anchor bundle a member vault would refuse: nothing is sent", "alarm", "proposal_bundle_unverified",
		"proposal_id", id, "document", what, "err", err.Error())
	return fmt.Errorf("%w: %s of %s: %v", ErrBundleUnverified, what, id, err)
}

func (m *Manager) tsaTime(bundle json.RawMessage, doc []byte) (int64, error) {
	if m.Timestamp == nil {
		return 0, ErrNoTimestamps
	}
	return m.Timestamp(bundle, doc)
}

// lock takes a proposal's lock, waiting at most as long as ctx allows,
// and returns its release.
func (m *Manager) lock(ctx context.Context, id string) (func(), error) {
	v, _ := m.locks.LoadOrStore(id, make(chan struct{}, 1))
	ch := v.(chan struct{})
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ChoiceInput is a choice the application lists: only its label. The
// service assigns the ids (c1, c2, … in this order) and adds abstain.
type ChoiceInput struct {
	Label string `json:"label"`
}

// ProposalInput is what the application asks for (§3.1, §3.4); the rest
// of the proposal is the service's. Of its fields the admins are shown
// the title, the labels, binding, removed_may_vote, the times and the
// quorum's min_ballots; text must be empty or the title, quorum.text must
// be empty, and outage_rule must be empty or DefaultOutageRule.
type ProposalInput struct {
	Title          string        `json:"title"`
	Text           string        `json:"text"`
	Choices        []ChoiceInput `json:"choices"`
	Quorum         vote.Quorum   `json:"quorum"`
	Binding        bool          `json:"binding"`
	RemovedMayVote bool          `json:"removed_may_vote"`
	OpensAt        int64         `json:"opens_at"`
	ClosesAt       int64         `json:"closes_at"`
	OutageRule     string        `json:"outage_rule"`
}

// Created is a new proposal.
type Created struct {
	ProposalID   string `json:"proposal_id"`
	ProposalHash []byte `json:"proposal_hash"`
	Eligible     int    `json:"eligible"`
	// Unsigned is how many of the eligible connections have no pinned
	// credential key at creation: their vaults refuse a vote
	// (not_signed_in) until the member signs in.
	Unsigned int `json:"unsigned"`
	// Sending is how many members vote.proposal is being sent to, in the
	// background (sends.go).
	Sending int `json:"sending"`
}

// ErrInput is a proposal the application asked for that isn't valid.
type ErrInput struct{ Err error }

func (e *ErrInput) Error() string { return e.Err.Error() }
func (e *ErrInput) Unwrap() error { return e.Err }

// Create makes a proposal from the roster at this moment, stores it,
// publishes it and sends it to every eligible member. The choices get
// abstain if they lack it.
//
// It needs the admins' approval (a proposal.create approval) of exactly
// in, in its canonical form (CanonicalProposal), and uses it up. The
// order is: everything that can refuse the input is checked first, so
// that a refusal leaves the approval usable; then the approval is
// checked and used, once; then the proposal is stored, published and
// sent. A failure after the approval was used leaves it used (the
// admins approve again); a proposal stored and not published is
// published by Publish.
func (m *Manager) Create(ctx context.Context, approvalID string, in ProposalInput) (*Created, error) {
	if m.Publisher == nil {
		return nil, ErrNoPublisher
	}
	if m.CheckBundle == nil {
		m.log().Error("no bundle check: proposals are refused", "alarm", "proposal_bundle_unverified")
		return nil, ErrNoBundleCheck
	}
	if err := checkInput(&in); err != nil {
		return nil, &ErrInput{err}
	}
	payload, err := CanonicalProposal(in)
	if err != nil {
		return nil, &ErrInput{err}
	}
	now := m.Now()
	id, err := m.NewID(now)
	if err != nil {
		return nil, err
	}
	// The ids are the service's: c1, c2, … in the order of the labels,
	// then the reserved abstain.
	choices := make([]vote.Choice, 0, len(in.Choices)+1)
	for i, c := range in.Choices {
		choices = append(choices, vote.Choice{ID: "c" + strconv.Itoa(i+1), Label: c.Label})
	}
	choices = append(choices, vote.Choice{ID: vote.AbstainID, Label: "Abstain"})
	conns := m.Roster.Eligible()
	if len(conns) == 0 {
		// A member's vault refuses a proposal with no eligible member
		// (§3.1), and none would get it.
		return nil, &ErrInput{errors.New("ballot: no eligible members")}
	}
	if len(conns) > m.maxEligible() {
		return nil, fmt.Errorf("%w: the roster has %d", ErrTooManyEligible, len(conns))
	}
	sort.Strings(conns)
	members := map[string]Member{}
	tags := make([][]byte, 0, len(conns))
	for _, c := range conns {
		secret := make([]byte, vote.SecretLen)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		tag, err := vote.RecordTag(id, secret)
		if err != nil {
			return nil, err
		}
		members[c] = Member{Tag: tag, Secret: secret}
		tags = append(tags, tag)
	}
	sortTags(tags)
	p := &vote.Proposal{V: 1, ProposalID: id, Service: m.IK, Title: in.Title, Text: in.Text, Choices: choices,
		Quorum: vote.Quorum{MinBallots: in.Quorum.MinBallots}, Binding: in.Binding, RemovedMayVote: in.RemovedMayVote,
		RecordAt: now.Unix(), OpensAt: in.OpensAt, ClosesAt: in.ClosesAt,
		Eligible: int64(len(tags)), RecordRoot: vote.Root(tags), OutageRule: DefaultOutageRule}
	doc, err := vote.EncodeProposal(p)
	if err != nil {
		return nil, &ErrInput{err}
	}
	sig, err := m.Sign(vote.LabelProposal, vote.ProposalSigMsg(doc))
	if err != nil {
		return nil, err
	}
	if err := m.consume(ctx, approvalID, ActionProposalCreate, payload, Use{ProposalID: id}); err != nil {
		return nil, err
	}
	o := &OpenProposal{Doc: doc, Sig: sig, ClosesAt: p.ClosesAt, Members: members}
	if err := m.Store.SaveProposal(ctx, o, true); err != nil {
		return nil, err
	}
	c := &Created{ProposalID: id, ProposalHash: sum(doc), Eligible: len(tags), Unsigned: countIn(conns, m.Roster.EligibleUnsigned())}
	if c.Sending, err = m.Publish(ctx, id); err != nil {
		return c, &ErrNotPublished{ProposalID: id, Err: err}
	}
	return c, nil
}

// ErrNotPublished is a proposal created but not yet published (and so
// sent to no member): Publish retries it.
type ErrNotPublished struct {
	ProposalID string
	Err        error
}

func (e *ErrNotPublished) Error() string { return e.Err.Error() }
func (e *ErrNotPublished) Unwrap() error { return e.Err }

// Publish publishes a stored proposal if it isn't yet, then starts
// sending vote.proposal to every eligible member in the background
// (sends.go), and returns how many it is sending to. A member it can't
// reach asks later (vote.status, §4.2). Called again while its sends run,
// it doesn't start them twice.
func (m *Manager) Publish(ctx context.Context, id string) (int, error) {
	if m.Publisher == nil {
		return 0, ErrNoPublisher
	}
	unlock, err := m.lock(ctx, id)
	if err != nil {
		return 0, err
	}
	defer unlock()
	o, err := m.Store.OpenProposalFresh(ctx, id)
	if err != nil {
		return 0, err
	}
	if o == nil {
		return 0, ErrUnknownProposal
	}
	// Once the vote is counted (the results record is kept at the count,
	// before the upload), members are sent vote.closed: a vote.proposal
	// sent after it would only tell them of a vote that is over.
	if _, done, err := m.Store.Records.Get(ctx, KindResults, id); err != nil {
		return 0, err
	} else if done {
		m.log().Info("vote.proposal not sent: the vote is counted", "proposal_id", id)
		return 0, nil
	}
	if o.Bundle == nil {
		// Published late (members' requests went unanswered meanwhile):
		// their vaults send a cast again hourly and stop at the close, so
		// with less than ResendCover left some may not reach it in time.
		if left := time.Unix(o.ClosesAt, 0).Sub(m.Now()); left > 0 && left < ResendCover {
			m.log().Warn("publishing near the close: extend the vote so every member's vault sends again", "proposal_id", id, "left", left.Round(time.Minute).String())
		}
		if o.Bundle, err = m.Publisher.PublishProposal(ctx, id, o.Doc, o.Sig); err != nil {
			return 0, fmt.Errorf("ballot: publish %s: %w", id, err)
		}
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return 0, err
		}
	}
	// Before any member is sent it, whether just published or published
	// before: a vault refuses what this refuses, so sending it would
	// only leave members unable to vote.
	if err := m.checkBundle("proposal", id, o.Doc, o.Bundle, time.Time{}); err != nil {
		return 0, err
	}
	p, err := o.Parsed()
	if err != nil {
		return 0, err
	}
	conns := sortedConns(o.Members)
	body := func(c string) (json.RawMessage, error) {
		mem := o.Members[c]
		proof, err := o.proofOf(mem.Tag)
		if err != nil {
			return nil, err
		}
		return json.Marshal(proposalBody{Proposal: o.Doc, ProposalSig: o.Sig, Bundle: o.Bundle, RecordSecret: mem.Secret,
			RecordProof: proof})
	}
	// The first member's body is built here, so that a broken record tree
	// fails the request rather than every send after it has answered.
	if len(conns) > 0 {
		if _, err := body(conns[0]); err != nil {
			return 0, fmt.Errorf("ballot: publish %s: a member's body: %w", id, err)
		}
	}
	sending := 0
	if m.sendInBackground(id, "proposal/"+id, TypeProposal, conns, voteSendUntil(o.ClosesAt), body) {
		sending = len(conns)
	}
	m.log().Info("proposal published", "proposal_id", id, "eligible", p.Eligible, "sending", sending)
	return sending, nil
}

// proposalBody is vote.proposal's body (§4.1).
type proposalBody struct {
	Proposal     []byte          `json:"proposal"`
	ProposalSig  []byte          `json:"proposal_sig"`
	Bundle       json.RawMessage `json:"bundle"`
	RecordSecret []byte          `json:"record_secret"`
	RecordProof  recordProof     `json:"record_proof"`
}

func nonNil(p [][]byte) [][]byte {
	if p == nil {
		return [][]byte{}
	}
	return p
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// ProposalStatus is what the application can read of a proposal before
// its results: nothing that counts ballots (§6 "No running tally").
type ProposalStatus struct {
	ProposalID   string `json:"proposal_id"`
	Proposal     string `json:"proposal"`
	ProposalHash []byte `json:"proposal_hash"`
	Eligible     int64  `json:"eligible"`
	OpensAt      int64  `json:"opens_at"`
	ClosesAt     int64  `json:"closes_at"` // as extended
	Published    bool   `json:"published"`
}

// Status reports a proposal, or nil for an unknown id.
func (m *Manager) Status(ctx context.Context, id string) (*ProposalStatus, error) {
	o, err := m.Store.OpenProposal(ctx, id)
	if err != nil || o == nil {
		return nil, err
	}
	p, err := o.Parsed()
	if err != nil {
		return nil, err
	}
	return &ProposalStatus{ProposalID: id, Proposal: string(o.Doc), ProposalHash: sum(o.Doc), Eligible: p.Eligible,
		OpensAt: p.OpensAt, ClosesAt: o.ClosesAt, Published: o.Bundle != nil}, nil
}

// countIn counts the ids of some that are in all.
func countIn(all, some []string) int {
	in := make(map[string]bool, len(all))
	for _, id := range all {
		in[id] = true
	}
	n := 0
	for _, id := range some {
		if in[id] {
			n++
		}
	}
	return n
}
