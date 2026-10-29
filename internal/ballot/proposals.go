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
	"sync"
	"time"
)

// Proposals (BALLOT-PROTOCOL §3, §4.1): creating a proposal from the
// roster, publishing it, and sending it to every eligible member.

// Roster lists the connections eligible at this moment (§3.2): active,
// and with a vault that takes votes.
type Roster interface {
	Eligible() []string
}

// Sender sends a message to a member's vault over its connection.
type Sender interface {
	SendMessage(ctx context.Context, connID, typ string, body json.RawMessage) (string, error)
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

// Manager creates and publishes proposals.
type Manager struct {
	Store     *RecordStore
	Sign      func(label string, msg []byte) ([]byte, error)
	IK        ed25519.PublicKey
	Roster    Roster
	Sender    Sender
	Publisher Publisher
	Catcher   Catcher
	NewID     func(time.Time) (string, error)
	Now       func() time.Time
	Log       *slog.Logger

	// locks holds a proposal's lock (a chan struct{} of one) while it is
	// read, published and saved: Publish, Extend and Close each replace
	// the whole record, so one mustn't save a copy read before another's
	// save. One task runs the service vault, so a process lock suffices.
	locks sync.Map
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

// ProposalInput is what the application asks for (§3.1); the rest of the
// proposal is the service's.
type ProposalInput struct {
	Title          string        `json:"title"`
	Text           string        `json:"text"`
	Choices        []vote.Choice `json:"choices"`
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
	Sent         int    `json:"sent"`
}

// ErrInput is a proposal the application asked for that isn't valid.
type ErrInput struct{ Err error }

func (e *ErrInput) Error() string { return e.Err.Error() }
func (e *ErrInput) Unwrap() error { return e.Err }

// Create makes a proposal from the roster at this moment, stores it,
// publishes it and sends it to every eligible member. The choices get
// abstain if they lack it.
func (m *Manager) Create(ctx context.Context, in ProposalInput) (*Created, error) {
	if m.Publisher == nil {
		return nil, ErrNoPublisher
	}
	now := m.Now()
	id, err := m.NewID(now)
	if err != nil {
		return nil, err
	}
	choices := append([]vote.Choice{}, in.Choices...)
	if !(&vote.Proposal{Choices: choices}).HasChoice(vote.AbstainID) {
		choices = append(choices, vote.Choice{ID: vote.AbstainID, Label: "Abstain"})
	}
	conns := m.Roster.Eligible()
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
		Quorum: in.Quorum, Binding: in.Binding, RemovedMayVote: in.RemovedMayVote,
		RecordAt: now.Unix(), OpensAt: in.OpensAt, ClosesAt: in.ClosesAt,
		Eligible: int64(len(tags)), RecordRoot: vote.Root(tags), OutageRule: in.OutageRule}
	doc, err := vote.EncodeProposal(p)
	if err != nil {
		return nil, &ErrInput{err}
	}
	sig, err := m.Sign(vote.LabelProposal, vote.ProposalSigMsg(doc))
	if err != nil {
		return nil, err
	}
	o := &OpenProposal{Doc: doc, Sig: sig, ClosesAt: p.ClosesAt, Members: members}
	if err := m.Store.SaveProposal(ctx, o, true); err != nil {
		return nil, err
	}
	c := &Created{ProposalID: id, ProposalHash: sum(doc), Eligible: len(tags)}
	if c.Sent, err = m.Publish(ctx, id); err != nil {
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

// Publish publishes a stored proposal if it isn't yet, then sends
// vote.proposal to every eligible member, and returns how many it sent.
// A member it couldn't reach asks later (vote.status, §4.2).
func (m *Manager) Publish(ctx context.Context, id string) (int, error) {
	if m.Publisher == nil {
		return 0, ErrNoPublisher
	}
	unlock, err := m.lock(ctx, id)
	if err != nil {
		return 0, err
	}
	defer unlock()
	o, err := m.Store.OpenProposal(ctx, id)
	if err != nil {
		return 0, err
	}
	if o == nil {
		return 0, ErrUnknownProposal
	}
	if o.Bundle == nil {
		if o.Bundle, err = m.Publisher.PublishProposal(ctx, id, o.Doc, o.Sig); err != nil {
			return 0, fmt.Errorf("ballot: publish %s: %w", id, err)
		}
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return 0, err
		}
	}
	p, err := o.Parsed()
	if err != nil {
		return 0, err
	}
	tags := o.Tags()
	conns := make([]string, 0, len(o.Members))
	for c := range o.Members {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	sent := 0
	for _, c := range conns {
		mem := o.Members[c]
		proof, err := o.proofOf(tags, mem.Tag)
		if err != nil {
			return sent, err
		}
		body, err := json.Marshal(proposalBody{Proposal: o.Doc, ProposalSig: o.Sig, Bundle: o.Bundle, RecordSecret: mem.Secret,
			RecordProof: proof})
		if err != nil {
			return sent, err
		}
		if _, err := m.Sender.SendMessage(ctx, c, TypeProposal, body); err != nil {
			m.log().Warn("vote.proposal not sent", "proposal_id", id, "connection_id", c, "err", err.Error())
			continue
		}
		sent++
	}
	m.log().Info("proposal published", "proposal_id", id, "eligible", p.Eligible, "sent", sent)
	return sent, nil
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
