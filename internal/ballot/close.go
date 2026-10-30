package ballot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/vote"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// Closing a vote (BALLOT-PROTOCOL §7): once every ballot of the window is
// in, the results are built from the write-once copy, checked as an
// observer checks them, signed, published and announced.

// KindResults is the published results' record (id: proposal_id).
const KindResults = "vote_results"

// CollectMargin is how far past the close the relay's messages must have
// been handled before the count (§7).
const CollectMargin = time.Minute

// Catcher reports whether every message the relay received before t has
// been handled (peer.Peer.Caught).
type Catcher interface {
	// Caught also returns how many messages from before t it stopped
	// waiting for (counts.unhandled, §7).
	Caught(ctx context.Context, t time.Time) (caught bool, unhandled int64, err error)
}

// ResultsPublisher anchors and publishes the results (§3.3), and returns
// their Sigstore bundle.
type ResultsPublisher interface {
	PublishResults(ctx context.Context, proposalID string, results, sig, rows []byte) (json.RawMessage, error)
}

// Errors from Close.
var (
	ErrNotClosed = errors.New("ballot: the vote hasn't closed")
	ErrNotCaught = errors.New("ballot: the relay's messages from before the close aren't all handled yet")
)

// PublishedResults is a vote's results as published.
type PublishedResults struct {
	Results []byte          `json:"results"`
	Sig     []byte          `json:"results_sig"`
	Rows    []byte          `json:"rows"`
	Bundle  json.RawMessage `json:"bundle,omitempty"`
}

// ResultsSummary is what Close reports.
type ResultsSummary struct {
	ProposalID  string           `json:"proposal_id"`
	ResultsHash []byte           `json:"results_hash"`
	Tally       map[string]int64 `json:"tally"`
	Counts      vote.Counts      `json:"counts"`
}

// Close counts a vote and publishes its results, or reports them if they
// are published already.
func (m *Manager) Close(ctx context.Context, id string) (*ResultsSummary, error) {
	unlock, err := m.lock(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rp, ok := m.Publisher.(ResultsPublisher)
	if m.Publisher == nil || !ok {
		return nil, ErrNoPublisher
	}
	o, err := m.Store.OpenProposal(ctx, id)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, ErrUnknownProposal
	}
	pr, err := m.Results(ctx, id)
	if err != nil {
		return nil, err
	}
	if pr == nil {
		end := time.Unix(o.ClosesAt, 0).Add(CollectMargin)
		if m.Now().Before(end) {
			return nil, ErrNotClosed
		}
		caught, unhandled, err := m.Catcher.Caught(ctx, end)
		if err != nil {
			return nil, err
		}
		if !caught {
			return nil, ErrNotCaught
		}
		// From here a cast is late (§4.2).
		if !o.Published {
			o.Published = true
			if err := m.Store.SaveProposal(ctx, o, false); err != nil {
				return nil, err
			}
		}
		if pr, err = m.count(ctx, o, unhandled); err != nil {
			return nil, err
		}
	}
	if pr.Bundle == nil {
		if pr.Bundle, err = rp.PublishResults(ctx, id, pr.Results, pr.Sig, pr.Rows); err != nil {
			return nil, fmt.Errorf("ballot: publish results of %s: %w", id, err)
		}
		if err := m.saveResults(ctx, id, pr, false); err != nil {
			return nil, err
		}
		m.announce(ctx, o, pr)
	}
	res, err := vote.ParseResults(pr.Results)
	if err != nil {
		return nil, err
	}
	return &ResultsSummary{ProposalID: id, ResultsHash: sum(pr.Results), Tally: res.Tally, Counts: res.Counts}, nil
}

// count builds and signs the results from the copy's ballots, checks them
// as an observer would, and stores them.
func (m *Manager) count(ctx context.Context, o *OpenProposal, unhandled int64) (*PublishedResults, error) {
	p, err := o.Parsed()
	if err != nil {
		return nil, err
	}
	items, err := m.Store.Copy.List(ctx, p.ProposalID)
	if err != nil {
		return nil, err
	}
	ballots := map[string]vote.Ballot{}
	for _, it := range items {
		r, err := decodeBallot(it.Data)
		if err != nil {
			return nil, err
		}
		ballots[string(r.Ballot.RecordTag)] = r.Ballot
	}
	active := map[string]bool{}
	for _, c := range m.Roster.Eligible() {
		active[c] = true
	}
	var removed int64
	for c := range o.Members {
		if !active[c] {
			removed++
		}
	}
	c := &vote.Count{Proposal: vote.Signed{Doc: o.Doc, Sig: o.Sig}, Extensions: o.Extensions, Tags: o.Tags(), Ballots: ballots, Removed: removed,
		Unhandled: unhandled}
	rows, results, err := c.Build()
	if err != nil {
		return nil, err
	}
	msg, _ := vote.DocSigMsg(sum(o.Doc), results)
	sig, err := m.Sign(vote.LabelResults, msg)
	if err != nil {
		return nil, err
	}
	if _, _, err := vote.Check(m.IK, results, sig, rows); err != nil {
		return nil, fmt.Errorf("ballot: the results don't pass the observer's check: %w", err)
	}
	pr := &PublishedResults{Results: results, Sig: sig, Rows: rows}
	if err := m.saveResults(ctx, p.ProposalID, pr, true); err != nil {
		return nil, err
	}
	m.log().Info("vote counted", "proposal_id", p.ProposalID, "eligible", p.Eligible, "ballots", len(ballots))
	return pr, nil
}

func (m *Manager) saveResults(ctx context.Context, id string, pr *PublishedResults, create bool) error {
	data, err := json.Marshal(pr)
	if err != nil {
		return err
	}
	return m.Store.Records.Apply(ctx, []peer.Change{{Kind: KindResults, ID: id, Data: data, IfAbsent: create}})
}

// Results returns a vote's results once counted, or nil.
func (m *Manager) Results(ctx context.Context, id string) (*PublishedResults, error) {
	data, ok, err := m.Store.Records.Get(ctx, KindResults, id)
	if err != nil || !ok {
		return nil, err
	}
	var pr PublishedResults
	if err := json.Unmarshal(data, &pr); err != nil {
		return nil, fmt.Errorf("ballot: stored results %s: %w", id, err)
	}
	return &pr, nil
}

// announce sends vote.closed to every eligible member (§4.1); a member it
// misses checks at its fixed time anyway (§8.3).
func (m *Manager) announce(ctx context.Context, o *OpenProposal, pr *PublishedResults) {
	p, _ := o.Parsed()
	body, _ := json.Marshal(struct {
		ProposalID  string `json:"proposal_id"`
		ResultsHash []byte `json:"results_hash"`
	}{p.ProposalID, sum(pr.Results)})
	for c := range o.Members {
		if _, err := m.Sender.SendMessage(ctx, c, TypeClosed, body); err != nil {
			m.log().Warn("vote.closed not sent", "proposal_id", p.ProposalID, "connection_id", c, "err", err.Error())
		}
	}
}
