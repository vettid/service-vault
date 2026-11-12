package ballot

import (
	"bytes"
	"context"
	"encoding/hex"
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
// been handled before the count (§7). It is also the allowance for the
// timestamp authority's clock: a member's vault fails results whose
// timestamp is before the close (§8.3 step 2), so the results are
// anchored a minute after it by this service's clock, and checked before
// they are uploaded (ResultsPublisher).
const CollectMargin = time.Minute

// Catcher reports whether every message the relay received before t has
// been handled (peer.Peer.Caught).
type Catcher interface {
	// Caught also returns how many messages with a relay time in
	// [from, until) it stopped waiting for (counts.unhandled, §7). An
	// empty collect counts as evidence only from one started at or after
	// emptyAfter (this service's clock, after the authority-confirmed
	// close, §7 0.13.12).
	Caught(ctx context.Context, t, emptyAfter, from, until time.Time) (caught bool, unhandled int64, err error)
}

// ResultsPublisher anchors and publishes the results (§3.3), and returns
// their Sigstore bundle. With notBefore (Unix seconds, the closes_at in
// force) it uploads only a bundle timestamped at or after it, anchoring
// the results again in place of an earlier one (§8.3 step 2), and answers
// ErrStampedEarly when it has none.
type ResultsPublisher interface {
	PublishResults(ctx context.Context, proposalID string, results, sig, rows []byte, notBefore int64) (Receipt, error)
	// RepublishResults uploads again results the site holds (its index
	// stale) with the bundle uploaded first, checked again; an early or
	// unverifiable one is kept and not uploaded.
	RepublishResults(ctx context.Context, proposalID string, results, sig, rows []byte, bundle json.RawMessage, notBefore int64) (Receipt, error)
}

// Errors from Close.
var (
	ErrNotClosed = errors.New("ballot: the vote hasn't closed")
	ErrNotCaught = errors.New("ballot: the relay's messages from before the close aren't all handled yet")
	// ErrStampedEarly: the results' timestamp is before the close, so
	// nothing was uploaded; a later Close anchors them again.
	ErrStampedEarly = errors.New("ballot: the results' timestamp is before the close: not published yet")
	// ErrAuthorityEarly: the timestamp authority's time is before the
	// close in force, so the vote is still collecting (§7, 0.13.12).
	ErrAuthorityEarly = errors.New("ballot: the timestamp authority's time is before the close: still collecting")
	// ErrAuthorityTime: the timestamp authority's time couldn't be had or
	// verified; nothing is counted (never the service's clock instead).
	ErrAuthorityTime = errors.New("ballot: the timestamp authority's time is unavailable: not counted")
)

// probeWait is the last probe of a proposal's close: a passing one (ok,
// for closes), an authority time before the close (tsa), or a failure;
// seen is this service's clock when it came back.
type probeWait struct {
	closes, tsa int64
	// seen keeps its monotonic reading (this process's): a cached pass
	// is compared with an empty collect's start on that clock, which a
	// wall-clock step doesn't move.
	seen       time.Time
	ok, failed bool
}

// ProbeRetry is the least time between two probes when the last failed;
// the caller backs off further (BALLOT-PROTOCOL §7, 0.13.12).
const ProbeRetry = 10 * time.Second

// ProbeTimeout is how long a probe may take (shorter than a caller's
// request, so a hung authority is seen and alarmed).
const ProbeTimeout = 5 * time.Second

// ProbeMaxWait bounds the rationing: however the estimate reads, a probe
// is made again after it, so a clock corrected meanwhile never starves
// the close (§7, 0.13.12).
const ProbeMaxWait = 5 * time.Minute

// authorityPast returns, with nil, a time on this service's clock at which
// the timestamp authority's time was at or after closesAt (§7, 0.13.12):
// the count may start, and an empty collect started after it (plus the
// margin) is evidence. Before it, the vote is still collecting
// (ErrAuthorityEarly); a probe that fails, or none, is ErrAuthorityTime.
// Probes are rationed: a passing one holds for that closesAt (authority
// time only moves forward); after one before the close the next waits
// until the authority's time, judged from it and this clock since, can
// have reached closesAt; after a failure, ProbeRetry. A wait is void if
// this clock went back, and none lasts over ProbeMaxWait. It runs under
// the proposal's lock, so a slow authority holds that lock up to
// ProbeTimeout (5 s).
func (m *Manager) authorityPast(ctx context.Context, id string, closesAt int64) (time.Time, error) {
	nowT := m.Now()
	if v, ok := m.probes.Load(id); ok {
		w := v.(probeWait)
		since := int64(nowT.Sub(w.seen) / time.Second)
		if nowT.Before(w.seen) {
			since = -1
		}
		switch {
		case since < 0:
			// This clock went back: what was judged by it is void.
		case w.ok && w.closes == closesAt:
			return w.seen, nil
		case w.failed && since < int64(ProbeRetry/time.Second):
			m.log().Info("the timestamp authority's time: retried too soon after a failure", "proposal_id", id)
			return time.Time{}, ErrAuthorityTime
		case !w.ok && !w.failed && w.tsa+since < closesAt && since < int64(ProbeMaxWait/time.Second):
			m.log().Info("the timestamp authority can't be past the close yet: not probed", "proposal_id", id, "closes_at", closesAt)
			return time.Time{}, ErrAuthorityEarly
		}
	}
	if m.AuthorityTime == nil {
		m.log().Error("no timestamp authority to ask: the vote is not counted", "alarm", "tsa_unavailable", "proposal_id", id)
		return time.Time{}, ErrAuthorityTime
	}
	// The probe has its own timeout, apart from the request's: a hung
	// authority is the authority's failure (alarmed), not a cancelled
	// request's, and a request the caller drops doesn't cut it short.
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), ProbeTimeout)
	t, err := m.AuthorityTime(pctx)
	cancel()
	if err != nil {
		// The floor runs from when the failure came back.
		m.probes.Store(id, probeWait{seen: m.Now(), failed: true})
		m.log().Error("the timestamp authority's time is unavailable: the vote is not counted", "alarm", "tsa_unavailable", "proposal_id", id, "err", err.Error())
		return time.Time{}, fmt.Errorf("%w: %v", ErrAuthorityTime, err)
	}
	seen := m.Now()
	if t < closesAt {
		m.probes.Store(id, probeWait{closes: closesAt, tsa: t, seen: seen})
		m.log().Error("the vote's close passed by this service's clock but not by the timestamp authority's: still collecting", "alarm", "count_clock_ahead",
			"proposal_id", id, "authority_time", t, "closes_at", closesAt, "skew_seconds", seen.Unix()-t)
		return time.Time{}, ErrAuthorityEarly
	}
	m.probes.Store(id, probeWait{closes: closesAt, seen: seen, ok: true})
	return seen, nil
}

// PublishedResults is a vote's results as published.
type PublishedResults struct {
	Results []byte `json:"results"`
	Sig     []byte `json:"results_sig"`
	// Rows are stored in chunks (KindChunk) named by RowChunks, written
	// with the first save; a record from before chunks holds them inline.
	Rows      []byte          `json:"rows,omitempty"`
	RowChunks []chunkRef      `json:"row_chunks,omitempty"`
	Bundle    json.RawMessage `json:"bundle,omitempty"`
	// IndexStale is set while the site has the results but answered that
	// its index isn't updated: the identical upload is repeated at each
	// Close until it is (BALLOT-PROTOCOL §3.3).
	IndexStale bool `json:"index_stale,omitempty"`
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
	sr, ok2 := m.Publisher.(SiteReader)
	ep, ok3 := m.Publisher.(ExtensionPublisher)
	bs, ok4 := m.Publisher.(BundleSource)
	if m.Publisher == nil || !ok || !ok2 || !ok3 || !ok4 {
		return nil, ErrNoPublisher
	}
	o, err := m.Store.OpenProposalFresh(ctx, id)
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
		// Held but not published: members' requests are not answered
		// meanwhile (ErrUnpublished), so counting now would leave out
		// ballots they will send again once it is published.
		if o.Bundle == nil {
			m.log().Error("close of an unpublished proposal: publish it", "alarm", "vote_unpublished", "proposal_id", id)
			return nil, ErrUnpublished
		}
		// Before counting: the extensions are the site's (an extension
		// published but not stored moves the close). Nothing is counted
		// while they can't be reconciled.
		if err := m.reconcile(ctx, sr, ep, bs, o); err != nil {
			return nil, err
		}
		end = time.Unix(o.ClosesAt, 0).Add(CollectMargin)
		if m.Now().Before(end) {
			return nil, ErrNotClosed
		}
		p, err := o.Parsed()
		if err != nil {
			return nil, err
		}
		// From here a cast is late (§4.2), and the counts that depend on
		// the moment are fixed: a retry after a failed count or publication
		// uses them, not the roster or the relay as they are then.
		if !o.Published || o.Unhandled == nil || o.Removed == nil {
			// The service's clock alone never starts the count: the
			// timestamp authority's time must be past the close too (§7,
			// 0.13.12), or a fast clock would refuse in-window casts.
			// An empty collect is timed by this clock too, so it counts as
			// evidence only after the passing probe plus the margin.
			emptyAfter := end
			if !o.Published {
				at, err := m.authorityPast(ctx, id, o.ClosesAt)
				if err != nil {
					return nil, err
				}
				emptyAfter = at.Add(CollectMargin)
			}
			// unhandled counts the window's messages: one in the last
			// minute would be a late cast.
			caught, unhandled, err := m.Catcher.Caught(ctx, end, emptyAfter, time.Unix(p.OpensAt, 0), time.Unix(o.ClosesAt, 0))
			if err != nil {
				return nil, err
			}
			if !caught {
				return nil, ErrNotCaught
			}
			removed := m.removed(o)
			o.Published, o.Unhandled, o.Removed = true, &unhandled, &removed
			if err := m.Store.SaveProposal(ctx, o, false); err != nil {
				return nil, err
			}
			m.probes.Delete(id) // counted: no more probes for it
		}
		if pr, err = m.count(ctx, o); err != nil {
			return nil, err
		}
	}
	if pr.Bundle == nil {
		rc, err := rp.PublishResults(ctx, id, pr.Results, pr.Sig, pr.Rows, o.ClosesAt)
		if err != nil {
			return nil, fmt.Errorf("ballot: publish results of %s: %w", id, err)
		}
		pr.Bundle, pr.IndexStale = rc.Bundle, rc.IndexStale
		if err := m.saveResults(ctx, id, pr, false); err != nil {
			return nil, err
		}
		m.announce(o, pr)
	} else if pr.IndexStale {
		// The site has the results; its index missed them. The identical
		// upload again reruns the index update. Its bundle was checked
		// before the first upload, and is checked again.
		switch rc, err := rp.RepublishResults(ctx, id, pr.Results, pr.Sig, pr.Rows, pr.Bundle, o.ClosesAt); {
		case err != nil:
			m.log().Warn("site index still not updated for the results", "proposal_id", id, "err", err.Error())
		case !rc.IndexStale:
			pr.IndexStale = false
			if err := m.saveResults(ctx, id, pr, false); err != nil {
				m.log().Warn("results not saved", "proposal_id", id, "err", err.Error())
			}
		}
	}
	res, err := vote.ParseResults(pr.Results)
	if err != nil {
		return nil, err
	}
	return &ResultsSummary{ProposalID: id, ResultsHash: sum(pr.Results), Tally: res.Tally, Counts: res.Counts}, nil
}

// removed counts the proposal's members no longer on the roster.
func (m *Manager) removed(o *OpenProposal) int64 {
	active := map[string]bool{}
	for _, c := range m.Roster.Active() {
		active[c] = true
	}
	var removed int64
	for c := range o.Members {
		if !active[c] {
			removed++
		}
	}
	return removed
}

// count builds and signs the results from the copy's ballots, checks them
// as an observer would, and stores them. The copy is listed once: Close
// saved o as Published before this, and a cast is written only while the
// proposal is as that cast read it, so none can be written after the
// list. Each ballot is checked again, and one that fails isn't counted.
func (m *Manager) count(ctx context.Context, o *OpenProposal) (*PublishedResults, error) {
	p, err := o.Parsed()
	if err != nil {
		return nil, err
	}
	if o.Unhandled == nil || o.Removed == nil {
		return nil, errors.New("ballot: counting a proposal whose counts weren't fixed")
	}
	items, err := m.Store.Copy.List(ctx, p.ProposalID)
	if err != nil {
		return nil, err
	}
	ph := sum(o.Doc)
	ballots := map[string]vote.Ballot{}
	for _, it := range items {
		r, err := decodeBallot(it.Data)
		if err != nil {
			return nil, err
		}
		if why := checkStored(p, o.ClosesAt, ph, it.Tag, r); why != "" {
			m.log().Error("ballot not counted", "proposal_id", p.ProposalID, "tag", hex.EncodeToString(it.Tag), "why", why, "alarm", "ballot_not_counted")
			continue
		}
		ballots[string(r.Ballot.RecordTag)] = r.Ballot
	}
	c := &vote.Count{Proposal: vote.Signed{Doc: o.Doc, Sig: o.Sig}, Extensions: o.Extensions, Tags: o.Tags(), Ballots: ballots, Removed: *o.Removed,
		Unhandled: *o.Unhandled}
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

// checkStored re-checks a stored ballot as cast checked it: it is under
// its own tag, the credential signature verifies under the key stored
// with it, and the relay's time was inside the window. It returns why not,
// or "".
func checkStored(p *vote.Proposal, closesAt int64, ph, tag []byte, r *BallotRecord) string {
	if !bytes.Equal(r.Ballot.RecordTag, tag) {
		return "tag differs from the item's"
	}
	leaf, err := r.Ballot.Leaf()
	if err != nil {
		return "no leaf"
	}
	cmsg, err := vote.CastMsg(ph, leaf)
	if err != nil || vote.Verify(r.CredentialKey, vote.LabelCast, cmsg, r.CastSig) != nil {
		return "cast_sig doesn't verify"
	}
	if r.MsgMS < uint64(p.OpensAt)*1000 || r.MsgMS >= uint64(closesAt)*1000 {
		return "relay time outside the window"
	}
	return ""
}

func (m *Manager) saveResults(ctx context.Context, id string, pr *PublishedResults, create bool) error {
	// Results always have a row per member; none is never saved.
	if len(pr.Rows) == 0 {
		return fmt.Errorf("ballot: results of %s without rows", id)
	}
	// The rows go to chunks at the first save, before the record; later
	// saves name the same chunks.
	if create {
		refs, err := putChunks(ctx, m.Store.Records, id, pr.Rows, maxRowChunks)
		if err != nil {
			return err
		}
		pr.RowChunks = refs
	}
	stored := *pr
	if len(pr.RowChunks) > 0 {
		stored.Rows = nil
	}
	data, err := json.Marshal(&stored)
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
	if len(pr.RowChunks) > 0 {
		if pr.Rows != nil {
			return nil, fmt.Errorf("ballot: stored results %s: rows both inline and in chunks", id)
		}
		if pr.Rows, err = getChunks(ctx, m.Store.Records, id, pr.RowChunks, maxRowChunks); err != nil {
			return nil, fmt.Errorf("ballot: stored results %s's rows: %w", id, err)
		}
	}
	// Results always have a row per member (never none).
	if len(pr.Rows) == 0 {
		return nil, fmt.Errorf("ballot: stored results %s: no rows", id)
	}
	return &pr, nil
}

// announce starts sending vote.closed to every eligible member in the
// background (§4.1, sends.go); a member it misses checks at its fixed
// time anyway (§8.3).
func (m *Manager) announce(o *OpenProposal, pr *PublishedResults) {
	p, _ := o.Parsed()
	body, _ := json.Marshal(struct {
		ProposalID  string `json:"proposal_id"`
		ResultsHash []byte `json:"results_hash"`
	}{p.ProposalID, sum(pr.Results)})
	m.sendInBackground(p.ProposalID, "closed/"+p.ProposalID, TypeClosed, sortedConns(o.Members), m.Now().Add(ClosedSendLife),
		func(string) (json.RawMessage, error) { return body, nil })
}
