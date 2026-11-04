package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/vote"
	"time"
)

// Extensions (BALLOT-PROTOCOL §10.2): a relay outage of more than an hour
// within the window extends the close by the outage, rounded up to the
// hour, by extensions totalling at most 24 h, each published before the
// close it extends.

// ExtensionPublisher anchors and publishes an extension (§3.3), and
// returns its Sigstore bundle.
type ExtensionPublisher interface {
	PublishExtension(ctx context.Context, proposalID string, n int64, doc, sig []byte) (Receipt, error)
}

// Receipt is what a publication returns: the document's bundle, and
// whether the site wrote the document but not its index entry
// (index_updated false in its answer; a missing field is not stale). The
// identical upload again finishes the index (BALLOT-PROTOCOL §3.3).
type Receipt struct {
	Bundle     json.RawMessage
	IndexStale bool
}

// BundleSource returns the bundle this service anchored for a document
// and kept (nil if there is none), without anchoring anything. Times are
// read only from such a bundle, never from one the site served.
type BundleSource interface {
	StoredBundle(ctx context.Context, doc []byte) (json.RawMessage, error)
}

// ErrPublishRefused is the site refusing a document with a code it gave:
// no retry changes it.
type ErrPublishRefused struct {
	Status int
	Code   string
}

func (e *ErrPublishRefused) Error() string {
	return fmt.Sprintf("publish: votes.vettid.org refused it: %d %s", e.Status, e.Code)
}

// MinOutage is the shortest outage that extends a vote (§10.2).
const MinOutage = 3600

// ExtensionInput is what the application asks for.
type ExtensionInput struct {
	ClosesAt int64       `json:"closes_at"`
	Outage   vote.Outage `json:"outage"`
}

// ExtendMargin is how long before the close an extension must be asked
// for: one published later may not reach the close it extends in time
// (§10.2), and the approval would be used for nothing. It is refused
// before the approval is looked at, so that it stays usable. It is
// CollectMargin, the margin the count already allows after the close.
const ExtendMargin = CollectMargin

// MaxExtensions is the most extensions a vote may have, as the votes
// site and the members' vaults bound them (BALLOT-PROTOCOL §10.2). The
// 24 h total alone does not bound their number (one may move the close
// by a second), and each is kept in the proposal's record and its
// results', so this also bounds those records' size (MaxEligible).
const MaxExtensions = 24

// ErrTooLate is an extension asked for once the close it would extend has
// passed, or one whose RFC 3161 time is not before that close.
var ErrTooLate = errors.New("ballot: the close to extend has passed")

// ErrExtensionPending is a new extension asked for while another is signed
// and stored but not yet in effect: it is finished (the same request
// again) or settled by Close first.
var ErrExtensionPending = errors.New("ballot: another extension is pending")

// Extend publishes an extension and sends vote.extended to every eligible
// member. The site also refuses a first upload by its own clock (once the
// close it extends has passed on the site), whatever the bundle says.
//
// It needs the admins' approval (a vote.extend approval) of exactly this
// extension of this proposal, in its canonical form (CanonicalExtension).
// The order is: refusals, sign, store the signed extension as pending
// (conditional on the record's version), use the approval, publish it,
// mark it in effect. The site's copy is write-once, so what is published
// must be stored first: a failure after the store leaves the pending
// extension, and the same request again (with the same approval, whose use
// is repeated, never doubled) publishes the same bytes and finishes. If
// the approval is refused the pending extension is cleared and the approval
// is as it was.
//
// Whether the extension is in effect is decided by the RFC 3161 time in
// the bundle this service anchored for it (Manager.Timestamp), as the site decides:
// before the close it extends, or it does not apply (ErrTooLate).
func (m *Manager) Extend(ctx context.Context, id, approvalID string, in ExtensionInput) (*vote.Extension, error) {
	unlock, err := m.lock(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ep, ok := m.Publisher.(ExtensionPublisher)
	bs, ok2 := m.Publisher.(BundleSource)
	if m.Publisher == nil || !ok || !ok2 {
		return nil, ErrNoPublisher
	}
	o, err := m.Store.OpenProposal(ctx, id)
	if err != nil {
		return nil, err
	}
	if o == nil {
		return nil, ErrUnknownProposal
	}
	p, err := o.Parsed()
	if err != nil {
		return nil, err
	}
	now := m.Now().Unix()
	// A new extension, or a retry that was never anchored (no bundle
	// kept), must leave the margin; a retry with a bundle is judged by
	// its time below.
	margin := now >= o.ClosesAt-int64(ExtendMargin/time.Second)
	var kept json.RawMessage
	if o.Pending != nil {
		if kept, err = bs.StoredBundle(ctx, o.Pending.Doc); err != nil {
			return nil, err
		}
		if kept != nil {
			margin = false
		}
	}
	if o.Published || margin {
		return nil, ErrTooLate
	}
	out := in.Outage
	length := out.To - out.From
	allowed := (length + 3599) / 3600 * 3600 // rounded up to the hour
	switch {
	case length <= MinOutage:
		return nil, &ErrInput{errors.New("ballot: an outage must be over an hour")}
	case o.Pending == nil && len(o.Extensions) >= MaxExtensions:
		return nil, &ErrInput{fmt.Errorf("ballot: a vote has at most %d extensions", MaxExtensions)}
	case o.Pending == nil && out.To > now:
		// An outage is extended for once it is over, not for its
		// expected end: the length must be known. A retry of a pending
		// extension was checked when it was stored, and a clock stepping
		// back must not hold it up.
		return nil, &ErrInput{ErrOutageNotOver}
	case out.From < p.OpensAt || out.From >= o.ClosesAt:
		return nil, &ErrInput{errors.New("ballot: the outage isn't within the window")}
	case in.ClosesAt <= o.ClosesAt || in.ClosesAt-o.ClosesAt > allowed:
		return nil, &ErrInput{errors.New("ballot: the new close isn't the outage's length, rounded up to the hour")}
	case in.ClosesAt-p.ClosesAt > vote.MaxExtension:
		return nil, &ErrInput{errors.New("ballot: extensions over 24 h")}
	}
	e := &vote.Extension{V: 1, ProposalID: id, N: int64(len(o.Extensions) + 1), ClosesAt: in.ClosesAt, Outage: out}
	doc, err := vote.EncodeExtension(e)
	if err != nil {
		return nil, &ErrInput{err}
	}
	payload, err := CanonicalExtension(id, in)
	if err != nil {
		return nil, &ErrInput{err}
	}
	if err := checkExtension(&ExtensionPayload{ProposalID: id, ClosesAt: in.ClosesAt, Outage: in.Outage}); err != nil {
		return nil, &ErrInput{err}
	}
	var sig []byte
	if pe := o.Pending; pe != nil {
		// Only the same request, with the same approval, finishes the
		// pending extension; nothing else is accepted while it is
		// pending. The approval's use is repeated, and the approvals
		// accept the repeat of the same use (it may or may not have been
		// recorded before the failure), so it is never used twice.
		if !bytes.Equal(pe.Doc, doc) || pe.ApprovalID != approvalID {
			return nil, ErrExtensionPending
		}
		if err := m.consume(ctx, approvalID, ActionVoteExtend, payload, Use{ProposalID: pe.Use.ProposalID, N: pe.Use.N, Retry: true}); err != nil {
			return nil, err
		}
		doc, sig = pe.Doc, pe.Sig
		if kept != nil {
			if at, err := m.tsaTime(kept, o.Pending.Doc); err != nil {
				return nil, err
			} else if at >= o.ClosesAt {
				return nil, ErrTooLate
			}
		}
	} else {
		msg, _ := vote.DocSigMsg(sum(o.Doc), doc)
		if sig, err = m.Sign(vote.LabelExtended, msg); err != nil {
			return nil, err
		}
		// Stored before the approval is used: a conflict or a failure
		// here uses nothing, and "retry" is honest. If the use then fails,
		// the pending extension is cleared and the approval stays usable.
		use := Use{ProposalID: id, N: e.N}
		o.Pending = &PendingExtension{Doc: doc, Sig: sig, ApprovalID: approvalID, Use: use}
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return nil, err
		}
		if err := m.consume(ctx, approvalID, ActionVoteExtend, payload, use); err != nil {
			o.Pending = nil
			if cerr := m.Store.SaveProposal(ctx, o, false); cerr != nil {
				m.log().Error("pending extension not cleared after a refused approval", "proposal_id", id, "err", cerr.Error())
			}
			return nil, err
		}
	}
	rc, err := ep.PublishExtension(ctx, id, e.N, doc, sig)
	var ref *ErrPublishRefused
	if errors.As(err, &ref) && ref.Status == 422 && ref.Code == "too_late" {
		// The site won't take it: not a failure to retry.
		return nil, ErrTooLate
	}
	if err != nil {
		return nil, fmt.Errorf("ballot: publish extension %d of %s: %w", e.N, id, err)
	}
	bundle := rc.Bundle
	if rc.IndexStale {
		m.log().Warn("site index not updated for the extension; the next close uploads it again", "proposal_id", id, "n", e.N)
	}
	// Each extension is published before the close it extends (§10.2):
	// the bundle's RFC 3161 time decides, not this clock.
	at, err := m.tsaTime(bundle, doc)
	if err != nil {
		return nil, err
	}
	if at >= o.ClosesAt {
		return nil, ErrTooLate
	}
	o.Extensions = append(o.Extensions, vote.Signed{Doc: doc, Sig: sig})
	o.ClosesAt = e.ClosesAt
	o.Pending = nil
	if err := m.Store.SaveProposal(ctx, o, false); err != nil {
		return nil, err
	}
	body, _ := json.Marshal(struct {
		ProposalID   string          `json:"proposal_id"`
		Extension    []byte          `json:"extension"`
		ExtensionSig []byte          `json:"extension_sig"`
		Bundle       json.RawMessage `json:"bundle"`
	}{id, doc, sig, bundle})
	for c := range o.Members {
		if _, err := m.Sender.SendMessage(ctx, c, TypeExtended, body); err != nil {
			m.log().Warn("vote.extended not sent", "proposal_id", id, "connection_id", c, "err", err.Error())
		}
	}
	m.log().Info("vote extended", "proposal_id", id, "n", e.N, "closes_at", e.ClosesAt)
	return e, nil
}

// RebuildAll puts back, for every proposal still running, the ballots the
// write-once copy holds and the table lost (after a restore of the
// table), and returns how many it put back.
func (m *Manager) RebuildAll(ctx context.Context) (int, error) {
	recs, err := m.Store.Records.Load(ctx, KindProposal)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		k, err := m.Store.Rebuild(ctx, r.ID)
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
