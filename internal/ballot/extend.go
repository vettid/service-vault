package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/vote"
	"strconv"
	"time"
)

// Extensions (BALLOT-PROTOCOL §10.2): a relay outage of more than an hour
// within the window extends the close by the outage, rounded up to the
// hour, by extensions totalling at most 24 h, each published before the
// close it extends.

// ExtensionPublisher anchors and publishes an extension (§3.3), and
// returns its Sigstore bundle.
type ExtensionPublisher interface {
	PublishExtension(ctx context.Context, proposalID string, n int64, doc, sig []byte) (json.RawMessage, error)
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

// ErrTooLate is an extension asked for once the close it would extend has
// passed, or one whose Rekor time is not before that close.
var ErrTooLate = errors.New("ballot: the close to extend has passed")

// ErrExtensionPending is a new extension asked for while another is signed
// and stored but not yet in effect: it is finished (the same request
// again) or settled by Close first.
var ErrExtensionPending = errors.New("ballot: another extension is pending")

// IntegratedTime returns the time (Unix seconds) at which the transparency
// log integrated the bundle's single entry: the time that decides whether
// an extension came before the close it extends. It fails closed on a
// bundle without exactly one entry carrying a time.
func IntegratedTime(bundle json.RawMessage) (int64, error) {
	var b struct {
		VerificationMaterial struct {
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || len(b.VerificationMaterial.TlogEntries) != 1 {
		return 0, errors.New("ballot: the bundle has no single log entry")
	}
	t, err := strconv.ParseInt(b.VerificationMaterial.TlogEntries[0].IntegratedTime, 10, 64)
	if err != nil || t <= 0 {
		return 0, errors.New("ballot: the bundle's log time is unreadable")
	}
	return t, nil
}

// Extend publishes an extension and sends vote.extended to every eligible
// member.
//
// It needs the admins' approval (a vote.extend approval) of exactly this
// extension of this proposal, in its canonical form (CanonicalExtension).
// The order is: refusals, use the approval, store the signed extension as
// pending (conditional on the record's version), publish it, mark it in
// effect. The site's copy is write-once, so what is published must be
// stored first: a failure after the publish leaves the pending extension,
// and the same request again (with the same approval, which is not used
// again) publishes the same bytes and finishes. A failure between the use
// and the store leaves the approval used (the admins approve again).
//
// Whether the extension is in effect is decided by the log time in its
// bundle: before the close it extends, or it does not apply (ErrTooLate).
func (m *Manager) Extend(ctx context.Context, id, approvalID string, in ExtensionInput) (*vote.Extension, error) {
	unlock, err := m.lock(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	ep, ok := m.Publisher.(ExtensionPublisher)
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
	p, err := o.Parsed()
	if err != nil {
		return nil, err
	}
	now := m.Now().Unix()
	// A retry of a pending extension may run up to the close; a new one
	// must leave the margin.
	if o.Published || now >= o.ClosesAt || o.Pending == nil && now >= o.ClosesAt-int64(ExtendMargin/time.Second) {
		return nil, ErrTooLate
	}
	out := in.Outage
	length := out.To - out.From
	allowed := (length + 3599) / 3600 * 3600 // rounded up to the hour
	switch {
	case length <= MinOutage:
		return nil, &ErrInput{errors.New("ballot: an outage must be over an hour")}
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
		// Only the same request, with the approval already used for it,
		// finishes the pending extension; nothing else is accepted while
		// it is pending.
		if !bytes.Equal(pe.Doc, doc) || pe.ApprovalID != approvalID {
			return nil, ErrExtensionPending
		}
		doc, sig = pe.Doc, pe.Sig
	} else {
		msg, _ := vote.DocSigMsg(sum(o.Doc), doc)
		if sig, err = m.Sign(vote.LabelExtended, msg); err != nil {
			return nil, err
		}
		use := Use{ProposalID: id, N: e.N}
		if err := m.consume(ctx, approvalID, ActionVoteExtend, payload, use); err != nil {
			return nil, err
		}
		o.Pending = &PendingExtension{Doc: doc, Sig: sig, ApprovalID: approvalID, Use: use}
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return nil, err
		}
	}
	bundle, err := ep.PublishExtension(ctx, id, e.N, doc, sig)
	if err != nil {
		return nil, fmt.Errorf("ballot: publish extension %d of %s: %w", e.N, id, err)
	}
	// Each extension is published before the close it extends (§10.2):
	// the log's time for it decides, not this clock.
	at, err := IntegratedTime(bundle)
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
