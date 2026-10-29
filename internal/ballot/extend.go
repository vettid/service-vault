package ballot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/service-vault/vote"
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

// ErrTooLate is an extension asked for once the close it would extend has
// passed.
var ErrTooLate = errors.New("ballot: the close to extend has passed")

// Extend publishes an extension and sends vote.extended to every eligible
// member.
func (m *Manager) Extend(ctx context.Context, id string, in ExtensionInput) (*vote.Extension, error) {
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
	if o.Published || m.Now().Unix() >= o.ClosesAt {
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
	msg, _ := vote.DocSigMsg(sum(o.Doc), doc)
	sig, err := m.Sign(vote.LabelExtended, msg)
	if err != nil {
		return nil, err
	}
	bundle, err := ep.PublishExtension(ctx, id, e.N, doc, sig)
	if err != nil {
		return nil, fmt.Errorf("ballot: publish extension %d of %s: %w", e.N, id, err)
	}
	o.Extensions = append(o.Extensions, vote.Signed{Doc: doc, Sig: sig})
	o.ClosesAt = e.ClosesAt
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
