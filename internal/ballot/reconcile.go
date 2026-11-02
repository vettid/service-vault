package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vettid/service-vault/vote"
)

// SiteExtension is an extension as the site holds it.
type SiteExtension struct {
	Doc    []byte
	Sig    []byte
	Bundle json.RawMessage
}

// SiteReader reads what votes.vettid.org holds of a proposal's
// extensions (vettid/votes docs/VOTES-SITE.md §3).
type SiteReader interface {
	// Extension returns extension n (p/<id>/extension-<n>.json, .sig and
	// .sigstore.json), or nil if the site has none.
	Extension(ctx context.Context, proposalID string, n int64) (*SiteExtension, error)
	// ExtensionCount returns the number of extensions the site's index
	// lists for the proposal; found is false if it lists none.
	ExtensionCount(ctx context.Context, proposalID string) (n int, found bool, err error)
}

// ErrSiteMismatch is a site and a store that disagree about the
// extensions in a way that can't be resolved: nothing is counted.
var ErrSiteMismatch = errors.New("ballot: the site and the service disagree about the extensions")

// reconcile makes the store's extensions those the site holds, before the
// count: a pending extension the site has is put in effect; one the site
// has and the store lacks is adopted only if it verifies (our signature,
// this proposal, the next number, within the limits, a log time before
// the close it extends); a pending one the site lacks, once the close it
// would extend has passed, is dropped. Anything else that differs is
// ErrSiteMismatch. The index is finished by publishing the last
// extension's same bytes again if it lags the files. o is saved if it
// changed.
func (m *Manager) reconcile(ctx context.Context, sr SiteReader, ep ExtensionPublisher, o *OpenProposal) error {
	p, err := o.Parsed()
	if err != nil {
		return err
	}
	fail := func(f string, a ...any) error {
		err := fmt.Errorf("%w: "+f, append([]any{ErrSiteMismatch}, a...)...)
		m.log().Error("extensions: site and store disagree", "proposal_id", p.ProposalID, "err", err.Error())
		return err
	}
	var site []*SiteExtension
	for n := int64(1); n <= MaxSiteExtensions; n++ {
		x, err := sr.Extension(ctx, p.ProposalID, n)
		if err != nil {
			return err
		}
		if x == nil {
			break
		}
		site = append(site, x)
	}
	k := len(o.Extensions)
	if len(site) < k {
		return fail("the service has %d extensions, the site %d", k, len(site))
	}
	for i, s := range o.Extensions {
		if !bytes.Equal(site[i].Doc, s.Doc) || !bytes.Equal(site[i].Sig, s.Sig) {
			return fail("extension %d differs", i+1)
		}
	}
	changed := false
	closes := o.ClosesAt
	for i := k; i < len(site); i++ {
		x := site[i]
		if pe := o.Pending; pe != nil && i == k {
			if !bytes.Equal(pe.Doc, x.Doc) || !bytes.Equal(pe.Sig, x.Sig) {
				return fail("the site's extension %d is not the pending one", i+1)
			}
		}
		if err := m.verifySiteExtension(o, p, closes, int64(i+1), x); err != nil {
			return fail("extension %d: %v", i+1, err)
		}
		e, _ := vote.ParseExtension(x.Doc)
		o.Extensions = append(o.Extensions, vote.Signed{Doc: x.Doc, Sig: x.Sig})
		o.ClosesAt, closes = e.ClosesAt, e.ClosesAt
		o.Pending = nil
		changed = true
		m.log().Warn("extension taken from the site", "proposal_id", p.ProposalID, "n", i+1)
	}
	if pe := o.Pending; pe != nil && len(site) == k {
		// Not on the site. Once the close it would extend (and the margin)
		// has passed, the site no longer takes it.
		if m.Now().Before(time.Unix(o.ClosesAt, 0).Add(CollectMargin)) {
			return nil
		}
		o.Pending = nil
		changed = true
		m.log().Warn("pending extension dropped: not on the site and too late", "proposal_id", p.ProposalID, "n", k+1)
	}
	if changed {
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return err
		}
	}
	// The index may lag the files (an upload that wrote the document but
	// not the index): the same bytes again finish it. Best effort; the
	// count doesn't depend on the index. The files, read one by one to the
	// first 404, decide; the index never does.
	if n, found, err := sr.ExtensionCount(ctx, p.ProposalID); err != nil {
		m.log().Warn("site index not read", "proposal_id", p.ProposalID, "err", err.Error())
	} else if found && n > len(site) {
		// The files were read to the first 404 and decide; the index is
		// only a repair target and is not relied on.
		m.log().Warn("site index lists more extensions than the files", "proposal_id", p.ProposalID, "index", n, "files", len(site))
	} else if len(site) > 0 && (!found || n < len(site)) {
		last := site[len(site)-1]
		if _, err := ep.PublishExtension(ctx, p.ProposalID, int64(len(site)), last.Doc, last.Sig); err != nil {
			m.log().Warn("site index not finished", "proposal_id", p.ProposalID, "err", err.Error())
		}
	}
	return nil
}

// MaxSiteExtensions is how many extension files the site can hold.
const MaxSiteExtensions = 24

// verifySiteExtension checks an extension the site holds, as number n
// extending the close `closes`.
func (m *Manager) verifySiteExtension(o *OpenProposal, p *vote.Proposal, closes, n int64, x *SiteExtension) error {
	e, err := vote.ParseExtension(x.Doc)
	if err != nil {
		return err
	}
	msg, _ := vote.DocSigMsg(sum(o.Doc), x.Doc)
	switch {
	case vote.Verify(m.IK, vote.LabelExtended, msg, x.Sig) != nil:
		return errors.New("not signed by this service")
	case e.ProposalID != p.ProposalID || e.N != n:
		return errors.New("another proposal or number")
	case e.ClosesAt <= closes || e.ClosesAt-p.ClosesAt > vote.MaxExtension:
		return errors.New("out of order or over 24 h")
	}
	at, err := IntegratedTime(x.Bundle)
	if err != nil {
		return err
	}
	if at >= closes {
		return errors.New("logged after the close it extends")
	}
	return nil
}
