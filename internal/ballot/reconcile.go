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

// SiteExtension is an extension as the site holds it. Only its bytes are
// used: any time is read from the bundle this service kept, never from
// the bundle the site served.
type SiteExtension struct {
	Doc    []byte
	Sig    []byte
	Bundle json.RawMessage
}

// SiteReader reads what votes.vettid.org holds of a proposal's
// extensions (vettid/votes docs/VOTES-SITE.md §3).
type SiteReader interface {
	// Extension returns extension n (p/<id>/extension-<n>.json, with
	// .json.sig and .json.sigstore.json), or nil if the site answers 404.
	// A 404 can be a cached one: it finds extensions, and is never proof
	// that one is absent. (A cached 404 of a .sig or .sigstore.json, read
	// as an error since the document is written last, can delay a close
	// by the CDN's error TTL: liveness only.)
	Extension(ctx context.Context, proposalID string, n int64) (*SiteExtension, error)
}

// ErrSiteMismatch is a site and a store that disagree about the
// extensions in a way that can't be resolved: nothing is counted.
var ErrSiteMismatch = errors.New("ballot: the site and the service disagree about the extensions")

// MaxSiteExtensions is how many extensions the site takes (VOTES-SITE §4:
// extensions are numbered at most 24).
const MaxSiteExtensions = 24

// reconcile makes the store's extensions those the site holds, before the
// count.
//
//   - The site's files are read, extension-1, -2, … to the first 404, to
//     find them.
//   - Those the store holds must be the site's, byte for byte.
//   - One the site has beyond them is put in effect (it is the pending
//     one) or adopted only if it verifies: our signature, this proposal,
//     the next number, the 24 h limit, and an RFC 3161 time before the
//     close it extends, read from OUR OWN kept bundle. One with no kept
//     bundle (a restored table) is refused, not adopted.
//   - A pending extension the 404 doesn't show is not thereby absent (the
//     404 may be cached): once the close and the margin have passed, its
//     stored bytes are uploaded again. The site answering 200 or 201 has
//     it, and it is adopted; 422 too_late says it doesn't, and it is
//     dropped; anything else is an error and nothing is dropped. The site
//     skips its time check for a document it already holds, so the probe
//     changes nothing there. Known limit: a 422 with another code
//     (bad_anchor, unknown_service) is an error here, so every close fails
//     with nothing dropped, until the site accepts the document or an
//     operator clears the pending extension (BALLOT-PROTOCOL §10.2).
//   - The last extension is uploaded again to finish the site's index if
//     it missed it (index_updated false), as the answer says.
//
// Anything else that differs is ErrSiteMismatch, logged. o is saved if it
// changed.
func (m *Manager) reconcile(ctx context.Context, sr SiteReader, ep ExtensionPublisher, bs BundleSource, o *OpenProposal) error {
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
		// The store holds one the 404s don't show: not proof of absence
		// either, but nothing is counted on it.
		return fail("the service has %d extensions, the site shows %d", k, len(site))
	}
	for i, s := range o.Extensions {
		if !bytes.Equal(site[i].Doc, s.Doc) || !bytes.Equal(site[i].Sig, s.Sig) {
			return fail("extension %d differs", i+1)
		}
	}
	changed := false
	adopt := func(n int64, doc, sig []byte, bundle json.RawMessage) error {
		if err := m.verifySiteExtension(o, p, o.ClosesAt, n, doc, sig, bundle); err != nil {
			return fail("extension %d: %v", n, err)
		}
		e, _ := vote.ParseExtension(doc)
		o.Extensions = append(o.Extensions, vote.Signed{Doc: doc, Sig: sig})
		o.ClosesAt = e.ClosesAt
		o.Pending = nil
		changed = true
		m.log().Warn("extension taken from the site", "proposal_id", p.ProposalID, "n", n)
		return nil
	}
	for i := k; i < len(site); i++ {
		x := site[i]
		if pe := o.Pending; pe != nil && i == k {
			if !bytes.Equal(pe.Doc, x.Doc) || !bytes.Equal(pe.Sig, x.Sig) {
				return fail("the site's extension %d is not the pending one", i+1)
			}
		}
		own, err := bs.StoredBundle(ctx, x.Doc)
		if err != nil {
			return err
		}
		if own == nil {
			// Sent to the signer, its answer lost: the signer is asked
			// again, and answers with the bundle the site holds for its
			// own claim. That answer is ours; the site's files are not.
			tried, err := attempted(ctx, bs, x.Doc)
			if err != nil {
				return err
			}
			if tried {
				rc, err := ep.PublishExtension(ctx, p.ProposalID, int64(i+1), x.Doc, x.Sig)
				if err != nil {
					return fmt.Errorf("ballot: asking the signer again for extension %d: %w", i+1, err)
				}
				own = rc.Bundle
			}
		}
		if own == nil {
			return fail("extension %d: no bundle of our own for it", i+1)
		}
		if err := adopt(int64(i+1), x.Doc, x.Sig, own); err != nil {
			return err
		}
	}
	if pe := o.Pending; pe != nil && len(site) == k {
		if m.Now().Before(time.Unix(o.ClosesAt, 0).Add(CollectMargin)) {
			return nil // it may still be published
		}
		own, err := bs.StoredBundle(ctx, pe.Doc)
		if err != nil {
			return err
		}
		tried, err := attempted(ctx, bs, pe.Doc)
		if err != nil {
			return err
		}
		drop := own == nil && !tried // never anchored: never reached the site
		if !drop {
			var ref *ErrPublishRefused
			switch rc, err := ep.PublishExtension(ctx, p.ProposalID, int64(k+1), pe.Doc, pe.Sig); {
			case err == nil:
				if own == nil {
					own = rc.Bundle // the signer's answer for its claim
				}
				if err := adopt(int64(k+1), pe.Doc, pe.Sig, own); err != nil {
					return err
				}
			case errors.As(err, &ref) && ref.Status == 422 && ref.Code == "too_late":
				drop = true
			default:
				return fmt.Errorf("ballot: probing the site for extension %d: %w", k+1, err)
			}
		}
		if drop {
			o.Pending = nil
			changed = true
			m.log().Warn("pending extension dropped: the site doesn't take it", "proposal_id", p.ProposalID, "n", k+1)
		}
	}
	if changed {
		if err := m.Store.SaveProposal(ctx, o, false); err != nil {
			return err
		}
	}
	// The site's index may have missed an upload (its answer said so): the
	// same bytes again rerun the update. The answer is the site's own, not
	// the cached index.json. Best effort; the count doesn't depend on it.
	if n := len(o.Extensions); n > 0 {
		last := o.Extensions[n-1]
		if own, err := bs.StoredBundle(ctx, last.Doc); err == nil && own != nil {
			if rc, err := ep.PublishExtension(ctx, p.ProposalID, int64(n), last.Doc, last.Sig); err != nil {
				m.log().Warn("site index not finished", "proposal_id", p.ProposalID, "err", err.Error())
			} else if rc.IndexStale {
				m.log().Warn("site index still not updated for the extension", "proposal_id", p.ProposalID, "n", n)
			}
		}
	}
	return nil
}

// verifySiteExtension checks an extension as number n extending the close
// `closes`, with the bundle this service kept for it.
func (m *Manager) verifySiteExtension(o *OpenProposal, p *vote.Proposal, closes, n int64, doc, sig []byte, own json.RawMessage) error {
	e, err := vote.ParseExtension(doc)
	if err != nil {
		return err
	}
	msg, _ := vote.DocSigMsg(sum(o.Doc), doc)
	switch {
	case vote.Verify(m.IK, vote.LabelExtended, msg, sig) != nil:
		return errors.New("not signed by this service")
	case e.ProposalID != p.ProposalID || e.N != n:
		return errors.New("another proposal or number")
	case e.ClosesAt <= closes || e.ClosesAt-p.ClosesAt > vote.MaxExtension:
		return errors.New("out of order or over 24 h")
	}
	at, err := m.tsaTime(own, doc)
	if err != nil {
		return err
	}
	if at >= closes {
		return errors.New("timestamped after the close it extends")
	}
	return nil
}
