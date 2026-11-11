package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/vettid/service-vault/internal/ballot/ballottest"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/vote"
)

// failSave fails the nth write (from 1) of a proposal record after armed.
type failSave struct {
	*peer.MemStore
	armed bool
	skip  int
}

func (f *failSave) Apply(ctx context.Context, cs []peer.Change) error {
	if f.armed && len(cs) == 1 && cs[0].Kind == KindProposal {
		if f.skip == 0 {
			f.armed = false
			return errors.New("disk full")
		}
		f.skip--
	}
	return f.MemStore.Apply(ctx, cs)
}

type extEnv struct {
	m      *Manager
	pub    *fakePublisher
	ap     *fakeApprovals
	id     string
	in     ProposalInput
	clock  *time.Time
	outage vote.Outage
	base   int // approvals used before the extension
}

func newExtEnv(t *testing.T) *extEnv {
	t.Helper()
	m, _, pub := newManager(t)
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(context.Background(), "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	clock := time.Unix(in.ClosesAt-600, 0)
	m.Now = func() time.Time { return clock }
	ap := m.Approvals.(*fakeApprovals)
	return &extEnv{m: m, pub: pub, ap: ap, base: ap.consumed, id: c.ProposalID, in: in, clock: &clock,
		outage: vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}}
}

func (e *extEnv) req(extra int64) ExtensionInput {
	return ExtensionInput{ClosesAt: e.in.ClosesAt + extra, Outage: e.outage}
}

func (e *extEnv) open(t *testing.T) *OpenProposal {
	t.Helper()
	o, err := e.m.Store.OpenProposal(context.Background(), e.id)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// A crash or a failed save after the publish leaves the extension
// pending; the same request again publishes the same bytes, uses no
// second approval, and finishes.
func TestExtendRetriesPendingByteForByte(t *testing.T) {
	ctx := context.Background()
	for name, setup := range map[string]func(*extEnv) *failSave{
		"lost answer": func(e *extEnv) *failSave { e.pub.failAfter = true; return nil },
		"failed save": func(e *extEnv) *failSave {
			f := &failSave{MemStore: peer.NewMemStore()}
			return f
		},
	} {
		t.Run(name, func(t *testing.T) {
			var e *extEnv
			var fs *failSave
			if name == "failed save" {
				m, _, pub := newManager(t)
				fs = &failSave{MemStore: peer.NewMemStore()}
				m.Store.Records = fs
				m.Catcher = &fakeCatcher{caught: true}
				c, err := m.Create(ctx, "apv", input())
				if err != nil {
					t.Fatal(err)
				}
				in := input()
				clock := time.Unix(in.ClosesAt-600, 0)
				m.Now = func() time.Time { return clock }
				e = &extEnv{m: m, pub: pub, ap: m.Approvals.(*fakeApprovals), base: m.Approvals.(*fakeApprovals).consumed, id: c.ProposalID, in: in, clock: &clock,
					outage: vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}}
				fs.armed, fs.skip = true, 1 // the pending write passes, the one after the publish fails
			} else {
				e = newExtEnv(t)
				setup(e)
			}
			if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
				t.Fatal("the failure was not reported")
			}
			o := e.open(t)
			if o.Pending == nil || len(o.Extensions) != 0 || o.ClosesAt != e.in.ClosesAt {
				t.Fatalf("after the failure: pending %v, %d extensions, closes %d", o.Pending != nil, len(o.Extensions), o.ClosesAt)
			}
			pendingDoc, pendingSig := o.Pending.Doc, o.Pending.Sig
			e.pub.failAfter = false
			if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err != nil {
				t.Fatalf("the retry: %v", err)
			}
			if e.ap.consumed-e.base != 1 {
				t.Fatalf("approval used %d times", e.ap.consumed)
			}
			if len(e.pub.published) != 2 || !bytes.Equal(e.pub.published[0], e.pub.published[1]) || !bytes.Equal(e.pub.published[1], pendingDoc) {
				t.Fatal("the retry did not publish the same bytes")
			}
			o = e.open(t)
			if o.Pending != nil || len(o.Extensions) != 1 || !bytes.Equal(o.Extensions[0].Doc, pendingDoc) ||
				!bytes.Equal(o.Extensions[0].Sig, pendingSig) || o.ClosesAt != e.in.ClosesAt+7200 {
				t.Fatalf("after the retry: %+v", o)
			}
		})
	}
}

// While one is pending, a different extension, or the same one with
// another approval, is refused before an approval is used.
func TestExtendRefusedWhilePending(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	e.pub.failAfter = true
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
		t.Fatal("expected the lost answer")
	}
	for name, f := range map[string]func() error{
		"another extension": func() error { _, err := e.m.Extend(ctx, e.id, "apv", e.req(3600)); return err },
		"another approval":  func() error { _, err := e.m.Extend(ctx, e.id, "apv2", e.req(7200)); return err },
	} {
		if err := f(); !errors.Is(err, ErrExtensionPending) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.ap.consumed-e.base != 1 || len(e.pub.published) != 1 {
		t.Fatalf("approvals used %d, published %d", e.ap.consumed, e.pub.calls)
	}
}

// The RFC 3161 time in our own bundle decides: one timestamped at or after
// the close it extends doesn't apply, however early this clock says it is;
// one timestamped before it does, whatever the Rekor entry's time.
func TestExtendByTimestamp(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	e.pub.tsa = func() int64 { return e.in.ClosesAt + 1 }
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); !errors.Is(err, ErrTooLate) {
		t.Fatalf("timestamped after the close: %v", err)
	}
	if o := e.open(t); len(o.Extensions) != 0 || o.ClosesAt != e.in.ClosesAt {
		t.Fatal("applied")
	}
	// Close doesn't take it up from the site either, and counts nothing.
	*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
	if _, err := e.m.Close(ctx, e.id); !errors.Is(err, ErrSiteMismatch) {
		t.Fatalf("close with a late extension on the site: %v", err)
	}
	if pr, _ := e.m.Results(ctx, e.id); pr != nil {
		t.Fatal("counted")
	}
}

// The timestamp before the close with the Rekor entry after it is accepted.
func TestExtendTimestampBeforeRekorAfter(t *testing.T) {
	e := newExtEnv(t)
	e.pub.tsa = func() int64 { return e.in.ClosesAt - 5 }
	e.pub.integrated = func() int64 { return e.in.ClosesAt + 300 }
	if _, err := e.m.Extend(context.Background(), e.id, "apv", e.req(7200)); err != nil {
		t.Fatalf("TSA before the close, Rekor after: %v", err)
	}
	if o := e.open(t); len(o.Extensions) != 1 {
		t.Fatal("not applied")
	}
}

// A close that runs after an extension was published but not stored takes
// it from the site, waits for the extended close, and counts with it; the
// index, behind the files, is finished.
func TestCloseReconcilesPending(t *testing.T) {
	ctx := context.Background()
	m, _, pub := newManager(t)
	fs := &failSave{MemStore: peer.NewMemStore()}
	m.Store.Records = fs
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	clock := time.Unix(in.ClosesAt-600, 0)
	m.Now = func() time.Time { return clock }
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
	fs.armed, fs.skip = true, 1
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage}); err == nil {
		t.Fatal("expected the failed save")
	}
	clock = time.Unix(in.ClosesAt, 0).Add(2 * CollectMargin)
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrNotClosed) {
		t.Fatalf("before the extended close: %v", err)
	}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	if o.Pending != nil || len(o.Extensions) != 1 || o.ClosesAt != in.ClosesAt+7200 || o.Published {
		t.Fatalf("after reconcile: pending %v, %d extensions, closes %d", o.Pending != nil, len(o.Extensions), o.ClosesAt)
	}
	if len(pub.published) != 2 {
		t.Fatalf("the index was not finished: %d uploads", len(pub.published))
	}
	clock = time.Unix(in.ClosesAt+7200, 0).Add(2 * CollectMargin)
	// Results stamped before the close aren't published: Close says so,
	// and the next one publishes them (BALLOT-PROTOCOL §8.3 step 2).
	pub.stampedEarly = true
	if _, err := m.Close(ctx, c.ProposalID); !errors.Is(err, ErrStampedEarly) {
		t.Fatalf("stamped early: %v", err)
	}
	if pr, _ := m.Results(ctx, c.ProposalID); pr == nil || pr.Bundle != nil {
		t.Fatal("results stamped early were taken as published")
	}
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	// Each upload is checked against the close in force: the extended one.
	if n := len(pub.notBefore); n != 2 || pub.notBefore[0] != in.ClosesAt+7200 || pub.notBefore[1] != in.ClosesAt+7200 {
		t.Fatalf("notBefore %v, want the extended close %d", pub.notBefore, in.ClosesAt+7200)
	}
	pr, _ := m.Results(ctx, c.ProposalID)
	if _, res, err := vote.Check(m.IK, pr.Results, pr.Sig, pr.Rows); err != nil || len(res.Extensions) != 1 {
		t.Fatalf("results: %v", err)
	}
}

// A pending extension the site never got is dropped once the close has
// passed, and the vote is counted without it.
func TestClosePendingNotOnSite(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	e.pub.fail = true
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
		t.Fatal("expected the failure")
	}
	if e.open(t).Pending == nil {
		t.Fatal("not pending")
	}
	e.pub.fail = false
	*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
	if _, err := e.m.Close(ctx, e.id); err != nil {
		t.Fatal(err)
	}
	if o := e.open(t); o.Pending != nil || len(o.Extensions) != 0 {
		t.Fatal("pending kept")
	}
}

// An extension on the site that the store lacks is adopted if it verifies
// and we kept our own bundle for it, and refused (nothing counted)
// otherwise. The bundle the site serves is never believed.
func TestCloseAdoptsOnlyVerifiedSiteExtension(t *testing.T) {
	ctx := context.Background()
	forged := func(at int64) []byte { return ballottest.Bundle(at, at) }
	build := func(e *extEnv, id string, n int64, sign func(string, []byte) ([]byte, error), ownAt int64) *SiteExtension {
		o := e.open(t)
		x := &vote.Extension{V: 1, ProposalID: id, N: n, ClosesAt: e.in.ClosesAt + 7200, Outage: e.outage}
		doc, err := vote.EncodeExtension(x)
		if err != nil {
			t.Fatal(err)
		}
		msg, _ := vote.DocSigMsg(sum(o.Doc), doc)
		sig, err := sign(vote.LabelExtended, msg)
		if err != nil {
			t.Fatal(err)
		}
		if ownAt != 0 {
			e.pub.own = map[string]json.RawMessage{string(doc): ballottest.Bundle(ownAt, ownAt)}
		}
		// The bundle on the site always claims an early time.
		return &SiteExtension{Doc: doc, Sig: sig, Bundle: forged(e.in.ClosesAt - 100)}
	}
	early, late := int64(0), int64(0)
	cases := map[string]struct {
		mutate func(e *extEnv) *SiteExtension
		ok     bool
	}{
		"valid": {func(e *extEnv) *SiteExtension { return build(e, e.id, 1, e.m.Sign, early) }, true},
		"wrong signer": {func(e *extEnv) *SiteExtension {
			e2 := newExtEnv(t)
			return build(e, e.id, 1, func(l string, m []byte) ([]byte, error) { return e2.m.Sign(l, append([]byte{1}, m...)) }, early)
		}, false},
		"wrong number":   {func(e *extEnv) *SiteExtension { return build(e, e.id, 2, e.m.Sign, early) }, false},
		"wrong proposal": {func(e *extEnv) *SiteExtension { return build(e, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1, e.m.Sign, early) }, false},
		"our bundle is late (the site's early bundle is forged)": {func(e *extEnv) *SiteExtension { return build(e, e.id, 1, e.m.Sign, late) }, false},
		"no bundle of our own": {func(e *extEnv) *SiteExtension { return build(e, e.id, 1, e.m.Sign, 0) }, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newExtEnv(t)
			early, late = e.in.ClosesAt-10, e.in.ClosesAt+10
			x := c.mutate(e)
			e.pub.site = map[int64]*SiteExtension{1: x}
			*e.clock = time.Unix(e.in.ClosesAt+7200, 0).Add(2 * CollectMargin)
			_, err := e.m.Close(ctx, e.id)
			if c.ok {
				if err != nil {
					t.Fatalf("a verified extension: %v", err)
				}
				if o := e.open(t); len(o.Extensions) != 1 {
					t.Fatal("not adopted")
				}
				return
			}
			if !errors.Is(err, ErrSiteMismatch) {
				t.Fatalf("an unverified extension: %v", err)
			}
			if pr, _ := e.m.Results(ctx, e.id); pr != nil || len(e.open(t).Extensions) != 0 {
				t.Fatal("counted or adopted")
			}
		})
	}
}

// A pending extension the site doesn't show (its 404 may be cached) is
// probed by uploading its stored bytes: accepted means it is there and is
// adopted, 422 too_late means it isn't and it is dropped, anything else is
// an error and it is kept.
func TestClosePendingProbe(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		refuse  *ErrPublishRefused
		pending bool
		ext     int
		wantErr bool
	}{
		"site has it":     {nil, false, 1, false},
		"too late":        {&ErrPublishRefused{Status: 422, Code: "too_late"}, false, 0, false},
		"another refusal": {&ErrPublishRefused{Status: 409, Code: "differs"}, true, 0, true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newExtEnv(t)
			e.pub.failAfter = true
			if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
				t.Fatal("expected the lost answer")
			}
			e.pub.failAfter = false
			e.pub.site = nil // a cached 404: the files aren't seen
			e.pub.refuse = c.refuse
			*e.clock = time.Unix(e.in.ClosesAt+7200, 0).Add(2 * CollectMargin)
			_, err := e.m.Close(ctx, e.id)
			if (err != nil) != c.wantErr || errors.Is(err, ErrSiteMismatch) {
				t.Fatalf("close: %v", err)
			}
			if o := e.open(t); (o.Pending != nil) != c.pending || len(o.Extensions) != c.ext {
				t.Fatalf("pending %v, %d extensions", o.Pending != nil, len(o.Extensions))
			}
		})
	}
}

// While the site says its index isn't updated, the identical results are
// uploaded again at each close until it is.
func TestCloseRetriesResultsIndex(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	e.pub.resultsStale = true
	*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
	if _, err := e.m.Close(ctx, e.id); err != nil {
		t.Fatal(err)
	}
	if pr, _ := e.m.Results(ctx, e.id); !pr.IndexStale || e.pub.resultsUploads != 1 {
		t.Fatalf("stale %v, uploads %d", pr.IndexStale, e.pub.resultsUploads)
	}
	if _, err := e.m.Close(ctx, e.id); err != nil || e.pub.resultsUploads != 2 {
		t.Fatalf("still stale: %v, uploads %d", err, e.pub.resultsUploads)
	}
	e.pub.resultsStale = false
	if _, err := e.m.Close(ctx, e.id); err != nil || e.pub.resultsUploads != 3 {
		t.Fatalf("index done: %v, uploads %d", err, e.pub.resultsUploads)
	}
	if pr, _ := e.m.Results(ctx, e.id); pr.IndexStale {
		t.Fatal("still marked")
	}
	if _, err := e.m.Close(ctx, e.id); err != nil || e.pub.resultsUploads != 3 {
		t.Fatalf("after: %v, uploads %d", err, e.pub.resultsUploads)
	}
}

// The store holding an extension the site lacks, or another one, is not
// counted.
func TestCloseRefusesDisagreement(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err != nil {
		t.Fatal(err)
	}
	*e.clock = time.Unix(e.in.ClosesAt+7200, 0).Add(2 * CollectMargin)
	saved := e.pub.site
	e.pub.site = nil
	if _, err := e.m.Close(ctx, e.id); !errors.Is(err, ErrSiteMismatch) {
		t.Fatalf("site without the extension: %v", err)
	}
	e.pub.site = map[int64]*SiteExtension{1: {Doc: append([]byte(nil), saved[1].Doc...), Sig: saved[1].Sig[:63], Bundle: saved[1].Bundle}}
	if _, err := e.m.Close(ctx, e.id); !errors.Is(err, ErrSiteMismatch) {
		t.Fatalf("site with another signature: %v", err)
	}
	e.pub.site = saved
	if _, err := e.m.Close(ctx, e.id); err != nil {
		t.Fatalf("agreeing: %v", err)
	}
}

// The pending extension is stored before the approval is used: a failed
// store uses nothing, and a refused approval clears the pending extension
// and leaves the approval usable.
func TestExtendStoresPendingBeforeConsume(t *testing.T) {
	ctx := context.Background()
	m, _, pub := newManager(t)
	fs := &failSave{MemStore: peer.NewMemStore()}
	m.Store.Records = fs
	m.Catcher = &fakeCatcher{caught: true}
	c, err := m.Create(ctx, "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	in := input()
	m.Now = func() time.Time { return time.Unix(in.ClosesAt-600, 0) }
	ap := m.Approvals.(*fakeApprovals)
	base := ap.consumed
	outage := vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}
	req := ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: outage}

	// The store of the pending extension fails (a conflict): nothing used.
	fs.armed = true
	if _, err := m.Extend(ctx, c.ProposalID, "apv", req); err == nil {
		t.Fatal("expected the failed store")
	}
	if ap.consumed != base || len(pub.published) != 0 {
		t.Fatalf("approvals used %d, published %d", ap.consumed-base, len(pub.published))
	}
	// The approval is refused: the pending extension is cleared.
	ap.fail = errors.New("not approved")
	if _, err := m.Extend(ctx, c.ProposalID, "apv", req); err == nil {
		t.Fatal("expected the refused approval")
	}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	if o.Pending != nil || ap.consumed != base || len(pub.published) != 0 {
		t.Fatalf("after the refusal: pending %v, used %d", o.Pending != nil, ap.consumed-base)
	}
	// The same approval, now accepted, works: it was never used.
	ap.fail = nil
	if _, err := m.Extend(ctx, c.ProposalID, "apv", req); err != nil || ap.consumed-base != 1 {
		t.Fatalf("after the refusals: %v, used %d", err, ap.consumed-base)
	}
}

// The site refusing a retry as too late is ErrTooLate, not a failure to
// retry; the pending extension stays for the close to settle.
func TestExtendRefusedTooLateBySite(t *testing.T) {
	e := newExtEnv(t)
	e.pub.refuse = &ErrPublishRefused{Status: 422, Code: "too_late"}
	if _, err := e.m.Extend(context.Background(), e.id, "apv", e.req(7200)); !errors.Is(err, ErrTooLate) {
		t.Fatalf("site's too_late: %v", err)
	}
	if e.open(t).Pending == nil {
		t.Fatal("pending was dropped")
	}
}
