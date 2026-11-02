package ballot

import (
	"bytes"
	"context"
	"errors"
	"strconv"
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

// The log's time decides: an extension integrated at or after the close
// it extends doesn't apply, however early this clock says it is.
func TestExtendByLogTime(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	e.pub.integrated = func() int64 { return e.in.ClosesAt + 1 }
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); !errors.Is(err, ErrTooLate) {
		t.Fatalf("logged after the close: %v", err)
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
	zero := 0
	pub.indexed = &zero
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
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
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

// An extension on the site that the store lacks is adopted if it
// verifies, and refused (nothing counted) if it doesn't.
func TestCloseAdoptsOnlyVerifiedSiteExtension(t *testing.T) {
	ctx := context.Background()
	other := func(e *extEnv) func(string, []byte) ([]byte, error) { return nil }
	_ = other
	build := func(e *extEnv, id string, n int64, sign func(string, []byte) ([]byte, error), at int64) *SiteExtension {
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
		return &SiteExtension{Doc: doc, Sig: sig, Bundle: []byte(`{"verificationMaterial":{"tlogEntries":[{"integratedTime":"` + strconv.FormatInt(at, 10) + `"}]}}`)}
	}
	cases := map[string]struct {
		mutate func(e *extEnv) *SiteExtension
		ok     bool
	}{
		"valid": {func(e *extEnv) *SiteExtension { return build(e, e.id, 1, e.m.Sign, e.in.ClosesAt-10) }, true},
		"wrong signer": {func(e *extEnv) *SiteExtension {
			e2 := newExtEnv(t)
			return build(e, e.id, 1, func(l string, m []byte) ([]byte, error) {
				s, err := e2.m.Sign(l, append([]byte{1}, m...))
				return s, err
			}, e.in.ClosesAt-10)
		}, false},
		"wrong number": {func(e *extEnv) *SiteExtension { return build(e, e.id, 2, e.m.Sign, e.in.ClosesAt-10) }, false},
		"wrong proposal": {func(e *extEnv) *SiteExtension {
			return build(e, "01ARZ3NDEKTSV4RRFFQ69G5FAV", 1, e.m.Sign, e.in.ClosesAt-10)
		}, false},
		"logged late": {func(e *extEnv) *SiteExtension { return build(e, e.id, 1, e.m.Sign, e.in.ClosesAt) }, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newExtEnv(t)
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
