package ballot

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot/ballottest"
)

// signerPublisher is the fake publisher with the anchor signer's
// AttemptSource: documents sent to the signer, whose answer may be lost.
type signerPublisher struct {
	*fakePublisher
	tried map[string]bool
}

func (s *signerPublisher) Attempted(_ context.Context, doc []byte) (bool, error) {
	return s.tried[string(doc)] || s.own[string(doc)] != nil, nil
}

// With the signer, a pending extension whose answer was lost has no
// bundle here, but the signer may have signed and published it: it is
// asked again, never dropped as never anchored. Without the signer's
// record, the same state is dropped, as before.
func TestClosePendingSentToSigner(t *testing.T) {
	ctx := context.Background()
	for _, viaSigner := range []bool{true, false} {
		e := newExtEnv(t)
		sp := &signerPublisher{fakePublisher: e.pub, tried: map[string]bool{}}
		if viaSigner {
			e.m.Publisher = sp
		}
		e.pub.fail = true // the call fails: no bundle comes back
		if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
			t.Fatal("expected the failure")
		}
		o := e.open(t)
		if o.Pending == nil {
			t.Fatal("not pending")
		}
		sp.tried[string(o.Pending.Doc)] = true // the signer got it
		e.pub.fail = false
		// The signer signed it then, before the close: asked again, it
		// answers with that bundle.
		signedAt := e.in.ClosesAt - 600
		e.pub.integrated = func() int64 { return signedAt }
		*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
		calls := e.pub.calls
		_, _ = e.m.Close(ctx, e.id)
		o = e.open(t)
		if viaSigner {
			if e.pub.calls == calls || o.Pending != nil || len(o.Extensions) != 1 {
				t.Fatalf("signer: asked again %v, pending %v, %d extensions", e.pub.calls != calls, o.Pending != nil, len(o.Extensions))
			}
			continue
		}
		if o.Pending != nil || len(o.Extensions) != 0 {
			t.Fatalf("no signer: pending %v, %d extensions", o.Pending != nil, len(o.Extensions))
		}
	}
}

// An extension on the site that this service has no bundle for, but sent
// to the signer, takes the signer's answer as its own (it is asked
// again), and is adopted if it verifies; the site's own bundle file is
// still never believed.
func TestCloseSiteExtensionSentToSigner(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	sp := &signerPublisher{fakePublisher: e.pub, tried: map[string]bool{}}
	e.m.Publisher = sp
	e.pub.failAfter = true // the signer published it; the answer was lost
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
		t.Fatal("expected the lost answer")
	}
	o := e.open(t)
	doc := o.Pending.Doc
	sp.tried[string(doc)] = true
	delete(e.pub.own, string(doc)) // nothing kept here
	e.pub.failAfter = false
	signedAt := e.in.ClosesAt - 600 // the signer's bundle, from before the close
	e.pub.integrated = func() int64 { return signedAt }
	if e.pub.site[1] == nil {
		t.Fatal("the site doesn't hold it")
	}
	*e.clock = time.Unix(e.in.ClosesAt+7200, 0).Add(2 * CollectMargin)
	if _, err := e.m.Close(ctx, e.id); err != nil {
		t.Fatal(err)
	}
	if o := e.open(t); len(o.Extensions) != 1 || o.Pending != nil {
		t.Fatalf("%d extensions, pending %v", len(o.Extensions), o.Pending != nil)
	}
}

// answerPublisher answers every extension with its own bundle: the one
// the signer returns, which the site holds.
type answerPublisher struct {
	*signerPublisher
	answer json.RawMessage
}

func (a *answerPublisher) PublishExtension(context.Context, string, int64, []byte, []byte) (Receipt, error) {
	a.calls++
	return Receipt{Bundle: a.answer}, nil
}

// A pending extension asked again at the close takes the signer's bundle
// over one kept here earlier: the signer's is what the site holds.
func TestClosePendingPrefersSignerBundle(t *testing.T) {
	ctx := context.Background()
	e := newExtEnv(t)
	sp := &signerPublisher{fakePublisher: e.pub, tried: map[string]bool{}}
	e.pub.fail = true
	if _, err := e.m.Extend(ctx, e.id, "apv", e.req(7200)); err == nil {
		t.Fatal("expected the failure")
	}
	o := e.open(t)
	if o.Pending == nil {
		t.Fatal("not pending")
	}
	if e.pub.own == nil {
		e.pub.own = map[string]json.RawMessage{}
	}
	late := e.in.ClosesAt + 600 // kept here, but not in time
	e.pub.own[string(o.Pending.Doc)] = ballottest.Bundle(late, late)
	signedAt := e.in.ClosesAt - 600
	e.m.Publisher = &answerPublisher{signerPublisher: sp, answer: ballottest.Bundle(signedAt, signedAt)}
	*e.clock = time.Unix(e.in.ClosesAt, 0).Add(2 * CollectMargin)
	_, _ = e.m.Close(ctx, e.id)
	if o := e.open(t); o.Pending != nil || len(o.Extensions) != 1 {
		t.Fatalf("pending %v, %d extensions", o.Pending != nil, len(o.Extensions))
	}
}
