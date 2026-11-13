package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot/ballottest"
)

func refuseBundle([]byte, json.RawMessage, time.Time) error {
	return errors.New("not under the pinned roots")
}

// A proposal whose bundle a member vault would refuse is not sent to
// anyone, and raises proposal_bundle_unverified; once the bundle checks
// (the pinned roots updated in a new build), Publish sends it.
func TestPublishChecksBundle(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	m, s, _ := newManager(t)
	m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	var gotNotAfter []time.Time
	m.CheckBundle = func(doc []byte, b json.RawMessage, notAfter time.Time) error {
		gotNotAfter = append(gotNotAfter, notAfter)
		return refuseBundle(doc, b, notAfter)
	}
	c, err := m.Create(ctx, "apv", input())
	var np *ErrNotPublished
	if !errors.Is(err, ErrBundleUnverified) || !errors.As(err, &np) || c == nil {
		t.Fatalf("created with a refused bundle: %v", err)
	}
	if len(gotNotAfter) != 1 || !gotNotAfter[0].IsZero() {
		t.Fatalf("a proposal is checked with the clock's limit (zero notAfter): %v", gotNotAfter)
	}
	m.Wait()
	if len(s.sent) != 0 {
		t.Fatalf("sent %d with a refused bundle", len(s.sent))
	}
	if !strings.Contains(logs.String(), `"alarm":"proposal_bundle_unverified"`) {
		t.Fatalf("no alarm:\n%s", logs.String())
	}
	if _, err := m.Publish(ctx, c.ProposalID); !errors.Is(err, ErrBundleUnverified) {
		t.Fatalf("Publish with a refused bundle: %v", err)
	}
	m.CheckBundle = ballottest.Check
	n, err := m.Publish(ctx, c.ProposalID)
	m.Wait()
	if err != nil || n != 3 || len(s.sent) != 3 {
		t.Fatalf("Publish: sending %d, sent %d, %v", n, len(s.sent), err)
	}
}

// Without a check, Create refuses before the approval is used or anything
// is published, and nothing is sent (fail closed).
func TestCreateWithoutCheckRefusesEarly(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	m, s, p := newManager(t)
	m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	m.CheckBundle = nil
	c, err := m.Create(ctx, "apv", input())
	if !errors.Is(err, ErrNoBundleCheck) || !errors.Is(err, ErrBundleUnverified) || c != nil {
		t.Fatalf("created without a check: %v %v", c, err)
	}
	if a := m.Approvals.(*fakeApprovals); a.consumed != 0 {
		t.Fatalf("the approval was used (%d) though nothing could be sent", a.consumed)
	}
	if p.calls != 0 {
		t.Fatalf("published (%d calls) without a check", p.calls)
	}
	m.Wait()
	if len(s.sent) != 0 {
		t.Fatalf("sent %d without a check", len(s.sent))
	}
	if !strings.Contains(logs.String(), `"alarm":"proposal_bundle_unverified"`) {
		t.Fatalf("no alarm:\n%s", logs.String())
	}
}

// An extension whose bundle a member vault would refuse is published and
// in effect (the site holds it), but not sent; the alarm is raised. It is
// checked against the close it extends, as a vault does.
func TestExtensionChecksBundle(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	m, s, a, pid, x := extendFixture(t)
	m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	approveExtension(t, a, "a", pid, x)
	o, err := m.Store.OpenProposal(ctx, pid)
	if err != nil {
		t.Fatal(err)
	}
	prevClose := o.ClosesAt
	var gotNotAfter time.Time
	m.CheckBundle = func(doc []byte, b json.RawMessage, notAfter time.Time) error {
		gotNotAfter = notAfter
		return refuseBundle(doc, b, notAfter)
	}
	if _, err := m.Extend(ctx, pid, "a", x); err != nil {
		t.Fatal(err)
	}
	m.Wait()
	if !gotNotAfter.Equal(time.Unix(prevClose-1, 0)) {
		t.Fatalf("notAfter %v, want the extended close %d minus 1 s", gotNotAfter, prevClose)
	}
	if extended(t, m, pid) != 1 {
		t.Fatal("the extension is not in effect")
	}
	for _, x := range s.sent {
		if x.typ == TypeExtended {
			t.Fatal("vote.extended sent with a refused bundle")
		}
	}
	if !strings.Contains(logs.String(), `"alarm":"proposal_bundle_unverified"`) {
		t.Fatalf("no alarm:\n%s", logs.String())
	}
}
