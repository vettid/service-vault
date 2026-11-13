package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/ballot/ballottest"
)

// A proposal whose bundle a member vault would refuse is not sent to
// anyone, and raises proposal_bundle_unverified; once the bundle checks
// (the roots updated, or anchored again), Publish sends it.
func TestPublishChecksBundle(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	m, s, _ := newManager(t)
	m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	m.CheckBundle = func([]byte, json.RawMessage) error { return errors.New("not under the pinned roots") }
	c, err := m.Create(ctx, "apv", input())
	if !errors.Is(err, ErrBundleUnverified) || c == nil {
		t.Fatalf("created with a refused bundle: %v", err)
	}
	m.Wait()
	if len(s.sent) != 0 {
		t.Fatalf("sent %d with a refused bundle", len(s.sent))
	}
	if !strings.Contains(logs.String(), `"alarm":"proposal_bundle_unverified"`) {
		t.Fatalf("no alarm:\n%s", logs.String())
	}
	m.CheckBundle = ballottest.Check
	n, err := m.Publish(ctx, c.ProposalID)
	m.Wait()
	if err != nil || n != 3 || len(s.sent) != 3 {
		t.Fatalf("Publish: sending %d, sent %d, %v", n, len(s.sent), err)
	}
}

// Without a check, nothing is sent (fail closed).
func TestPublishWithoutCheckSendsNothing(t *testing.T) {
	ctx := context.Background()
	m, s, _ := newManager(t)
	m.CheckBundle = nil
	if _, err := m.Create(ctx, "apv", input()); !errors.Is(err, ErrBundleUnverified) {
		t.Fatalf("created without a check: %v", err)
	}
	m.Wait()
	if len(s.sent) != 0 {
		t.Fatalf("sent %d without a check", len(s.sent))
	}
}

// An extension whose bundle a member vault would refuse is published and
// in effect (the site holds it), but not sent; the alarm is raised.
func TestExtensionChecksBundle(t *testing.T) {
	ctx := context.Background()
	var logs bytes.Buffer
	m, s, a, pid, x := extendFixture(t)
	m.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	approveExtension(t, a, "a", pid, x)
	m.CheckBundle = func([]byte, json.RawMessage) error { return errors.New("not under the pinned roots") }
	if _, err := m.Extend(ctx, pid, "a", x); err != nil {
		t.Fatal(err)
	}
	m.Wait()
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
