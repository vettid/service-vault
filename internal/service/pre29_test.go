package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// The webhooks for a connection or a claim ended at a start carry the
// reason (RELEASE-29 §11): connection.removed and connection.expired with
// reason pre29 or ended_all; without one, no reason member.
func TestWebhookEndReason(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, e := range []*peer.Event{
		{ID: "01M00000000000000000000001", Type: peer.EventConnectionRemoved, ConnectionID: "c-pre29", Direction: "out", Reason: peer.RemovedPre29},
		{ID: "01M00000000000000000000002", Type: peer.EventConnectionRemoved, ConnectionID: "c-plain", Direction: "out"},
		{ID: "01M00000000000000000000003", Type: peer.EventConnectionExpired, ConnectionID: "r-all", InviteID: "i-all", Reason: peer.RemovedEndAll},
	} {
		if err := f.svc.Deliver(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	reason := func(typ, conn string) (string, bool) {
		for _, e := range f.hk.of(typ) {
			if e.ConnectionID != conn {
				continue
			}
			var d map[string]string
			if err := json.Unmarshal(e.Data, &d); err != nil {
				t.Fatal(err)
			}
			r, ok := d["reason"]
			return r, ok
		}
		t.Fatalf("no %s webhook for %s", typ, conn)
		return "", false
	}
	if r, _ := reason(peer.EventConnectionRemoved, "c-pre29"); r != "pre29" {
		t.Fatalf("pre29: %q", r)
	}
	if _, ok := reason(peer.EventConnectionRemoved, "c-plain"); ok {
		t.Fatal("a reason on a plain removal")
	}
	if r, _ := reason(peer.EventConnectionExpired, "r-all"); r != "ended_all" {
		t.Fatalf("ended_all: %q", r)
	}
}
