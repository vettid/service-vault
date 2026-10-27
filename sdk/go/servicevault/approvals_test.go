package servicevault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	iwebhook "github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// The approval calls against the real API and service (fake peer): the
// member with the bootstrap email connects and is the first admin; an
// approval is created, checked against the locally computed hash,
// approved by the admin's answer and reported; the webhooks decode.
func TestApprovalsAgainstAPI(t *testing.T) {
	secret := []byte(randomHex(t, 32))
	got := &received{}
	rc := &servicevault.Receiver{Secret: secret, Replay: &servicevault.MemoryReplayCache{}}
	srv := httptest.NewServer(rc.Handler(got.handle))
	defer srv.Close()
	f := newFixture(t, &iwebhook.Dispatcher{URL: srv.URL, Secret: secret})
	c := f.client(t)
	ctx := context.Background()

	if _, err := c.CreateApproval(ctx, servicevault.ApprovalRequest{Action: servicevault.ActionVoteOpen, Summary: "Open",
		Payload: json.RawMessage(`{}`)}); apiCode(err) != servicevault.CodeUnreachable {
		t.Fatalf("no admins: %v", err)
	}
	f.deliver(t, peer.Event{ID: "01JEVENTA", Type: peer.EventConnectionAdded, ConnectionID: "c1", Tag: f.emailKey})
	if err := f.tick(ctx); err != nil {
		t.Fatal(err)
	}
	a, err := c.Admins(ctx)
	if err != nil || len(a.Admins) != 1 || a.Admins[0] != "c1" || a.Threshold != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	if ev, ok := got.last().(*servicevault.AdminSetChanged); !ok || ev.Added != "c1" || ev.Reason != servicevault.AdminSetBootstrap ||
		ev.ConnectionID != "c1" || len(ev.Admins) != 1 {
		t.Fatalf("event %#v", got.last())
	}

	req := servicevault.ApprovalRequest{Action: servicevault.ActionProposalCreate, Summary: "Create proposal 7",
		Payload: json.RawMessage(`{ "title": "Bylaws", "id": 7 }`)}
	cr, err := c.CreateApproval(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := servicevault.ActionHash(req.Action, req.Summary, req.Payload)
	if cr.ActionHash != want || cr.Status != servicevault.ApprovalStatusPending || cr.ExpiresAt.IsZero() {
		t.Fatalf("%+v, want hash %s", cr, want)
	}
	if _, err := c.RemindApproval(ctx, cr.ID); apiCode(err) != servicevault.CodeTooSoon {
		t.Fatalf("remind: %v", err)
	}
	ap, err := c.Approval(ctx, cr.ID)
	if err != nil || ap.Status != servicevault.ApprovalStatusPending || len(ap.Admins) != 1 || ap.Threshold != 1 {
		t.Fatalf("%+v %v", ap, err)
	}
	// The admin approves: the fake peer numbered the challenge req1.
	f.deliver(t, peer.Event{ID: "01JEVENTB", Type: peer.EventSignInApproved, ConnectionID: "c1", RequestID: "req1",
		Context: "ctx", Key: make([]byte, 32), Signature: make([]byte, 64), SignedAt: time.Now()})
	if err := f.tick(ctx); err != nil {
		t.Fatal(err)
	}
	ap, err = c.Approval(ctx, cr.ID)
	if err != nil || ap.Status != servicevault.ApprovalStatusApproved || len(ap.Approvals) != 1 || ap.Approvals[0].ConnectionID != "c1" {
		t.Fatalf("%+v %v", ap, err)
	}
	if ev, ok := got.last().(*servicevault.ApprovalApproved); !ok || ev.ApprovalID != cr.ID || ev.ActionHash != want ||
		ev.Action != servicevault.ActionProposalCreate || ev.Applied != nil {
		t.Fatalf("event %#v", got.last())
	}
	if _, err := c.RemindApproval(ctx, cr.ID); apiCode(err) != servicevault.CodeNotPending {
		t.Fatalf("remind: %v", err)
	}
	if _, err := c.Approval(ctx, "nope"); !servicevault.IsNotFound(err) {
		t.Fatalf("%v", err)
	}

	// The audit log, two entries a page.
	var all []servicevault.AuditEntry
	since := ""
	for {
		p, err := c.Audit(ctx, since, 2)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, p.Entries...)
		if p.Next == "" {
			break
		}
		since = p.Next
	}
	var types []string
	for _, e := range all {
		types = append(types, e.Type)
	}
	if len(all) != 4 || all[1].Type != "approval.requested" || all[2].Answer != "approved" || len(all[2].Signature) != 64 ||
		string(all[1].Payload) != `{"id":7,"title":"Bylaws"}` {
		t.Fatalf("audit %v", types)
	}

	// An open approval, then the admin's connection is removed: the set is
	// empty and the approval can no longer be approved.
	cr2, err := c.CreateApproval(ctx, servicevault.ApprovalRequest{Action: servicevault.ActionVoteClose, Summary: "Close",
		Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	f.deliver(t, peer.Event{ID: "01JEVENTC", Type: peer.EventConnectionRemoved, ConnectionID: "c1", Direction: "in",
		Tag: f.emailKey})
	if err := f.tick(ctx); err != nil {
		t.Fatal(err)
	}
	var changed *servicevault.AdminSetChanged
	var denied *servicevault.ApprovalDenied
	got.mu.Lock()
	for _, e := range got.evs {
		switch e := e.(type) {
		case *servicevault.AdminSetChanged:
			changed = e
		case *servicevault.ApprovalDenied:
			denied = e
		}
	}
	got.mu.Unlock()
	if changed == nil || changed.Removed != "c1" || changed.Reason != servicevault.AdminSetConnectionRemoved || len(changed.Admins) != 0 {
		t.Fatalf("admin set %#v", changed)
	}
	if denied == nil || denied.ApprovalID != cr2.ID || denied.Reason != "admins_removed" {
		t.Fatalf("denied %#v", denied)
	}
}

func apiCode(err error) string {
	var ae *servicevault.APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}
