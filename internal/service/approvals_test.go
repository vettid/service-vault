package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func (f *fixture) withApprovals(threshold int, bootKey string) *approval.Manager {
	st := f.svc.Store.(*peer.MemStore)
	m := &approval.Manager{Peer: f.p, Store: st, Pager: st, Hooks: f.hk.outbox(st, approval.HookKind), ServiceName: f.svc.ServiceName,
		Threshold: threshold, BootstrapKey: bootKey, BoundConnection: f.svc.BoundConnection, Now: f.clk.Now, Log: f.svc.Log}
	f.svc.Approvals = m
	return m
}

// The member whose email is the bootstrap email connects and becomes the
// first admin; an approval reaches their phone as a challenge naming the
// action and its hash; they sign; the approval is approved, and the
// audit log holds a signature that verifies over the challenge.
func TestApprovalEndToEnd(t *testing.T) {
	f := newFixture(t)
	m := f.withApprovals(1, "admin-key")
	ctx := context.Background()
	other, _ := f.connect(f.member(20), "other-key")
	admin, _ := f.connect(f.m, "admin-key")
	// The connection waits for the operator, who confirms the fingerprint
	// of its identity key; then the first tick makes it the admin.
	if a, _ := m.Admins(ctx); len(a.Admins) != 0 {
		t.Fatalf("admin before the confirmation: %v", a.Admins)
	}
	pc, pfp, err := m.BootstrapPending(ctx)
	if err != nil || pc != admin {
		t.Fatalf("pending %q %v", pc, err)
	}
	if err := m.ConfirmBootstrap(ctx, pc, pfp); err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	a, _ := m.Admins(ctx)
	if len(a.Admins) != 1 || a.Admins[0] != admin {
		t.Fatalf("admins %v (other %s)", a.Admins, other)
	}

	payload := `{"proposal":7}`
	c, err := m.Create(ctx, approval.Request{Action: approval.ActionContractTemplateChange, Summary: "Open the vote on proposal 7",
		Payload: json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(f.m.Challenges) != 1 {
		t.Fatalf("%d challenges", len(f.m.Challenges))
	}
	ch := f.m.Challenges[0]
	hash, _ := servicevault.ActionHash(approval.ActionContractTemplateChange, "Open the vote on proposal 7", json.RawMessage(payload))
	if c.ActionHash != hash || ch.Context != "Approve on VettID Member Service: Contract template: Open the vote on proposal 7 — ref "+hash[:16] {
		t.Fatalf("context %q", ch.Context)
	}
	f.sign(f.m, ch, f.m.Cred)
	s, _ := m.Status(ctx, c.ID)
	if s.Status != approval.StatusApproved || len(s.Approvals) != 1 || s.Approvals[0].ConnectionID != admin {
		t.Fatalf("status %+v", s)
	}
	// Not a sign-in: no signin.* webhook.
	if len(f.hk.of(peer.EventSignInApproved)) != 0 {
		t.Fatal("sign-in webhook for an approval")
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.hk.of(approval.EventApproved)) != 1 || len(f.hk.of(approval.EventAdminSetChanged)) != 1 {
		t.Fatal("approval webhooks")
	}
	p, err := m.Audit(ctx, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	var resp *approval.AuditEntry
	for i := range p.Entries {
		if p.Entries[i].Type == approval.AuditResponse {
			resp = &p.Entries[i]
		}
	}
	if resp == nil || resp.Answer != approval.AnswerApproved || resp.Context != ch.Context || resp.RequestID != ch.RequestID {
		t.Fatalf("audit %+v", p.Entries)
	}
	if resp.Purpose != peerwire.PurposeApproval {
		t.Fatalf("audited purpose %q", resp.Purpose)
	}
	if peerwire.VerifyConnAuthResponse(&peerwire.ConnAuthResponse{RequestID: resp.RequestID, Status: peerwire.ConnAuthSigned,
		Key: ed25519.PublicKey(resp.Key), Sig: resp.Signature, Purpose: resp.Purpose}, f.keys.IKPublic(), f.m.IK.Public().(ed25519.PublicKey), ch) != nil {
		t.Fatal("audited signature does not verify")
	}
	if logs := f.logs.String(); strings.Contains(logs, "proposal 7") || strings.Contains(logs, hash[:16]) {
		t.Fatalf("logs carry the context:\n%s", logs)
	}

	// The real peer pinned the governance key at the admin's first sign-in.
	// A later approval signed with another key does not count, the first
	// time (key_changed) and every time after (not_repinned), while an
	// ordinary sign-in with that key still works.
	_, otherKey, _ := ed25519.GenerateKey(nil)
	for i, want := range []string{approval.ReasonKeyChanged, approval.ReasonNotRepinned} {
		d, err := m.Create(ctx, approval.Request{Action: approval.ActionContractTemplateChange, Summary: "Second", Payload: json.RawMessage(`{"n":` + string(rune('1'+i)) + `}`)})
		if err != nil {
			t.Fatal(err)
		}
		f.pump()
		f.sign(f.m, f.m.Challenges[len(f.m.Challenges)-1], otherKey)
		s, _ := m.Status(ctx, d.ID)
		if s.Status != approval.StatusPending || len(s.Approvals) != 1 || s.Approvals[0].Counted || s.Approvals[0].Reason != want {
			t.Fatalf("approval %d with another key: %+v", i, s)
		}
	}

	// The admin removes the connection: the set is empty.
	f.m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	if a, _ := m.Admins(ctx); len(a.Admins) != 0 {
		t.Fatalf("admins %v", a.Admins)
	}
}

// A sign-in still works beside approvals.
func TestSignInWithApprovals(t *testing.T) {
	f := newFixture(t)
	f.withApprovals(1, "")
	f.connect(f.m, "email-key")
	id := f.start("email-key", "", "42")
	f.pump()
	f.sign(f.m, f.m.Challenges[0], f.m.Cred)
	if s := f.status(id); s.Status != "approved" || len(f.hk.of(peer.EventSignInApproved)) != 1 {
		t.Fatalf("%+v", s)
	}
}

// An invitation without an email (the application did not verify it)
// binds nothing and makes no admin, even while a bootstrap applies.
func TestBootstrapNeedsVerifiedInvite(t *testing.T) {
	f := newFixture(t)
	m := f.withApprovals(1, "admin-key")
	conn, d := f.connect(f.m, "")
	if d["email_bound"] != false {
		t.Fatalf("connection.added %v", d)
	}
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a, _ := m.Admins(context.Background()); len(a.Admins) != 0 {
		t.Fatalf("admins %v (connection %s)", a.Admins, conn)
	}
}
