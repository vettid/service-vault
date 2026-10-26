//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/webhook"
)

// approvalPeer is a fake peer: c1..c3 are active; challenges are numbered.
type approvalPeer struct {
	mu   sync.Mutex
	n    int
	last map[string]string // connection -> its last request id
}

func (p *approvalPeer) Connection(id string) (peer.ConnectionInfo, bool) {
	return peer.ConnectionInfo{ID: id, State: peer.StateActive}, id == "c1" || id == "c2" || id == "c3"
}

func (p *approvalPeer) Authenticate(_ context.Context, conn, _ string, _ time.Duration) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	if p.last == nil {
		p.last = map[string]string{}
	}
	p.last[conn] = fmt.Sprintf("req%03d", p.n)
	return p.last[conn], nil
}

func (p *approvalPeer) CancelChallenge(context.Context, string) (bool, error) { return true, nil }

// Approvals on DynamoDB: the admin set, approvals and the webhook outbox
// survive a restart (a new Manager on the same table); answers are
// handled once; the audit log is append-only and reads back in order,
// page by page, through a Query.
func TestApprovalsOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	p := &approvalPeer{}
	hooks := &hookList{}
	bound := map[string]string{"boot-key": "c1"}
	newManager := func() *approval.Manager {
		return &approval.Manager{Peer: p, Store: tbl.Peer(), Pager: tbl, Webhooks: hooks, ServiceName: "VettID Member Service",
			Threshold: 2, BootstrapKey: "boot-key", BoundConnection: func(_ context.Context, k string) (string, bool, error) {
				c, ok := bound[k]
				return c, ok, nil
			}}
	}
	m := newManager()
	if err := m.Tick(ctx); err != nil { // c1 is bound and active: the first admin
		t.Fatal(err)
	}
	answer := func(m *approval.Manager, id, conn string) {
		t.Helper()
		e := &peer.Event{ID: id, Type: peer.EventSignInApproved, ConnectionID: conn, RequestID: p.last[conn],
			Key: make([]byte, 32), Signature: make([]byte, 64), SignedAt: time.Now(), At: time.Now()}
		if ok, err := m.Answer(ctx, e); err != nil || !ok {
			t.Fatalf("answer %v %v", ok, err)
		}
	}
	// Threshold 2 with one admin: unreachable. Lower it to add c2 and c3.
	if _, err := m.Create(ctx, approval.Request{Action: approval.ActionVoteOpen, Summary: "x", Payload: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("m > n accepted")
	}
	m.Threshold = 1
	for i, c := range []string{"c2", "c3"} {
		cr, err := m.Create(ctx, approval.Request{Action: approval.ActionAdminSetAdd, Summary: "Add " + c,
			Payload: json.RawMessage(`{"connection_id":"` + c + `"}`)})
		if err != nil {
			t.Fatal(err)
		}
		answer(m, fmt.Sprint("ev-add-", i), "c1")
		if s, _ := m.Status(ctx, cr.ID); s.Status != approval.StatusApproved || !*s.Applied {
			t.Fatalf("%+v", s)
		}
	}

	// Restart with m = 2: one approval, then the answers.
	m = newManager()
	if a, err := m.Admins(ctx); err != nil || len(a.Admins) != 3 {
		t.Fatalf("admins after restart %+v %v", a, err)
	}
	cr, err := m.Create(ctx, approval.Request{Action: approval.ActionProposalCreate, Summary: "Create proposal 7",
		Payload: json.RawMessage(`{"id":7}`)})
	if err != nil {
		t.Fatal(err)
	}
	answer(m, "ev-1", "c1")
	answer(m, "ev-1", "c1") // redelivered
	m = newManager()        // restart between answers
	if s, err := m.Status(ctx, cr.ID); err != nil || s.Status != approval.StatusPending || len(s.Approvals) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	answer(m, "ev-2", "c3")
	if s, _ := m.Status(ctx, cr.ID); s.Status != approval.StatusApproved || len(s.Approvals) != 2 {
		t.Fatalf("%+v", s)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, e := range hooks.all() {
		counts[e.Type]++
	}
	if counts[approval.EventApproved] != 3 || counts[approval.EventAdminSetChanged] != 3 {
		t.Fatalf("webhooks %v", counts)
	}
	if err := m.Tick(ctx); err != nil || len(hooks.all()) != 6 {
		t.Fatalf("redelivered webhooks: %d %v", len(hooks.all()), err)
	}

	// The audit log, page by page, in order: each answer once.
	var all []approval.AuditEntry
	since := ""
	for {
		pg, err := m.Audit(ctx, since, 4)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, pg.Entries...)
		if pg.Next == "" {
			break
		}
		since = pg.Next
	}
	responses := 0
	for i, e := range all {
		if i > 0 && e.ID <= all[i-1].ID {
			t.Fatalf("out of order at %d", i)
		}
		if e.Type == approval.AuditResponse {
			responses++
			if len(e.Signature) != 64 || e.SignedAt == nil {
				t.Fatalf("evidence %+v", e)
			}
		}
	}
	// bootstrap; 2 × (requested, response, admin_set.changed, approved); requested, 2 responses, approved
	if len(all) != 1+8+4 || responses != 4 {
		t.Fatalf("%d entries, %d responses", len(all), responses)
	}
	// Append-only: an entry cannot be written again.
	if err := tbl.Peer().Apply(ctx, []peer.Change{{Kind: approval.KindAudit, ID: all[0].ID, Data: []byte("{}"), IfAbsent: true}}); err != peer.ErrConflict {
		t.Fatalf("overwrite: %v", err)
	}
}

func (h *hookList) all() []*webhook.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*webhook.Event(nil), h.evs...)
}

// The bootstrap is one-shot on DynamoDB: its state survives a restart, so
// a new Manager with the same setting does not bootstrap again after the
// set empties; an armed bootstrap applies once.
func TestBootstrapOneShotOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	p := &approvalPeer{}
	bound := map[string]string{"boot-key": "c1"}
	newManager := func() *approval.Manager {
		return &approval.Manager{Peer: p, Store: tbl.Peer(), Pager: tbl, Threshold: 1, BootstrapKey: "boot-key",
			BoundConnection: func(_ context.Context, k string) (string, bool, error) { c, ok := bound[k]; return c, ok, nil }}
	}
	admins := func(m *approval.Manager) []string {
		t.Helper()
		a, err := m.Admins(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return a.Admins
	}
	m := newManager()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil || len(admins(m)) != 1 {
		t.Fatalf("bootstrap: %v %v", err, admins(m))
	}
	if err := m.ConnectionRemoved(ctx, "c1"); err != nil || len(admins(m)) != 0 {
		t.Fatalf("remove: %v", err)
	}
	// A restart with the setting still there: no second bootstrap.
	m = newManager()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	bound["boot-key"] = "c2"
	if err := m.Tick(ctx); err != nil || len(admins(m)) != 0 {
		t.Fatalf("second bootstrap: %v %v", err, admins(m))
	}
	// The operator arms a new one (another process, as the CLI is).
	if err := newManager().ArmBootstrap(ctx, "new-key"); err != nil {
		t.Fatal(err)
	}
	bound["new-key"] = "c3"
	if err := m.Tick(ctx); err != nil || len(admins(m)) != 1 || admins(m)[0] != "c3" {
		t.Fatalf("armed bootstrap: %v %v", err, admins(m))
	}
	if err := newManager().ArmBootstrap(ctx, "new-key"); !errors.Is(err, approval.ErrAdminsExist) {
		t.Fatalf("armed with admins: %v", err)
	}
	if err := m.ConnectionRemoved(ctx, "c3"); err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil || len(admins(m)) != 0 {
		t.Fatalf("armed bootstrap applied twice: %v %v", err, admins(m))
	}
}
