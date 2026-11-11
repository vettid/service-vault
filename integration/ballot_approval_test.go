//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"github.com/vettid/service-vault/internal/ballot/ballottest"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

type roster []string

func (r roster) Eligible() []string         { return append([]string{}, r...) }
func (r roster) EligibleUnsigned() []string { return nil }
func (r roster) Active() []string           { return append([]string{}, r...) }

type sink struct{}

func (sink) SendMessage(context.Context, string, string, json.RawMessage, time.Time) (string, error) {
	return "id", nil
}

type site struct{}

func (site) PublishProposal(context.Context, string, []byte, []byte) (json.RawMessage, error) {
	return json.RawMessage(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`), nil
}

func (site) PublishExtension(context.Context, string, int64, []byte, []byte) (ballot.Receipt, error) {
	now := time.Now().Unix()
	return ballot.Receipt{Bundle: ballottest.Bundle(now, now)}, nil
}

func (site) StoredBundle(context.Context, []byte) (json.RawMessage, error) { return nil, nil }

// A vote is made, and extended, only through the admins' approval of
// its exact input, used once, on DynamoDB: the request, the admins'
// signed answers, the execution, a second use (409) and a changed field
// (403), through the HTTP API.
func TestProposalNeedsApprovalOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	runProposalApproval(t, ctx, tbl.Peer(), tbl)
}

func runProposalApproval(t *testing.T, ctx context.Context, st peer.Store, pager approval.Pager) {
	t.Helper()
	p := &approvalPeer{}
	m := &approval.Manager{Peer: p, Store: st, Pager: pager, ServiceName: "VettID Member Service", Threshold: 1, BootstrapKey: "boot-key",
		BoundConnection: func(_ context.Context, k string) (string, bool, error) { return "c1", k == "boot-key", nil }}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	bootstrapAdmin(t, ctx, m, st, p, "c1") // c1 is the first admin, once the operator confirms
	n := 0
	answer := func(conn string) {
		t.Helper()
		n++
		e := &peer.Event{ID: "ev-" + string(rune('a'+n)), Type: peer.EventSignInApproved, ConnectionID: conn, RequestID: p.last[conn],
			Key: make([]byte, 32), Signature: make([]byte, 64), SignedAt: time.Now(), At: time.Now(), Purpose: "approval"}
		if ok, err := m.Answer(ctx, e); err != nil || !ok {
			t.Fatalf("answer %v %v", ok, err)
		}
	}
	// c2 joins the admins by approval; then two of two are needed.
	add, err := m.Create(ctx, approval.Request{Action: approval.ActionAdminSetAdd, Summary: "", Payload: json.RawMessage(`{"connection_id":"c2"}`)})
	if err != nil {
		t.Fatal(err)
	}
	answer("c1")
	if s, _ := m.Status(ctx, add.ID); s.Status != approval.StatusApproved || s.Applied == nil || !*s.Applied {
		t.Fatalf("admin_set.add: %+v", s)
	}
	m.Threshold = 2

	ik := ed25519.NewKeyFromSeed(sha256Bytes("service ik"))
	bm := &ballot.Manager{Store: &ballot.RecordStore{Records: st, Copy: &ballot.MemCopy{}}, IK: ik.Public().(ed25519.PublicKey),
		Sign:   func(label string, msg []byte) ([]byte, error) { return suite.Sign(ik, label, msg) },
		Roster: roster{"c1", "c2", "c3"}, Sender: sink{}, Publisher: site{}, Approvals: m, NewID: envelope.NewULID, Now: time.Now, Timestamp: ballottest.Time}
	m.ProposalTitle = func(ctx context.Context, id string) (string, bool, error) {
		o, err := bm.Store.OpenProposal(ctx, id)
		if err != nil || o == nil {
			return "", false, err
		}
		pr, err := o.Parsed()
		if err != nil {
			return "", false, err
		}
		return pr.Title, true, nil
	}
	h := (&api.Server{Keys: [][32]byte{api.HashKey("k")}, Approvals: m, Proposals: bm}).Handler()
	call := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer k")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	opens := time.Now().Add(time.Hour).Unix()
	in := ballot.ProposalInput{Title: "Adopt the 2027 budget", Choices: []ballot.ChoiceInput{{Label: "Yes"}, {Label: "No"}},
		Quorum: vote.Quorum{MinBallots: 1}, Binding: true, OpensAt: opens, ClosesAt: opens + 86400, OutageRule: ballot.DefaultOutageRule}
	payload, err := ballot.CanonicalProposal(in)
	if err != nil {
		t.Fatal(err)
	}
	body := func(approvalID string, in ballot.ProposalInput) string {
		b, _ := json.Marshal(struct {
			ApprovalID string `json:"approval_id"`
			ballot.ProposalInput
		}{approvalID, in})
		return string(b)
	}
	// No approval: nothing is made.
	if code, out := call("POST", "/v1/proposals", body("", in)); code != 400 || out["error"] != "approval_required" {
		t.Fatalf("no approval id: %d %v", code, out)
	}
	// Ask the admins; the summary is the service's, built from the input.
	code, out := call("POST", "/v1/approvals", `{"action":"proposal.create","summary":"","payload":`+string(payload)+`}`)
	if code != 201 && code != 200 {
		t.Fatalf("approval: %d %v", code, out)
	}
	id := out["approval_id"].(string)
	if code, out := call("POST", "/v1/proposals", body(id, in)); code != 403 || out["error"] != "approval_not_approved" {
		t.Fatalf("pending: %d %v", code, out)
	}
	answer("c1")
	if code, out := call("POST", "/v1/proposals", body(id, in)); code != 403 || out["error"] != "approval_not_approved" {
		t.Fatalf("one of two admins: %d %v", code, out)
	}
	answer("c2")
	// One field changed: refused, and the approval is still good.
	other := in
	other.ClosesAt++
	if code, out := call("POST", "/v1/proposals", body(id, other)); code != 403 || out["error"] != "approval_mismatch" {
		t.Fatalf("changed field: %d %v", code, out)
	}
	code, out = call("POST", "/v1/proposals", body(id, in))
	if code != 201 || out["proposal_id"] == "" {
		t.Fatalf("execute: %d %v", code, out)
	}
	pid := out["proposal_id"].(string)
	if code, out := call("POST", "/v1/proposals", body(id, in)); code != 409 || out["error"] != "approval_used" {
		t.Fatalf("reuse: %d %v", code, out)
	}
	if code, out := call("POST", "/v1/proposals", body(id, other)); code == 201 {
		t.Fatalf("reuse with a changed field: %d %v", code, out)
	}
	recs, err := bm.Store.Records.Load(ctx, ballot.KindProposal)
	if err != nil || len(recs) != 1 {
		t.Fatalf("%d proposals, %v", len(recs), err)
	}

	// Extending takes its own approval of the exact extension.
	ext := ballot.ExtensionInput{ClosesAt: opens + 86400 + 7200,
		Outage: vote.Outage{From: opens + 3600, To: opens + 3600 + 5400, Source: "https://status.vettid.org/"}}
	// An outage is approved and extended for once it is over: the
	// service's clocks are moved past its end.
	later := func() time.Time { return time.Unix(ext.Outage.To+60, 0) }
	bm.Now, m.Now = later, later
	xp, err := ballot.CanonicalExtension(pid, ext)
	if err != nil {
		t.Fatal(err)
	}
	code, out = call("POST", "/v1/approvals", `{"action":"vote.extend","summary":"","payload":`+string(xp)+`}`)
	if code != 201 && code != 200 {
		t.Fatalf("extension approval: %d %v", code, out)
	}
	xid := out["approval_id"].(string)
	answer("c1")
	answer("c2")
	xbody := func(approvalID string, ext ballot.ExtensionInput) string {
		b, _ := json.Marshal(struct {
			ApprovalID string `json:"approval_id"`
			ballot.ExtensionInput
		}{approvalID, ext})
		return string(b)
	}
	changed := ext
	changed.Outage.Source += "x"
	path := "/v1/proposals/" + pid + "/extend"
	if code, out := call("POST", path, xbody(xid, changed)); code != 403 || out["error"] != "approval_mismatch" {
		t.Fatalf("changed extension: %d %v", code, out)
	}
	if code, out := call("POST", path, xbody(xid, ext)); code != http.StatusOK {
		t.Fatalf("extend: %d %v", code, out)
	}
	// The same extension is now refused as input (its new close is the
	// close already), before the approval is looked at; either way it is
	// not made twice.
	if code, out := call("POST", path, xbody(xid, ext)); code != 409 && code != 400 {
		t.Fatalf("extension reuse: %d %v", code, out)
	}

	// Each use is in the audit log.
	consumed := 0
	since := ""
	for {
		pg, err := m.Audit(ctx, since, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range pg.Entries {
			if e.Type == approval.AuditConsumed {
				consumed++
			}
		}
		if pg.Next == "" {
			break
		}
		since = pg.Next
	}
	if consumed != 2 {
		t.Fatalf("%d approval.consumed entries", consumed)
	}
}

func sha256Bytes(s string) []byte { x := sha256.Sum256([]byte(s)); return x[:] }
