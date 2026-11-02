package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/approval"
)

// fakeApprovals answers by id: "a1" exists, "soon" is too soon, "done"
// is no longer pending; actions named "unreachable" are refused.
type fakeApprovals struct {
	last       approval.Request
	since      string
	limit      int
	statusFail bool
	force      []string
}

func (f *fakeApprovals) Create(_ context.Context, req approval.Request) (*approval.Created, error) {
	f.last = req
	if req.Summary == "unreachable" {
		return nil, &approval.Error{Code: approval.CodeUnreachable}
	}
	if req.Summary == "bad" {
		return nil, &approval.Error{Code: approval.CodeInvalidSummary}
	}
	return &approval.Created{ID: "a1", ActionHash: strings.Repeat("ab", 32), Status: approval.StatusPending,
		ExpiresAt: time.Unix(1_800_086_400, 0).UTC()}, nil
}

func (f *fakeApprovals) Status(_ context.Context, id string) (*approval.Status, error) {
	if f.statusFail {
		return nil, context.DeadlineExceeded
	}
	if id != "a1" {
		return nil, approval.ErrNotFound
	}
	return &approval.Status{ID: id, Status: approval.StatusApproved, ActionHash: strings.Repeat("ab", 32), Threshold: 1,
		Admins: []string{"c1"}, Approvals: []approval.Approver{{ConnectionID: "c1", KeyChanged: true}}, Denials: []approval.Denier{}, RemindNeeded: []string{"c2"}}, nil
}

func (f *fakeApprovals) Remind(_ context.Context, id string, force ...string) (*approval.Reminder, error) {
	f.force = force
	if len(force) > 0 && id == "a1" {
		switch force[0] {
		case "notadmin":
			return nil, &approval.Error{Code: approval.CodeNotAdmin}
		case "answered":
			return nil, &approval.Error{Code: approval.CodeAnswered}
		case "spent":
			return nil, &approval.Error{Code: approval.CodeAskBudget}
		}
		return &approval.Reminder{ID: id, Reminded: force}, nil
	}
	switch id {
	case "soon":
		return nil, &approval.Error{Code: approval.CodeTooSoon}
	case "idle":
		return nil, &approval.Error{Code: approval.CodeNothingToRemind}
	case "done":
		return nil, &approval.Error{Code: approval.CodeNotPending}
	case "a1":
		return &approval.Reminder{ID: id, Reminded: []string{"c2"}}, nil
	}
	return nil, approval.ErrNotFound
}

func (f *fakeApprovals) Admins(context.Context) (*approval.Admins, error) {
	return &approval.Admins{Admins: []string{"c1", "c2"}, Threshold: 1}, nil
}

func (f *fakeApprovals) Audit(_ context.Context, since string, limit int) (*approval.AuditPage, error) {
	f.since, f.limit = since, limit
	return &approval.AuditPage{Entries: []approval.AuditEntry{{ID: "e1", Type: approval.AuditRequested}}, Next: "e1"}, nil
}

func TestApprovalRoutes(t *testing.T) {
	s, _, _ := newServer(t)
	if rec, _ := do(t, s.Handler(), "GET", "/v1/admins", apiKey, ""); rec.Code != 404 {
		t.Fatalf("served without approvals: %d", rec.Code)
	}
	fa := &fakeApprovals{}
	s.Approvals = fa
	h := s.Handler()
	if rec, _ := do(t, h, "GET", "/v1/admins", "", ""); rec.Code != 401 {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	payload := `{"text":"` + strings.Repeat("x", approval.MaxPayload-20) + `"}`
	rec, m := do(t, h, "POST", "/v1/approvals", apiKey, `{"action":"contract_template.change","summary":"Open","payload":`+payload+`}`)
	if rec.Code != 201 || m["approval_id"] != "a1" || m["status"] != "pending" || m["action_hash"] == nil || m["expires_at"] == nil {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if fa.last.Action != "contract_template.change" || string(fa.last.Payload) != payload {
		t.Fatalf("request %+v", fa.last.Action)
	}
	for body, want := range map[string]int{
		`{"action":"contract_template.change","summary":"unreachable","payload":{}}`:                                         422,
		`{"action":"contract_template.change","summary":"bad","payload":{}}`:                                                 400,
		`{"action":"contract_template.change","summary":"x","payload":{},"extra":1}`:                                         400,
		`{"action":"contract_template.change","summary":"x","payload":"` + strings.Repeat("y", 3*approval.MaxPayload) + `"}`: 400,
	} {
		if rec, m := do(t, h, "POST", "/v1/approvals", apiKey, body); rec.Code != want {
			t.Errorf("%.60s: %d %v", body, rec.Code, m)
		}
	}
	if _, m := do(t, h, "POST", "/v1/approvals", apiKey, `{"action":"contract_template.change","summary":"unreachable","payload":{}}`); m["error"] != "unreachable" {
		t.Fatalf("%v", m)
	}
	rec, m = do(t, h, "GET", "/v1/approvals/a1", apiKey, "")
	ap, _ := m["approvals"].([]any)
	if rec.Code != 200 || m["status"] != "approved" || len(ap) != 1 || ap[0].(map[string]any)["key_changed"] != true || fmt.Sprint(m["remind_needed"]) != "[c2]" {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/approvals/nope", apiKey, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}
	for id, want := range map[string]int{"a1": 200, "soon": 429, "idle": 409, "done": 409, "nope": 404} {
		if rec, m := do(t, h, "POST", "/v1/approvals/"+id+"/remind", apiKey, ""); rec.Code != want {
			t.Errorf("remind %s: %d %v", id, rec.Code, m)
		}
	}
	// A forced re-send names admins in the body; the body is optional.
	for body, want := range map[string]int{`{"force":["c2"]}`: 200, `{"force":["notadmin"]}`: 422, `{"force":["answered"]}`: 409,
		`{"force":["spent"]}`: 409, `{"force":"c2"}`: 400, `{"other":1}`: 400, `{`: 400,
		`{"force":["c2"]}}`: 400, `{"force":["c2"]}]`: 400, `{"force":["c2"]} x`: 400, `{"force":["c2"]}{}`: 400} {
		if rec, m := do(t, h, "POST", "/v1/approvals/a1/remind", apiKey, body); rec.Code != want {
			t.Errorf("remind %s: %d %v", body, rec.Code, m)
		}
	}
	if rec, m := do(t, h, "POST", "/v1/approvals/a1/remind", apiKey, `{"force":["c2"]}`); rec.Code != 200 || fmt.Sprint(m["reminded"]) != "[c2]" || fmt.Sprint(fa.force) != "[c2]" {
		t.Errorf("forced remind: %d %v %v", rec.Code, m, fa.force)
	}
	if rec, _ := do(t, h, "POST", "/v1/approvals/a1/remind", apiKey, ""); rec.Code != 200 || len(fa.force) != 0 {
		t.Errorf("plain remind: %d %v", rec.Code, fa.force)
	}
	// An empty body sent chunked (length unknown) is no body either.
	chunked := httptest.NewRequest("POST", "/v1/approvals/a1/remind", strings.NewReader(""))
	chunked.ContentLength = -1
	chunked.Header.Set("Authorization", "Bearer "+apiKey)
	crec := httptest.NewRecorder()
	h.ServeHTTP(crec, chunked)
	if crec.Code != 200 || len(fa.force) != 0 {
		t.Errorf("chunked empty remind: %d %s", crec.Code, crec.Body.String())
	}
	if rec, m := do(t, h, "GET", "/v1/admins", apiKey, ""); rec.Code != 200 || m["threshold"] != float64(1) {
		t.Fatalf("%d %v", rec.Code, m)
	}
	rec, m = do(t, h, "GET", "/v1/audit?since=e0&limit=5", apiKey, "")
	if rec.Code != 200 || m["next"] != "e1" || fa.since != "e0" || fa.limit != 5 {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/audit", apiKey, ""); rec.Code != 200 || fa.since != "" || fa.limit != 0 {
		t.Fatalf("%d", rec.Code)
	}
	for _, q := range []string{"limit=0", "limit=101", "limit=x", "since=" + strings.Repeat("z", 65)} {
		if rec, _ := do(t, h, "GET", "/v1/audit?"+q, apiKey, ""); rec.Code != 400 {
			t.Errorf("%s: %d", q, rec.Code)
		}
	}
	fa.statusFail = true
	if rec, m := do(t, h, "GET", "/v1/approvals/a1", apiKey, ""); rec.Code != http.StatusServiceUnavailable || m["error"] != "unavailable" {
		t.Fatalf("%d %v", rec.Code, m)
	}
}
