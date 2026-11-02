package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/vote"
)

type fakeProposals struct {
	last     ballot.ProposalInput
	lastAppr string
	created  int
	err      error
}

func (f *fakeProposals) Create(_ context.Context, approvalID string, in ballot.ProposalInput) (*ballot.Created, error) {
	f.last, f.lastAppr = in, approvalID
	f.created++
	if f.err != nil {
		return nil, f.err
	}
	return &ballot.Created{ProposalID: "01JBQZ0000000000000000000A", ProposalHash: []byte{1}, Eligible: 3, Unsigned: 1, Sent: 3}, nil
}

func (f *fakeProposals) Status(_ context.Context, id string) (*ballot.ProposalStatus, error) {
	if id != "01JBQZ0000000000000000000A" {
		return nil, nil
	}
	return &ballot.ProposalStatus{ProposalID: id, Eligible: 3, Published: true}, nil
}

func (f *fakeProposals) Close(_ context.Context, id string) (*ballot.ResultsSummary, error) {
	switch id {
	case "open":
		return nil, ballot.ErrNotClosed
	case "busy":
		return nil, ballot.ErrNotCaught
	case "nope":
		return nil, ballot.ErrUnknownProposal
	}
	return &ballot.ResultsSummary{ProposalID: id, Tally: map[string]int64{"yes": 2}}, nil
}

func (f *fakeProposals) Results(_ context.Context, id string) (*ballot.PublishedResults, error) {
	if id != "done" {
		return nil, nil
	}
	return &ballot.PublishedResults{Results: []byte(`{"v":1}`), Sig: []byte{1}, Rows: []byte(`{"rows":[]}`), Bundle: []byte(`{}`)}, nil
}

func (f *fakeProposals) Publish(_ context.Context, id string) (int, error) {
	if id != "p1" {
		return 0, ballot.ErrUnknownProposal
	}
	return 3, nil
}

func (f *fakeProposals) Extend(_ context.Context, id, approvalID string, in ballot.ExtensionInput) (*vote.Extension, error) {
	if f.err != nil {
		return nil, f.err
	}
	switch id {
	case "late":
		return nil, ballot.ErrTooLate
	case "changed":
		return nil, ballot.ErrProposalChanged
	case "bad":
		return nil, &ballot.ErrInput{Err: errors.New("short")}
	}
	return &vote.Extension{V: 1, ProposalID: id, N: 1, ClosesAt: in.ClosesAt}, nil
}

func TestProposalRoutes(t *testing.T) {
	s, _, _ := newServer(t)
	if rec, _ := do(t, s.Handler(), "POST", "/v1/proposals", apiKey, `{}`); rec.Code != 404 {
		t.Fatalf("served without proposals: %d", rec.Code)
	}
	fp := &fakeProposals{}
	s.Proposals = fp
	h := s.Handler()
	if rec, _ := do(t, h, "POST", "/v1/proposals", "", `{}`); rec.Code != 401 {
		t.Fatalf("unauthenticated: %d", rec.Code)
	}
	body := `{"approval_id":"A1","title":"T","text":"x","choices":[{"id":"yes","label":"Yes"},{"id":"no","label":"No"}],"quorum":{"text":"q","min_ballots":1},"binding":false,"removed_may_vote":false,"opens_at":1,"closes_at":2,"outage_rule":"r"}`
	rec, m := do(t, h, "POST", "/v1/proposals", apiKey, body)
	if rec.Code != 201 || m["proposal_id"] != "01JBQZ0000000000000000000A" || m["eligible"] != float64(3) || m["unsigned"] != float64(1) || fp.last.Title != "T" || fp.lastAppr != "A1" || len(fp.last.Choices) != 2 {
		t.Fatalf("%d %v", rec.Code, m)
	}
	// Without approval_id nothing is created or extended.
	n := fp.created
	noApproval := strings.Replace(body, `"approval_id":"A1",`, "", 1)
	if rec, m := do(t, h, "POST", "/v1/proposals", apiKey, noApproval); rec.Code != 400 || m["error"] != "approval_required" || fp.created != n {
		t.Fatalf("create without approval_id: %d %v", rec.Code, m)
	}
	if rec, m := do(t, h, "POST", "/v1/proposals", apiKey, strings.Replace(body, `"A1"`, `""`, 1)); rec.Code != 400 || m["error"] != "approval_required" {
		t.Fatalf("create with an empty approval_id: %d %v", rec.Code, m)
	}
	if rec, m := do(t, h, "POST", "/v1/proposals/ok/extend", apiKey, `{"closes_at":9,"outage":{"from":1,"to":5000,"source":"s"}}`); rec.Code != 400 || m["error"] != "approval_required" {
		t.Fatalf("extend without approval_id: %d %v", rec.Code, m)
	}
	for code, want := range map[string]int{approval.CodeApprovalNotApproved: 403, approval.CodeApprovalMismatch: 403, approval.CodeApprovalWrongAction: 403,
		approval.CodeApprovalNotFound: 403, approval.CodeApprovalExpired: 403, approval.CodeApprovalUsed: 409} {
		fp.err = &approval.Error{Code: code}
		if rec, m := do(t, h, "POST", "/v1/proposals", apiKey, body); rec.Code != want || m["error"] != code {
			t.Errorf("create, %s: %d %v", code, rec.Code, m)
		}
		if rec, m := do(t, h, "POST", "/v1/proposals/ok/extend", apiKey, `{"approval_id":"A1","closes_at":9,"outage":{"from":1,"to":5000,"source":"s"}}`); rec.Code != want || m["error"] != code {
			t.Errorf("extend, %s: %d %v", code, rec.Code, m)
		}
	}
	fp.err = ballot.ErrNoApprovals
	if rec, m := do(t, h, "POST", "/v1/proposals", apiKey, body); rec.Code != 503 || m["error"] != "approvals_not_configured" {
		t.Fatalf("no approvals: %d %v", rec.Code, m)
	}
	fp.err = nil
	if rec, _ := do(t, h, "POST", "/v1/proposals", apiKey, `{"approval_id":"A1","title":"T","extra":1}`); rec.Code != 400 {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	for err, want := range map[error]string{
		&ballot.ErrInput{Err: errors.New("bad")}: "invalid_proposal",
		ballot.ErrNoPublisher:                    "publication_not_configured",
		errors.New("store down"):                 "unavailable",
		&ballot.ErrNotPublished{ProposalID: "p1", Err: errors.New("rekor down")}: "not_published",
	} {
		fp.err = err
		if _, m := do(t, h, "POST", "/v1/proposals", apiKey, body); m["error"] != want {
			t.Errorf("%v: %v", err, m)
		}
	}
	fp.err = &ballot.ErrNotPublished{ProposalID: "p1", Err: errors.New("rekor down")}
	if rec, m := do(t, h, "POST", "/v1/proposals", apiKey, body); rec.Code != 503 || m["proposal_id"] != "p1" {
		t.Fatalf("not published: %d %v", rec.Code, m)
	}
	for id, want := range map[string]int{"p1": 200, "nope": 404} {
		if rec, m := do(t, h, "POST", "/v1/proposals/"+id+"/publish", apiKey, ""); rec.Code != want || (want == 200 && m["sent"] != float64(3)) {
			t.Errorf("publish %s: %d %v", id, rec.Code, m)
		}
	}
	if rec, m := do(t, h, "GET", "/v1/proposals/01JBQZ0000000000000000000A", apiKey, ""); rec.Code != 200 || m["published"] != true {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/proposals/01JBQZ0000000000000000000B", apiKey, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}
	for id, want := range map[string]int{"done": 200, "open": 409, "busy": 503, "nope": 404} {
		if rec, m := do(t, h, "POST", "/v1/proposals/"+id+"/close", apiKey, ""); rec.Code != want {
			t.Errorf("close %s: %d %v", id, rec.Code, m)
		}
	}
	fp.err = nil
	ext := `{"approval_id":"A1","closes_at":9,"outage":{"from":1,"to":5000,"source":"https://status.vettid.org/"}}`
	for id, want := range map[string]int{"ok": 200, "late": 409, "bad": 400, "changed": 409} {
		if rec, m := do(t, h, "POST", "/v1/proposals/"+id+"/extend", apiKey, ext); rec.Code != want {
			t.Errorf("extend %s: %d %v", id, rec.Code, m)
		}
	}
	if rec, m := do(t, h, "GET", "/v1/proposals/done/results", apiKey, ""); rec.Code != 200 || m["results"] != `{"v":1}` {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/proposals/open/results", apiKey, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}
}
