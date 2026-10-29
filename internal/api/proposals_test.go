package api

import (
	"context"
	"errors"
	"testing"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/vote"
)

type fakeProposals struct {
	last ballot.ProposalInput
	err  error
}

func (f *fakeProposals) Create(_ context.Context, in ballot.ProposalInput) (*ballot.Created, error) {
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return &ballot.Created{ProposalID: "01JBQZ0000000000000000000A", ProposalHash: []byte{1}, Eligible: 3, Sent: 3}, nil
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

func (f *fakeProposals) Extend(_ context.Context, id string, in ballot.ExtensionInput) (*vote.Extension, error) {
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
	body := `{"title":"T","text":"x","choices":[{"id":"yes","label":"Yes"},{"id":"no","label":"No"}],"quorum":{"text":"q","min_ballots":1},"binding":false,"removed_may_vote":false,"opens_at":1,"closes_at":2,"outage_rule":"r"}`
	rec, m := do(t, h, "POST", "/v1/proposals", apiKey, body)
	if rec.Code != 201 || m["proposal_id"] != "01JBQZ0000000000000000000A" || m["eligible"] != float64(3) || fp.last.Title != "T" || len(fp.last.Choices) != 2 {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "POST", "/v1/proposals", apiKey, `{"title":"T","extra":1}`); rec.Code != 400 {
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
	ext := `{"closes_at":9,"outage":{"from":1,"to":5000,"source":"https://status.vettid.org/"}}`
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
