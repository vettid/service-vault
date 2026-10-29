package api

import (
	"context"
	"errors"
	"testing"

	"github.com/vettid/service-vault/internal/ballot"
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
	} {
		fp.err = err
		if _, m := do(t, h, "POST", "/v1/proposals", apiKey, body); m["error"] != want {
			t.Errorf("%v: %v", err, m)
		}
	}
	if rec, m := do(t, h, "GET", "/v1/proposals/01JBQZ0000000000000000000A", apiKey, ""); rec.Code != 200 || m["published"] != true {
		t.Fatalf("%d %v", rec.Code, m)
	}
	if rec, _ := do(t, h, "GET", "/v1/proposals/01JBQZ0000000000000000000B", apiKey, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}
}
