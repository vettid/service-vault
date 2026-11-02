package servicevault_test

import (
	"context"
	"encoding/json"
	"testing"
)

// CreateProposal and ExtendProposal send the approval's id with the
// input, once (a 503 is not retried: a retry would use a second
// approval), and refuse a missing id or an input that already has one.
func TestProposalCallsCarryTheApproval(t *testing.T) {
	ctx := context.Background()
	s := &scripted{answers: []int{200}}
	c := scriptedClient(t, s)
	if _, err := c.CreateProposal(ctx, "A1", json.RawMessage(`{"title":"T","closes_at":2}`)); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(s.body.Load().(string)), &got); err != nil || got["approval_id"] != "A1" || got["title"] != "T" || len(got) != 3 {
		t.Fatalf("body %v, %v", s.body.Load(), err)
	}
	if _, err := c.ExtendProposal(ctx, "01JBQZ0000000000000000000A", "A2", json.RawMessage(`{"closes_at":9}`)); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(s.body.Load().(string)), &got); err != nil || got["approval_id"] != "A2" {
		t.Fatalf("body %v, %v", s.body.Load(), err)
	}
	n := s.calls.Load()
	for name, f := range map[string]func() error{
		"no approval":      func() error { _, err := c.CreateProposal(ctx, "", json.RawMessage(`{}`)); return err },
		"has an approval":  func() error { _, err := c.CreateProposal(ctx, "A", json.RawMessage(`{"approval_id":"B"}`)); return err },
		"not an object":    func() error { _, err := c.CreateProposal(ctx, "A", json.RawMessage(`[]`)); return err },
		"duplicate names":  func() error { _, err := c.CreateProposal(ctx, "A", json.RawMessage(`{"a":1,"a":2}`)); return err },
		"extend, no id":    func() error { _, err := c.ExtendProposal(ctx, "", "A", json.RawMessage(`{}`)); return err },
		"extend, no appr.": func() error { _, err := c.ExtendProposal(ctx, "p", "", json.RawMessage(`{}`)); return err },
	} {
		if err := f(); err == nil {
			t.Errorf("%s: sent", name)
		}
	}
	if s.calls.Load() != n {
		t.Fatal("a refused call reached the server")
	}
	s = &scripted{answers: []int{503}}
	if _, err := scriptedClient(t, s).CreateProposal(ctx, "A", json.RawMessage(`{}`)); err == nil || s.calls.Load() != 1 {
		t.Fatalf("%v, %d calls", err, s.calls.Load())
	}
}
