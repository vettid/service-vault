package approval

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/signin"
)

// Ordinary actions stop at askBudget - askReserve counting challenges;
// the repair actions may still use the reserved one, so a burst of vote
// approvals cannot leave the admins unaskable for a change to the set.
func TestAskReserveForRepairs(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.fillAsks("c1", ordinaryLimit)
	f.fillAsks("c2", ordinaryLimit)
	if _, err := f.createErr(); codeOf(err) != CodeAskBudget {
		t.Fatalf("ordinary at the reserve: %v", err)
	}
	for _, a := range []string{ActionProposalCreate, ActionVoteExtend, ActionAssignmentPush} {
		if !(askLimit(a) == askBudget-askReserve) {
			t.Fatalf("%s: limit %d", a, askLimit(a))
		}
	}
	rm := f.create(ActionAdminSetRemove, "", `{"connection_id":"c2"}`)
	if len(rm.AskBudget) != 0 {
		t.Fatalf("repair left out: %+v", rm.AskBudget)
	}
	l, err := f.m.asks(context.Background(), "c1")
	if err != nil || len(l.Exp) != askBudget {
		t.Fatalf("%+v %v", l, err)
	}
	// Now full for repairs too.
	if _, err := f.m.Create(context.Background(), Request{Action: ActionAdminSetRemove, Payload: json.RawMessage(`{"connection_id":"c2"}`)}); codeOf(err) != CodeAskBudget {
		t.Fatalf("repair at the budget: %v", err)
	}
}

// Create is limited per group of actions: the ordinary ones share one
// count, the repair ones another, and a refused or invalid request counts.
func TestCreateRateLimit(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.m.Rate = &RateLimit{Counters: &signin.MemCounters{}, Limits: DefaultCreateLimits}
	ctx := context.Background()
	ordinary := func(action, payload string) error {
		_, err := f.m.Create(ctx, Request{Action: action, Summary: "Open", Payload: json.RawMessage(payload)})
		return err
	}
	// Two in the hour, across actions.
	if err := ordinary(ActionContractTemplateChange, `{}`); err != nil {
		t.Fatal(err)
	}
	if err := ordinary(ActionAssignmentPush, `{"x":1`); codeOf(err) != CodeInvalidPayload {
		t.Fatalf("invalid: %v", err)
	}
	if err := ordinary(ActionContractTemplateChange, `{}`); codeOf(err) != CodeRateLimited {
		t.Fatalf("third in the hour: %v", err)
	}
	// The repair group keeps its own count.
	if _, err := f.m.Create(ctx, Request{Action: ActionAdminSetRemove, Payload: json.RawMessage(`{"connection_id":"c2"}`)}); err != nil {
		t.Fatalf("repair: %v", err)
	}
	// A new hour: two more, then the day's 4 are spent.
	f.clk.Advance(time.Hour)
	for i := range 2 {
		if err := ordinary(ActionContractTemplateChange, `{}`); i == 0 && err != nil || i == 1 && codeOf(err) != CodeRateLimited {
			t.Fatalf("hour 2, %d: %v", i, err)
		}
	}
	f.clk.Advance(time.Hour)
	if err := ordinary(ActionContractTemplateChange, `{}`); codeOf(err) != CodeRateLimited {
		t.Fatalf("over the day: %v", err)
	}
	f.clk.Advance(24 * time.Hour)
	if err := ordinary(ActionContractTemplateChange, `{}`); err != nil && codeOf(err) != CodeAskBudget {
		t.Fatalf("next day: %v", err)
	}
}

// A counter error fails closed.
func TestCreateRateLimitCounterError(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.Rate = &RateLimit{Counters: failCounters{}, Limits: DefaultCreateLimits}
	if c, err := f.createErr(); err == nil || codeOf(err) != "" {
		t.Fatalf("%+v %v", c, err)
	}
	if f.openCount() != 0 {
		t.Fatal("created on a counter error")
	}
}

type failCounters struct{}

func (failCounters) Incr(context.Context, string, time.Duration, time.Time) (int64, error) {
	return 0, context.DeadlineExceeded
}
