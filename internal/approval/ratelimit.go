package approval

import (
	"context"
	"strconv"
	"time"

	"github.com/vettid/service-vault/internal/signin"
)

// DefaultCreateLimits are the default limits on creating approvals
// (chosen; not in the spec): 2 per hour and 4 per 24 hours, counted
// across every action of a group, the repair actions (repairActions) in
// one and all the others in the other. Each approval created asks every
// admin and so spends one of each admin's askBudget challenges in 24
// hours. The ordinary group's 4 per 24 hours matches askBudget -
// askReserve, so the API key alone cannot create more ordinary approvals
// in a day than the admins can be asked about, and a burst of them does
// not also refuse a re-pin, whose own group keeps its own count.
var DefaultCreateLimits = []signin.Limit{{Max: 2, Window: time.Hour}, {Max: 4, Window: 24 * time.Hour}}

// RateLimit limits Create per group of actions, in fixed windows
// (SV_APPROVAL_LIMITS, the same limits for each group).
type RateLimit struct {
	Counters signin.Counters
	Limits   []signin.Limit
}

// countCreate counts one Create of action against every limit of its
// group and refuses it (CodeRateLimited) when it exceeds any. A request
// is counted before it is checked further, so a refused or invalid one
// counts too; a counter error fails closed.
func (m *Manager) countCreate(ctx context.Context, action string) error {
	rl := m.Rate
	if rl == nil || rl.Counters == nil {
		return nil
	}
	group := "ordinary"
	if repairActions[action] {
		group = "repair"
	}
	over := false
	for _, lim := range rl.Limits {
		n, err := rl.Counters.Incr(ctx, "apv#"+group+"#"+strconv.FormatInt(int64(lim.Window/time.Second), 10), lim.Window, m.now())
		if err != nil {
			return err
		}
		over = over || n > lim.Max
	}
	if over {
		m.log().Warn("approval rate limited", "action", action, "group", group)
		return errCode(CodeRateLimited)
	}
	return nil
}
