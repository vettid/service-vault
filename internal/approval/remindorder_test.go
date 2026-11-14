package approval

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// failAfterStore lets the first ok batches that write kind through, then
// fails every one that does: a crash or a store error part way.
type failAfterStore struct {
	peer.Store
	kind string
	ok   int
}

func (s *failAfterStore) Apply(ctx context.Context, changes []peer.Change) error {
	for _, c := range changes {
		if c.Kind == s.kind {
			if s.ok == 0 {
				return errors.New("store down")
			}
			s.ok--
			break
		}
	}
	return s.Store.Apply(ctx, changes)
}

// A reminder that fails to save after withdrawing the old challenge
// leaves its admin in remind_needed, and the next reminder reaches them;
// one that fails before withdrawing anything leaves the old challenge
// live and named.
func TestRemindSaveFailsAfterWithdraw(t *testing.T) {
	for _, force := range []bool{true, false} {
		f := newFixture(t, 2, "c1", "c2")
		f.m.LongChallenges = true
		c := f.create(ActionContractTemplateChange, "Open", `{}`)
		ctx := context.Background()
		old := f.p.last("c1")
		f.clk.Advance(RemindInterval)
		var args []string
		if force {
			args = []string{"c1"}
		} else {
			// Without force, only an undelivered challenge is replaced.
			f.p.mu.Lock()
			if f.p.delivery == nil {
				f.p.delivery = map[string]peer.Delivery{}
			}
			f.p.delivery[old.req] = peer.DeliveryUndelivered
			f.p.mu.Unlock()
		}

		// The store fails before anything is withdrawn: nothing changes.
		f.m.Store = &failAfterStore{Store: f.st, kind: kindApproval}
		if _, err := f.m.Remind(ctx, c.ID, args...); err == nil {
			t.Fatalf("force %v: reminded with the store down", force)
		}
		if slices.Contains(f.p.cancelled, old.req) {
			t.Fatalf("force %v: withdrawn though nothing was saved", force)
		}

		// The store fails after the withdraw, at the reminder's own save.
		f.m.Store = &failAfterStore{Store: f.st, kind: kindApproval, ok: 1}
		if _, err := f.m.Remind(ctx, c.ID, args...); err == nil {
			t.Fatalf("force %v: the failing save didn't fail the reminder", force)
		}
		if !slices.Contains(f.p.cancelled, old.req) {
			t.Fatalf("force %v: not withdrawn", force)
		}
		f.m.Store = f.st
		if s := f.status(c.ID); !slices.Contains(s.RemindNeeded, "c1") || slices.Contains(s.RemindNeeded, "c2") {
			t.Fatalf("force %v: remind_needed %v", force, s.RemindNeeded)
		}
		before := f.p.last("c1")
		r, err := f.m.Remind(ctx, c.ID)
		if err != nil || !slices.Contains(r.Reminded, "c1") || f.p.last("c1").req == before.req {
			t.Fatalf("force %v: next reminder %+v %v", force, r, err)
		}
	}
}
