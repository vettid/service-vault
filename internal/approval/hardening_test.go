package approval

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
)

// An action's payload is stored and served as its canonical bytes: <, >
// and & are not escaped, so hashing what the audit log serves gives the
// action_hash.
func TestAuditPayloadNotEscaped(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.create(ActionVoteOpen, "Open", `{"note":"<b>&"}`)
	recs, err := f.st.Page(context.Background(), KindAudit, "", 10)
	if err != nil || len(recs) == 0 {
		t.Fatalf("audit: %v %v", recs, err)
	}
	if !bytes.Contains(recs[0].Data, []byte(`<b>&`)) || bytes.Contains(recs[0].Data, []byte("\\"+"u003c")) {
		t.Fatalf("payload escaped: %s", recs[0].Data)
	}
}

// racing writes an admin to the set right after ArmBootstrap reads it,
// as the daemon's bootstrap would from its own process.
type racing struct {
	*peer.MemStore
	done bool
}

func (r *racing) Load(ctx context.Context, kind string) ([]peer.Record, error) {
	recs, err := r.MemStore.Load(ctx, kind)
	if kind == kindAdmins && !r.done {
		r.done = true
		cur, _ := r.MemStore.Load(ctx, kind)
		ch := peer.Change{Kind: kindAdmins, ID: adminsID, Data: []byte(`{"admins":["c9"]}`)}
		if len(cur) > 0 {
			ch.IfVersion = cur[0].Version
		}
		_ = r.MemStore.Apply(ctx, []peer.Change{ch})
	}
	return recs, err
}

// The admin CLI's arming holds only if the admin set is still the empty
// one it read: an admin set meanwhile makes it ErrAdminsExist, both when
// the set had no record and when it was empty.
func TestArmBootstrapRace(t *testing.T) {
	for _, withRecord := range []bool{false, true} {
		f := newFixture(t, 1)
		if withRecord {
			b := f.m.batch(f.clk.Now())
			_ = b.setAdmins(nil)
			_ = b.apply(context.Background())
		}
		f.m.Store = &racing{MemStore: f.st}
		if err := f.m.ArmBootstrap(context.Background(), "key"); !errors.Is(err, ErrAdminsExist) {
			t.Fatalf("record %v: %v", withRecord, err)
		}
	}
}
