package peer

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Only an approval challenge may outlive 10 minutes, and not 24 hours
// (VAULT-MESSAGING 0.82.0 §10.4, "Long-lived approval challenges").
func TestChallengeLifeByPurpose(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	for _, c := range []struct {
		purpose string
		ttl     time.Duration
		want    time.Duration
	}{
		{peerwire.PurposeApproval, 6 * time.Hour, 6 * time.Hour},
		{peerwire.PurposeApproval, 48 * time.Hour, MaxApprovalChallengeTTL},
		{peerwire.PurposeApproval, 0, peerwire.ConnAuthChallengeTTL},
		{peerwire.PurposeSignIn, 6 * time.Hour, peerwire.ConnAuthChallengeTTL},
		{"", 6 * time.Hour, peerwire.ConnAuthChallengeTTL},
	} {
		before := len(m.Received(peerwire.TypeConnAuthChallenge))
		if _, err := f.p.Authenticate(ctx, cid, "x", c.purpose, c.ttl); err != nil {
			t.Fatal(err)
		}
		f.pump()
		got := m.Received(peerwire.TypeConnAuthChallenge)
		if len(got) != before+1 {
			t.Fatalf("%d challenges, want %d", len(got), before+1)
		}
		if want := f.clk.Now().Add(c.want).Truncate(time.Millisecond); !got[before].Exp.Equal(want) {
			t.Fatalf("%q %v: exp %v, want %v", c.purpose, c.ttl, got[before].Exp, want)
		}
	}
}
