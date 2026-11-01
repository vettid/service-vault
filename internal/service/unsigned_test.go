package service

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func (f *fixture) unsigned(max int) *api.UnsignedSignIns {
	f.t.Helper()
	u, err := f.svc.StartUnsigned(context.Background(), max)
	if err != nil {
		f.t.Fatal(err)
	}
	f.pump()
	return u
}

// byConn indexes a run's entries by connection.
func byConn(t *testing.T, u *api.UnsignedSignIns) map[string]api.UnsignedSignIn {
	t.Helper()
	out := map[string]api.UnsignedSignIn{}
	for _, s := range u.SignIns {
		if _, dup := out[s.ConnectionID]; dup {
			t.Fatalf("%s twice in one run", s.ConnectionID)
		}
		out[s.ConnectionID] = s
	}
	return out
}

// StartUnsigned challenges the eligible connections without a pinned key
// once each: not a connection that has signed in, one that cannot vote,
// or one that already has a sign-in pending; and a declined challenge
// holds the connection off for an hour.
func TestStartUnsigned(t *testing.T) {
	f := newFixture(t)
	a := f.m
	b, n := f.member(20), f.member(30)
	n.Features = nil // its vault does not take votes
	ca, _ := f.connect(a, "")
	cb, _ := f.connect(b, "")
	f.connect(n, "")

	u := f.unsigned(50)
	got := byConn(t, u)
	if len(got) != 2 || got[ca].SignInID == "" || got[cb].SignInID == "" || got[ca].MatchCode == "" || u.More != 0 {
		t.Fatalf("first run: %+v", u)
	}
	if len(a.Challenges) != 1 || len(b.Challenges) != 1 || len(n.Challenges) != 0 {
		t.Fatalf("challenges sent: %d %d %d", len(a.Challenges), len(b.Challenges), len(n.Challenges))
	}
	want, _ := signin.Context("VettID Member Service", got[ca].MatchCode)
	if a.Challenges[0].Context != want || a.Challenges[0].MatchCode != got[ca].MatchCode || a.Challenges[0].Purpose != peerwire.PurposeSignIn {
		t.Fatalf("challenge %+v", a.Challenges[0])
	}
	if st := f.status(got[ca].SignInID); st.Status != api.SignInPending {
		t.Fatalf("status %+v", st)
	}

	// Both have a challenge pending: nothing more is sent.
	got = byConn(t, f.unsigned(50))
	if got[ca].Skipped != api.SkipPending || got[cb].Skipped != api.SkipPending || len(a.Challenges) != 1 || len(b.Challenges) != 1 {
		t.Fatalf("second run: %+v", got)
	}

	// a signs: its key is pinned and it drops out. b declines.
	f.sign(a, a.Challenges[0], a.Cred)
	b.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(b.Challenges[0].RequestID).Marshal())
	f.pump()
	got = byConn(t, f.unsigned(50))
	if _, listed := got[ca]; listed || len(got) != 1 || got[cb].Skipped != api.SkipDeclined || len(b.Challenges) != 1 {
		t.Fatalf("after a signed and b declined: %+v", got)
	}

	// An hour after the decline b is challenged again.
	f.clk.Advance(declineCooldown + time.Minute)
	got = byConn(t, f.unsigned(50))
	if got[cb].SignInID == "" || len(b.Challenges) != 2 {
		t.Fatalf("after the cooldown: %+v", got)
	}
}

// A run sends at most max challenges and says how many connections it
// left.
func TestStartUnsignedBound(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "")
	f.connect(f.member(20), "")
	f.connect(f.member(30), "")
	u := f.unsigned(2)
	sent := 0
	for _, s := range u.SignIns {
		if s.SignInID != "" {
			sent++
		}
	}
	if sent != 2 || len(u.SignIns) != 2 || u.More != 1 {
		t.Fatalf("max 2 of 3: %+v", u)
	}
	// The next run, with the two pending, reaches the third.
	got := f.unsigned(2)
	sent = 0
	for _, s := range got.SignIns {
		if s.SignInID != "" {
			sent++
		}
	}
	if sent != 1 || got.More != 0 {
		t.Fatalf("second run: %+v", got)
	}
}

// No more than 10 challenges go to a connection in 24 h, whatever the
// member did with them.
func TestStartUnsignedDailyLimit(t *testing.T) {
	f := newFixture(t)
	cid, _ := f.connect(f.m, "")
	for i := 0; i < maxChallengesPerDay; i++ {
		u := f.unsigned(50)
		if len(u.SignIns) != 1 || u.SignIns[0].SignInID == "" {
			t.Fatalf("challenge %d: %+v", i+1, u)
		}
		f.m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(f.m.Challenges[i].RequestID).Marshal())
		f.pump()
		f.clk.Advance(declineCooldown + time.Minute)
	}
	if u := f.unsigned(50); len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipDailyLimit || len(f.m.Challenges) != maxChallengesPerDay {
		t.Fatalf("over the day's count: %+v", u)
	}
	f.clk.Advance(challengeDay)
	if u := f.unsigned(50); len(u.SignIns) != 1 || u.SignIns[0].SignInID == "" || u.SignIns[0].ConnectionID != cid {
		t.Fatalf("a day later: %+v", u)
	}
}

// An email sign-in's pending challenge holds the run off the connection.
func TestUnsignedSkipsEmailSignIn(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "email-key")
	f.start("email-key", "", "42")
	f.pump()
	if u := f.unsigned(50); len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipPending {
		t.Fatalf("with an email sign-in pending: %+v", u)
	}
}
