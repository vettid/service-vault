package peer

import (
	"context"
	"crypto/ed25519"
	"slices"
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

// A third long-lived approval challenge to a connection is sent with 10
// minutes, as the member vault keeps two (VAULT-MESSAGING 0.82.0 §10.4,
// "Limits"); a place frees when its challenge is withdrawn or ends; one
// whose withdraw was not queued keeps counting until its exp.
func TestLongLivedChallengeLimit(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	send := func(ttl time.Duration) (string, time.Duration) {
		t.Helper()
		n := len(m.Received(peerwire.TypeConnAuthChallenge))
		id, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, ttl)
		if err != nil {
			t.Fatal(err)
		}
		f.pump()
		got := m.Received(peerwire.TypeConnAuthChallenge)
		if len(got) != n+1 {
			t.Fatalf("%d challenges", len(got))
		}
		return id, got[n].Exp.Sub(f.clk.Now())
	}
	long, short := 6*time.Hour, peerwire.ConnAuthChallengeTTL
	a, d := send(long)
	b, d2 := send(long)
	if d != long || d2 != long {
		t.Fatalf("first two %v %v", d, d2)
	}
	third, d3 := send(long)
	if d3 != short {
		t.Fatalf("third %v", d3)
	}
	// Withdrawn (queued): the places are free. The 10-minute third counted
	// as one too (a lagging member clock would see it as long).
	for _, id := range []string{a, third} {
		if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
	f.pump()
	if _, d := send(long); d != long {
		t.Fatalf("after a withdraw %v", d)
	}
	// Cancelled with the outbox full, so no withdraw: still counted.
	c := f.p.conns[cid]
	for f.p.outboxFor(cid) < MaxOutboxPerConn {
		f.p.queueDeposit(&outboxEntry{ConnID: cid, Mailbox: c.Peer.Relay.Mailbox, Payload: []byte("x"), NotBefore: f.clk.Now().Add(1000 * time.Hour)},
			f.clk.Now())
	}
	if ok, err := f.p.CancelChallenge(ctx, b); !ok || err != nil {
		t.Fatal(ok, err)
	}
	p := f.p
	p.mu.Lock()
	p.outbox = slices.DeleteFunc(p.outbox, func(e *outboxEntry) bool { return string(e.Payload) == "x" })
	p.mu.Unlock()
	f.pump()
	if n := len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 2 {
		t.Fatalf("%d withdraws", n)
		t.Fatalf("%d withdraws", n)
	}
	if _, d := send(long); d != short {
		t.Fatalf("with an undelivered withdraw %v", d)
	}
	// A cancelled place answers to nothing and is not reported when it ends.
	if ok, _ := f.p.CancelChallenge(ctx, b); ok {
		t.Fatal("a forgotten challenge cancelled twice")
	}
	f.clk.Advance(long)
	f.tick()
	for _, e := range f.p.events {
		if e.RequestID == b {
			t.Fatalf("event %s for a cancelled challenge", e.Type)
		}
	}
	// At exp the places still count for the clock skew, then they are free.
	if _, d := send(long); d != short {
		t.Fatalf("at exp %v", d)
	}
	f.clk.Advance(ClockSkew)
	f.tick()
	if _, d := send(long); d != long {
		t.Fatalf("after the places ended %v", d)
	}
}

// The member vault holds at most 4 challenges from a connection and drops a
// fifth silently; a long approval challenge past that is sent with 10
// minutes, so that its expiry is seen (VAULT-MESSAGING §10.4.1).
func TestHeldChallengeLimit(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	short := peerwire.ConnAuthChallengeTTL
	expOf := func(purpose string, ttl time.Duration) (string, time.Duration) {
		t.Helper()
		n := len(m.Received(peerwire.TypeConnAuthChallenge))
		id, err := f.p.Authenticate(ctx, cid, "x", purpose, ttl)
		if err != nil {
			t.Fatal(err)
		}
		f.pump()
		return id, m.Received(peerwire.TypeConnAuthChallenge)[n].Exp.Sub(f.clk.Now())
	}
	// A sign-in and three short approvals fill the four places.
	s, _ := expOf(peerwire.PurposeSignIn, 0)
	for i := 0; i < 3; i++ {
		if _, d := expOf(peerwire.PurposeApproval, 0); d != short {
			t.Fatal(d)
		}
	}
	if _, d := expOf(peerwire.PurposeApproval, 6*time.Hour); d != short {
		t.Fatalf("a fifth place %v", d)
	}
	// Withdrawn: a place is free, and a long one is long again.
	if ok, err := f.p.CancelChallenge(ctx, s); !ok || err != nil {
		t.Fatal(ok, err)
	}
	f.pump()
	// The fifth (10 minutes) still holds a place: 4 held.
	if _, d := expOf(peerwire.PurposeApproval, 6*time.Hour); d != short {
		t.Fatalf("still four held %v", d)
	}
	f.clk.Advance(short + ClockSkew)
	f.tick()
	if _, d := expOf(peerwire.PurposeApproval, 6*time.Hour); d != 6*time.Hour {
		t.Fatalf("after the places ended %v", d)
	}
}

// A long challenge keeps its place until exp plus the clock skew.
func TestLongPlaceSkewBoundary(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	long := time.Hour
	for i := 0; i < MaxLongLivedChallenges; i++ {
		if _, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, long); err != nil {
			t.Fatal(err)
		}
	}
	f.pump()
	next := func() time.Duration {
		t.Helper()
		n := len(m.Received(peerwire.TypeConnAuthChallenge))
		if _, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, long); err != nil {
			t.Fatal(err)
		}
		f.pump()
		return m.Received(peerwire.TypeConnAuthChallenge)[n].Exp.Sub(f.clk.Now())
	}
	f.clk.Advance(long + ClockSkew - time.Second)
	f.tick()
	if d := next(); d != peerwire.ConnAuthChallengeTTL {
		t.Fatalf("inside the skew %v", d)
	}
	f.clk.Advance(time.Second)
	f.tick()
	if d := next(); d != long {
		t.Fatalf("at exp plus the skew %v", d)
	}
}

// An expired challenge stays as a Gone record until exp plus the clock
// skew: reported once, a late signed answer is not accepted, and it is
// deleted after the skew. A Gone sign-in still counts as pending.
func TestExpiredChallengeKeptUntilSkew(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	id, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.clk.Advance(2 * time.Minute)
	f.tick()
	if ex := f.ev.of(EventSignInExpired); len(ex) != 1 || ex[0].RequestID != id {
		t.Fatalf("expired %+v", ex)
	}
	if f.p.challenges[id] == nil || !f.p.challenges[id].Gone {
		t.Fatal("the expired challenge is not kept")
	}
	if !f.p.HasPendingSignIn(cid) {
		t.Fatal("a Gone sign-in does not count as pending")
	}
	// A late signed answer inside the skew.
	r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(30 * time.Second)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if n := len(f.ev.of(EventSignInApproved)); n != 0 {
		t.Fatalf("%d approvals for a late answer", n)
	}
	f.tick()
	f.tick()
	if n := len(f.ev.of(EventSignInExpired)); n != 1 {
		t.Fatalf("%d expired events", n)
	}
	if f.p.challenges[id] == nil {
		t.Fatal("deleted inside the skew")
	}
	f.clk.Advance(ClockSkew)
	f.tick()
	if f.p.challenges[id] != nil {
		t.Fatal("kept past exp plus the skew")
	}
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("still pending after the skew")
	}
	if n := len(f.ev.of(EventSignInExpired)); n != 1 {
		t.Fatalf("%d expired events at the end", n)
	}
}

// A member vault whose clock lags counts even a 10-minute approval challenge
// as long-lived, so two of them held leave no long place: a third long
// request is sent with 10 minutes.
func TestShortApprovalChallengesCountAsLong(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	for i := 0; i < MaxLongLivedChallenges; i++ {
		if _, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 0); err != nil {
			t.Fatal(err)
		}
	}
	f.pump()
	n := len(m.Received(peerwire.TypeConnAuthChallenge))
	if _, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if d := m.Received(peerwire.TypeConnAuthChallenge)[n].Exp.Sub(f.clk.Now()); d != peerwire.ConnAuthChallengeTTL {
		t.Fatalf("third %v", d)
	}
}
