package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func (f *fixture) unsigned(max int) *api.UnsignedSignIns {
	f.t.Helper()
	u, err := f.svc.StartUnsigned(context.Background(), max, api.MaxUnsignedExamined)
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

// A run sends no more than its bound of challenges; skipped connections
// do not use it, so a run still reaches the sendable ones behind them,
// but they do count toward the examined bound.
func TestStartUnsignedBounds(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "")
	f.connect(f.member(20), "")
	f.connect(f.member(30), "")
	u := f.unsigned(2)
	if len(u.SignIns) != 2 || u.SignIns[0].SignInID == "" || u.SignIns[1].SignInID == "" || u.More != 1 || u.Stopped != "" {
		t.Fatalf("send 2 of 3: %+v", u)
	}
	// The first two are pending now: skipped without using the bound, and
	// the third gets the challenge.
	u = f.unsigned(2)
	if len(u.SignIns) != 3 || u.SignIns[0].Skipped != api.SkipPending || u.SignIns[1].Skipped != api.SkipPending ||
		u.SignIns[2].SignInID == "" || u.More != 0 {
		t.Fatalf("second run: %+v", u)
	}
	// Examining two connections leaves the third.
	u, err := f.svc.StartUnsigned(context.Background(), 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.SignIns) != 2 || u.SignIns[0].Skipped != api.SkipPending || u.SignIns[1].Skipped != api.SkipPending || u.More != 1 {
		t.Fatalf("examine 2: %+v", u)
	}
}

// More than MaxUnsignedSignIns skippable connections ahead of a sendable
// one do not keep a run from it.
func TestStartUnsignedBehindSkipped(t *testing.T) {
	f := newFixture(t)
	n := api.MaxUnsignedSignIns + 2
	for i := 0; i < n; i++ {
		f.connect(f.member(byte(20+i)), "")
	}
	f.unsigned(n)              // all pending
	f.clk.Advance(time.Second) // the next connection's id sorts after theirs
	f.connect(f.member(100), "")
	u := f.unsigned(1)
	sent := 0
	for _, s := range u.SignIns {
		if s.SignInID != "" {
			sent++
		}
	}
	if sent != 1 || len(u.SignIns) != n+1 || u.More != 0 {
		t.Fatalf("sent %d of %d entries, more %d", sent, len(u.SignIns), u.More)
	}
}

// answerDenied has the member decline its n-th challenge.
func (f *fixture) answerDenied(m *peertest.Member, n int) {
	f.t.Helper()
	m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(m.Challenges[n].RequestID).Marshal())
	f.pump()
}

// A decline of an email sign-in's challenge holds the unsigned run off
// the connection for the hour, and the email path's challenges count
// toward the 10 a day.
func TestUnsignedHistoryFromEmailSignIns(t *testing.T) {
	f := newFixture(t)
	cid, _ := f.connect(f.m, "email-key")
	f.start("email-key", "", "42")
	f.pump()
	f.answerDenied(f.m, 0)
	if u := f.unsigned(10); len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipDeclined {
		t.Fatalf("after an email sign-in was declined: %+v", u)
	}
	f.clk.Advance(declineCooldown + time.Minute)
	for i := 1; i < maxChallengesPerDay; i++ {
		f.start("email-key", "", "42")
		f.pump()
		f.answerDenied(f.m, i)
		f.clk.Advance(declineCooldown + time.Minute)
	}
	if len(f.m.Challenges) != maxChallengesPerDay {
		t.Fatalf("%d challenges", len(f.m.Challenges))
	}
	if u := f.unsigned(10); len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipDailyLimit || u.SignIns[0].ConnectionID != cid {
		t.Fatalf("after 10 email sign-ins: %+v", u)
	}
}

// An answer that does not verify is not a decline: no cooldown.
func TestBadSignatureStartsNoCooldown(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "")
	if u := f.unsigned(10); u.SignIns[0].SignInID == "" {
		t.Fatalf("%+v", u)
	}
	r, err := peerwire.SignConnAuth(f.m.Cred, f.keys.IKPublic(), f.m.IK.Public().(ed25519.PublicKey), f.m.Challenges[0], f.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Sig[0] ^= 1
	f.m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if dn := f.hk.of(peer.EventSignInDenied); len(dn) != 1 || !strings.Contains(string(dn[0].Data), "bad_signature") {
		t.Fatalf("denied webhooks %+v", dn)
	}
	if u := f.unsigned(10); len(u.SignIns) != 1 || u.SignIns[0].SignInID == "" || len(f.m.Challenges) != 2 {
		t.Fatalf("after a bad signature: %+v", u)
	}
}

// A connection that cannot take the challenge now is not_sent, and not
// counted against the day.
func TestStartUnsignedNotSent(t *testing.T) {
	f := newFixture(t)
	cid, _ := f.connect(f.m, "")
	for i := 0; i < peer.MaxPendingChallenges; i++ {
		if _, err := f.p.Authenticate(context.Background(), cid, "x", peerwire.PurposeApproval, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	u := f.unsigned(10)
	if len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipNotSent || u.Stopped != "" {
		t.Fatalf("%+v", u)
	}
	h, err := f.svc.history(context.Background(), cid)
	if err != nil || len(h.Sent) != 0 {
		t.Fatalf("history %+v, %v", h, err)
	}
}

// cancelAfterSend cancels the run's context once a challenge has gone
// out, as a deadline would.
type cancelAfterSend struct {
	Peer
	cancel func()
}

func (c cancelAfterSend) AuthenticateSignIn(ctx context.Context, connID, ctxt, code string, ttl time.Duration) (string, error) {
	id, err := c.Peer.AuthenticateSignIn(ctx, connID, ctxt, code, ttl)
	c.cancel()
	return id, err
}

// A run that ends early answers with what it did, stopped, and counts
// the connections it did not reach.
func TestStartUnsignedStopped(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "")
	f.connect(f.member(20), "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.svc.Peer = cancelAfterSend{f.p, cancel}
	u, err := f.svc.StartUnsigned(ctx, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(u.SignIns) != 1 || u.SignIns[0].SignInID == "" || u.Stopped != api.StoppedTimeout || u.More != 1 {
		t.Fatalf("%+v", u)
	}
	if st := f.status(u.SignIns[0].SignInID); st.Status != api.SignInPending {
		t.Fatalf("status %+v", st)
	}
}

// failSignInStore fails the write of a sign-in record.
type failSignInStore struct{ peer.Store }

func (s failSignInStore) Apply(ctx context.Context, ch []peer.Change) error {
	for _, c := range ch {
		if c.Kind == kindSignIn {
			return errors.New("store down")
		}
	}
	return s.Store.Apply(ctx, ch)
}

// A challenge sent whose sign-in could not be saved still counts toward
// the day, and its match code is given.
func TestStartUnsignedNotRecorded(t *testing.T) {
	f := newFixture(t)
	f.connect(f.m, "")
	m2 := f.member(20)
	f.connect(m2, "")
	f.svc.Store = failSignInStore{f.svc.Store}
	u := f.unsigned(10)
	if len(u.SignIns) != 1 || u.SignIns[0].Skipped != api.SkipNotRecorded || u.SignIns[0].MatchCode == "" ||
		u.SignIns[0].SignInID != "" || u.Stopped != api.StoppedError || u.More != 1 {
		t.Fatalf("%+v", u)
	}
	if n := len(f.m.Challenges) + len(m2.Challenges); n != 1 {
		t.Fatalf("%d challenges", n)
	}
	if h, err := f.svc.history(context.Background(), u.SignIns[0].ConnectionID); err != nil || len(h.Sent) != 1 {
		t.Fatalf("history %+v, %v", h, err)
	}
}

func stripe(k string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(k))
	return h.Sum32() % 64
}

// An email sign-in for a connection whose history lock is on the same
// stripe as the email's lock returns: the history has locks of its own.
func TestSignInWithCollidingStripes(t *testing.T) {
	f := newFixture(t)
	cid, _ := f.connect(f.m, "")
	var k string
	for i := 0; ; i++ {
		k = fmt.Sprintf("email-%d", i)
		if stripe(k) == stripe(cid) {
			break
		}
	}
	if err := f.svc.Store.Apply(context.Background(), []peer.Change{{Kind: kindEmail, ID: k, Data: []byte(cid)}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.svc.SignIns().Start(context.Background(), api.SignInRequest{EmailKey: k, MatchCode: "42"})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("StartSignIn hangs on a stripe it holds")
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
