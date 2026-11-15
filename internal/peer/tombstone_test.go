package peer

import (
	"context"
	"strings"
	"testing"
	"time"
)

// wholeUp is t rounded up to the whole second, as a relay reports it.
func wholeUp(t time.Time) time.Time {
	if r := t.Truncate(time.Second); r.Before(t) {
		return r.Add(time.Second)
	}
	return t
}

// issuedJTIs is the set of tokens the service has issued.
func issuedJTIs(f *fixture) map[string]bool {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	out := map[string]bool{}
	for jti := range f.p.issued {
		out[jti] = true
	}
	return out
}

// mintedSince returns the iat of each token issued that isn't in was.
func mintedSince(f *fixture, was map[string]bool) (iats []time.Time) {
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	for jti, tk := range f.p.issued {
		if !was[jti] {
			iats = append(iats, tk.Iat)
		}
	}
	return iats
}

// A relay that reports tombstones answers with no tokens_not_before after
// a registration that got no answer: nothing was lost, whatever the
// attempted mark says. No alarm, no wait, and the mark clears.
func TestTombReportNoneAfterUnanswered(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	setRelayReg(t, f, relayReg{Registered: true, Attempted: true})
	f.reportTomb = true
	f.start()
	if lostAlarms(f) != 0 || f.slept != 0 {
		t.Fatalf("%d alarms, waited %s", lostAlarms(f), f.slept)
	}
	if r, _ := f.p.readRelayReg(context.Background()); r.Attempted || !r.RemintAfter.IsZero() || !r.Registered {
		t.Fatalf("record %+v", r)
	}
}

// A fresh deletion: the relay reports its tokens-not-before; the member's
// tokens are older, so the mailbox was lost. The alarm is raised once, the
// wait is until T + TombstoneSkew (not FreshMailboxWait from the answer),
// and the re-minted tokens have iat at or after T. The same T at a later
// start is nothing new.
func TestTombReportFreshDeletion(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := issuedTo(m)
	f.clk.Advance(5 * time.Second)
	f.w.DeleteMailbox(f.keys.Mailbox())
	nb := wholeUp(f.clk.Now().Add(90 * time.Second))
	f.reportTomb, f.tombNB = true, nb
	start, was := f.clk.Now(), issuedJTIs(f)
	f.start()
	if lostAlarms(f) != 1 || !strings.Contains(f.logs.String(), "tokens_not_before=") {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	if want := nb.Add(TombstoneSkew).Sub(start); f.slept != want {
		t.Fatalf("waited %s, want %s (until T + TombstoneSkew)", f.slept, want)
	}
	f.pump()
	if got := issuedTo(m) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted", got)
	}
	iats := mintedSince(f, was)
	if len(iats) != 2 {
		t.Fatalf("%d tokens minted after the start", len(iats))
	}
	for _, iat := range iats {
		if iat.Before(nb) {
			t.Fatalf("a re-minted token's iat %v is before the tombstone %v", iat, nb)
		}
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.Tombstone.Equal(nb) || !r.RemintAfter.IsZero() {
		t.Fatalf("record %+v", r)
	}
	slept := f.slept
	f.start()
	f.tick()
	f.pump()
	if lostAlarms(f) != 1 || f.slept != slept || issuedTo(m)-before != 2 {
		t.Fatalf("the same T again: %d alarms, waited %s more, %d tokens", lostAlarms(f), f.slept-slept, issuedTo(m)-before)
	}
}

// A deletion long ago, before every token the service relies on (a relay
// that keeps the time for good reports it at every registration): no
// alarm and no wait, even after an unanswered registration.
func TestTombReportOldDeletion(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(-48 * time.Hour)
	nb := wholeUp(f.clk.Now())
	f.clk.Advance(48 * time.Hour)
	m := f.member(10)
	f.connect(m, "")
	before := issuedTo(m)
	setRelayReg(t, f, relayReg{Registered: true, Attempted: true})
	f.reportTomb, f.tombNB = true, nb
	f.start()
	f.start()
	f.tick()
	f.pump()
	if lostAlarms(f) != 0 || f.slept != 0 || issuedTo(m) != before {
		t.Fatalf("%d alarms, waited %s, %d tokens", lostAlarms(f), f.slept, issuedTo(m)-before)
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.Tombstone.Equal(nb) || r.Attempted {
		t.Fatalf("record %+v", r)
	}
}

// A deletion long ago, but after tokens the service still relies on: a
// loss, with no wait (T + TombstoneSkew is long past), and a re-mint. A
// record without an iat counts as older.
func TestTombReportOlderTokens(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		f.connect(m, "")
		before := issuedTo(m)
		if unknown {
			f.p.mu.Lock() // as records stored before Iat was kept
			for _, tk := range f.p.issued {
				tk.Iat = time.Time{}
				f.p.markDirty(kindToken, tk.JTI)
			}
			err := f.p.flush(context.Background())
			f.p.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			f.clk.Advance(time.Minute) // a T after nothing but the unknown iat could be
		} else {
			f.clk.Advance(2 * time.Hour)
		}
		nb := wholeUp(f.clk.Now().Add(-time.Hour / 2))
		if unknown {
			nb = wholeUp(f.clk.Now().Add(-48 * time.Hour))
		}
		f.reportTomb, f.tombNB = true, nb
		f.start()
		f.pump()
		if lostAlarms(f) != 1 || f.slept != 0 || issuedTo(m)-before != 2 {
			t.Fatalf("unknown iat %v: %d alarms, waited %s, %d tokens", unknown, lostAlarms(f), f.slept, issuedTo(m)-before)
		}
		if got := strings.Contains(f.logs.String(), "tokens_of_unknown_age=true"); got != unknown {
			t.Fatalf("unknown iat %v: tokens_of_unknown_age logged %v", unknown, got)
		}
	}
}

// Nothing is minted before T + TombstoneSkew, even when no token relied on
// is older (no loss): a token minted then would be refused.
func TestTombReportMintFloor(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	nb := wholeUp(f.clk.Now().Add(-61 * time.Second)) // just before the member's tokens' iat
	f.reportTomb, f.tombNB = true, nb
	start := f.clk.Now()
	f.start()
	if lostAlarms(f) != 0 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	if want := nb.Add(TombstoneSkew).Sub(start); want <= 0 || f.slept != want {
		t.Fatalf("waited %s, want %s", f.slept, want)
	}
	if _, err := f.p.CreateInvite(context.Background(), ""); err != nil {
		t.Fatalf("after the floor: %v", err)
	}
}

// A 201 with no tokens_not_before, for a mailbox registered before: the
// relay lost what it held. The members' tokens still work, so no re-mint
// and no wait; the alarm is raised and revocations are sent again.
func TestTombReportDataLoss(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	ctx := context.Background()
	var usedOpen string // the member's invitation: used, its token revoked
	f.p.mu.Lock()
	for _, iv := range f.p.invites {
		if iv.Used {
			usedOpen = iv.OpenJTI
		}
	}
	f.p.mu.Unlock()
	inv, err := f.p.CreateInvite(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.CancelInvite(ctx, inv.ID); err != nil {
		t.Fatal(err)
	}
	f.pump()
	revoked, usedRevoked := f.revokes[inv.OpenJTI], f.revokes[usedOpen]
	if revoked == 0 {
		t.Fatal("the cancelled invitation's token was never revoked")
	}
	before := issuedTo(m)
	f.w.DeleteMailbox(f.keys.Mailbox()) // the relay answers 201 again
	f.reportTomb = true
	f.start()
	f.pump()
	logs := f.logs.String()
	if lostAlarms(f) != 1 || !strings.Contains(logs, "tokens_kept=true") || f.slept != 0 || issuedTo(m) != before {
		t.Fatalf("%d alarms, waited %s, %d tokens", lostAlarms(f), f.slept, issuedTo(m)-before)
	}
	if f.revokes[inv.OpenJTI] <= revoked {
		t.Fatal("the revocation was not sent again")
	}
	// The used invitation's one-shot token is revoked again too (the relay
	// forgot its use).
	if usedOpen == "" || f.revokes[usedOpen] <= usedRevoked {
		t.Fatalf("a used invitation's token %q was not revoked again", usedOpen)
	}
}

// cancelledInvite makes an invitation and cancels it (its open token is
// revoked), and returns its token's jti and how often it was revoked.
func cancelledInvite(t *testing.T, f *fixture) (string, int) {
	t.Helper()
	ctx := context.Background()
	inv, err := f.p.CreateInvite(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.CancelInvite(ctx, inv.ID); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if f.revokes[inv.OpenJTI] == 0 {
		t.Fatal("the cancelled invitation's token was never revoked")
	}
	return inv.OpenJTI, f.revokes[inv.OpenJTI]
}

// A 201 with a T already judged (a relay that lost the mailbox's record
// but kept its tombstone) still means the relay lost its denylist:
// revocations are sent again, with the alarm.
func TestTombReport201SameT(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	jti, n := cancelledInvite(t, f)
	nb := wholeUp(f.clk.Now().Add(-48 * time.Hour))
	setRelayReg(t, f, relayReg{Registered: true, Tombstone: nb})
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.reportTomb, f.tombNB = true, nb
	f.start()
	f.pump()
	if lostAlarms(f) != 1 || !strings.Contains(f.logs.String(), "tokens_kept=true") || f.revokes[jti] <= n {
		t.Fatalf("%d alarms, revocations %d -> %d", lostAlarms(f), n, f.revokes[jti])
	}
	if r, _ := f.p.readRelayReg(context.Background()); r.DenyOwed {
		t.Fatalf("record %+v", r)
	}
}

// Revocations owed by a data loss survive a stop before they were stored:
// the next registration, a plain 200, sends them.
func TestTombReportDenyOwedSurvives(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	jti, n := cancelledInvite(t, f)
	setRelayReg(t, f, relayReg{Registered: true, DenyOwed: true})
	f.reportTomb = true
	f.start()
	f.pump()
	if f.revokes[jti] <= n {
		t.Fatalf("revocations %d -> %d", n, f.revokes[jti])
	}
	if r, _ := f.p.readRelayReg(context.Background()); r.DenyOwed {
		t.Fatalf("record %+v", r)
	}
}

// A T far ahead of the clock is waited for (a token minted before it would
// be refused), and logged; a new T that refuses no token relied on is
// logged as a possible loss of messages.
func TestTombReportLogs(t *testing.T) {
	f := newFixture(t)
	f.reportTomb, f.tombNB = true, wholeUp(f.clk.Now().Add(24*time.Hour))
	f.start()
	if !strings.Contains(f.logs.String(), "far ahead") || f.slept < 24*time.Hour {
		t.Fatalf("waited %s", f.slept)
	}
	g := newFixture(t)
	g.clk.Advance(-time.Hour)
	nb := wholeUp(g.clk.Now())
	g.clk.Advance(time.Hour)
	g.connect(g.member(10), "")
	g.reportTomb, g.tombNB = true, nb
	g.start()
	if lostAlarms(g) != 0 || !strings.Contains(g.logs.String(), "messages deposited before it may be gone") {
		t.Fatalf("%d alarms", lostAlarms(g))
	}
}

// A floor not yet passed is kept when a later answer doesn't report one
// (a relay instance without the flag).
func TestTombReportFloorKept(t *testing.T) {
	f := newFixture(t)
	f.start()
	ctx := context.Background()
	f.reportTomb, f.tombNB = true, wholeUp(f.clk.Now().Add(30*time.Second))
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	if err := f.p.register(ctx); err != nil {
		t.Fatal(err)
	}
	f.reportTomb = false
	if err := f.p.register(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.p.mintWait(f.clk.Now()) {
		t.Fatal("an answer without the flag lifted the floor")
	}
	f.clk.Advance(30*time.Second + TombstoneSkew)
	if err := f.p.register(ctx); err != nil {
		t.Fatal(err)
	}
	if f.p.mintWait(f.clk.Now()) {
		t.Fatal("the floor outlived itself")
	}
}
