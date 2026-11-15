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
