package peer

import (
	"context"
	"errors"
	"fmt"
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
	jti, n := cancelledInvite(t, f)
	waiting, err := f.p.CreateInvite(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	setRelayReg(t, f, relayReg{Registered: true, Attempted: true})
	f.reportTomb = true
	f.start()
	f.pump()
	if lostAlarms(f) != 0 || f.slept != 0 {
		t.Fatalf("%d alarms, waited %s", lostAlarms(f), f.slept)
	}
	// The unanswered attempt may have been a 201 (a data loss): the
	// revocations in force are sent again, with a warning, not an alarm;
	// a waiting invitation is left alone (nothing is known to be lost).
	if f.revokes[jti] <= n || !strings.Contains(f.logs.String(), "warning=relay_mailbox_maybe_lost") {
		t.Fatalf("revocations %d -> %d", n, f.revokes[jti])
	}
	if got, _ := f.p.Invite(waiting.ID); got.Withdrew || f.revokes[waiting.OpenJTI] != 0 {
		t.Fatalf("a waiting invitation withdrawn on a possible loss: %+v", got)
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

// A T far ahead of the clock raises relay_tombstone_ahead; the start waits
// at most maxStartWait and then runs, with mints still refused until it
// passes; it is not stored as judged. A new T that refuses no token relied
// on is logged as a possible loss of messages.
func TestTombReportLogs(t *testing.T) {
	f := newFixture(t)
	far := wholeUp(f.clk.Now().Add(24 * time.Hour))
	f.reportTomb, f.tombNB = true, far
	f.start()
	if !strings.Contains(f.logs.String(), "alarm=relay_tombstone_ahead") || f.slept != maxStartWait {
		t.Fatalf("waited %s", f.slept)
	}
	if _, err := f.p.CreateInvite(context.Background(), ""); !errors.Is(err, ErrMailboxRenewing) {
		t.Fatalf("an invitation before a far T: %v", err)
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.Tombstone.IsZero() {
		t.Fatalf("a far T stored as judged: %+v", r)
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

// A far T doesn't hide a real one after it: the real one is judged.
func TestTombReportFarThenReal(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.reportTomb, f.tombNB = true, wholeUp(f.clk.Now().Add(24*time.Hour))
	f.start()
	f.clk.Advance(5 * time.Second)
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.tombNB = wholeUp(f.clk.Now().Add(90 * time.Second))
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms: the real T was not judged", lostAlarms(f))
	}
}

// The floor comes back from the stored T after a restart: an answer
// without T then mints nothing before it.
func TestTombReportFloorStored(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	nb := wholeUp(f.clk.Now().Add(-60 * time.Second)) // judged: the tokens aren't older
	setRelayReg(t, f, relayReg{Registered: true, Tombstone: nb})
	f.reportTomb = true // and no T
	start := f.clk.Now()
	f.start()
	if want := nb.Add(TombstoneSkew).Sub(start); want <= 0 || f.slept != want {
		t.Fatalf("waited %s, want %s", f.slept, want)
	}
}

// After a data loss every unexpired open token is revoked, and a waiting
// invitation withdrawn: its one-shot token's use may not be known.
func TestTombReportDataLossOpenTokens(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	inv, err := f.p.CreateInvite(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.reportTomb = true
	f.start()
	f.pump()
	got, _ := f.p.Invite(inv.ID)
	if f.revokes[inv.OpenJTI] == 0 || !got.Withdrew {
		t.Fatalf("the waiting invitation: revoked %d, %+v", f.revokes[inv.OpenJTI], got)
	}
}

// failOutboxStore fails every write that stores an outbox entry.
type failOutboxStore struct {
	*MemStore
	fail bool
}

func (s *failOutboxStore) Apply(ctx context.Context, cs []Change) error {
	if s.fail {
		for _, c := range cs {
			if c.Kind == kindOutbox {
				return errors.New("store down")
			}
		}
	}
	return s.MemStore.Apply(ctx, cs)
}

// Revocations owed survive a write of them that fails: the mark stays
// until they are stored.
func TestTombReportDenyOwedFlushFails(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	jti, n := cancelledInvite(t, f)
	setRelayReg(t, f, relayReg{Registered: true, DenyOwed: true})
	f.reportTomb = true
	st := &failOutboxStore{MemStore: f.store, fail: true}
	f.storeWrap = st
	if err := f.startErr(); err == nil {
		t.Fatal("the failing write didn't fail the start")
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.DenyOwed {
		t.Fatalf("the mark cleared before the revocations were stored: %+v", r)
	}
	st.fail = false
	f.start()
	f.pump()
	if f.revokes[jti] <= n {
		t.Fatalf("revocations %d -> %d", n, f.revokes[jti])
	}
}

// While running, a collect answered mailbox_unknown registers again: on a
// relay that reports tombstones, a 201 with no T is a data loss (alarm,
// revocations sent again, no wait), not a lost mailbox's re-mint.
func TestTombReportWhileRunning(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	jti, n := cancelledInvite(t, f)
	before := issuedTo(m)
	f.reportTomb = true
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("a collect from a deleted mailbox succeeded")
	}
	if lostAlarms(f) != 1 || !strings.Contains(f.logs.String(), "tokens_kept=true") {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	if _, err := f.p.CreateInvite(context.Background(), ""); err != nil {
		t.Fatalf("an invitation after a data loss: %v", err)
	}
	f.tick()
	f.pump()
	if f.revokes[jti] <= n || issuedTo(m) != before {
		t.Fatalf("revocations %d -> %d, %d tokens re-minted", n, f.revokes[jti], issuedTo(m)-before)
	}
}

// Many revocations are all sent again. (MemStore takes any number of
// changes at once: a store's 100-change split isn't exercised here.)
func TestTombReportManyRevocations(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	var jtis []string
	counts := map[string]int{}
	for range 70 {
		jti, n := cancelledInvite(t, f)
		jtis, counts[jti] = append(jtis, jti), n
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.reportTomb = true
	f.start()
	f.pump()
	missed := 0
	for _, j := range jtis {
		if f.revokes[j] <= counts[j] {
			missed++
		}
	}
	if missed != 0 {
		t.Fatal(fmt.Sprint(missed, " of ", len(jtis), " revocations not sent again"))
	}
}

// Any T other than the one last judged is judged, an earlier one too (a
// relay instance whose tombstone differs): a token older than it is a loss.
func TestTombReportOtherTJudged(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.clk.Advance(2 * time.Hour)
	setRelayReg(t, f, relayReg{Registered: true, Tombstone: wholeUp(f.clk.Now().Add(-10 * time.Minute))})
	f.reportTomb, f.tombNB = true, wholeUp(f.clk.Now().Add(-time.Hour))
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms: an earlier T was not judged", lostAlarms(f))
	}
}

// While running, a collect's mailbox_unknown proves the loss: a
// re-registration that made the mailbox but whose answer was lost, then a
// 200 with no T, is a data loss (alarm), not a possible one.
func TestTombReportRunningUnanswered(t *testing.T) {
	f := newFixture(t)
	f.connect(f.member(10), "")
	jti, n := cancelledInvite(t, f)
	f.reportTomb = true
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.loseRegAnswer = true
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("a collect from a deleted mailbox succeeded")
	}
	if lostAlarms(f) != 0 {
		t.Fatalf("%d alarms before an answer", lostAlarms(f))
	}
	if _, err := f.p.Step(context.Background(), 0); err != nil { // the owed registration: a 200
		t.Fatal(err)
	}
	f.pump()
	if lostAlarms(f) != 1 || !strings.Contains(f.logs.String(), "tokens_kept=true") || f.revokes[jti] <= n {
		t.Fatalf("%d alarms, revocations %d -> %d", lostAlarms(f), n, f.revokes[jti])
	}
}

// A real loss with a T far ahead is labelled: whether tokens are refused
// is unknown. A registration once the recheck is due takes the relay's
// sane T: judged, and the far floor lifted.
func TestTombReportFarWithLossThenSane(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.reportTomb, f.tombNB = true, wholeUp(f.clk.Now().Add(24*time.Hour))
	f.start()
	if !strings.Contains(f.logs.String(), "tokens_kept=unknown") {
		t.Fatal("a loss with a far T not labelled unknown")
	}
	alarms := lostAlarms(f)
	f.tombNB = wholeUp(f.clk.Now().Add(-time.Minute)) // the relay is sane again; tokens are older
	f.clk.Advance(tombstoneAhead)
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if lostAlarms(f) != alarms+1 {
		t.Fatalf("%d alarms: the sane T was not judged", lostAlarms(f)-alarms)
	}
	f.clk.Advance(TombstoneSkew)
	if _, err := f.p.CreateInvite(context.Background(), ""); err != nil {
		t.Fatalf("the far floor not lifted: %v", err)
	}
}
