package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// backup copies the store, as a table backup does.
func (f *fixture) backup() *MemStore {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	c := &MemStore{m: map[string]map[string]Record{}, Now: f.store.Now}
	for k, v := range f.store.m {
		c.m[k] = maps.Clone(v)
	}
	return c
}

// restore puts the backup back and restarts the service, with the restore
// marker when marked; it returns how often the marker was cleared.
func (f *fixture) restore(b *MemStore, marked bool) *int {
	f.t.Helper()
	cleared := new(int)
	f.store = b
	f.afterRestore = nil
	if marked {
		f.afterRestore = func(context.Context) error { *cleared++; return nil }
	}
	f.start()
	f.afterRestore = nil
	return cleared
}

// A restore past a rekey: the service's session is older than the
// member's, so nothing gets through, until the start after a marked
// restore reconnects, naming its last epoch, which the member still has in
// its history.
func TestReconnectAfterRestore(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey() // after the backup, as every day
	f.pump()

	f.restore(b, false)
	if f.signIn(m, cid) {
		t.Fatal("sign-in through a session the member left")
	}
	b2 := f.backup()
	cleared := f.restore(b2, true)
	if *cleared != 1 {
		t.Fatalf("marker cleared %d times", *cleared)
	}
	f.pump()
	if m.Reconnects != 1 {
		t.Fatalf("member answered %d reconnects", m.Reconnects)
	}
	c := f.p.conns[cid]
	if c.kr.Current().ID() != m.KR.Current().ID() || len(f.p.outgoing) != 0 {
		t.Fatal("no common session after the reconnect")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
	// The tokens the reconnect carried are stored: a restart keeps it.
	f.start()
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after a restart")
	}
}

// A restore past the member's identity rotation: the service names the
// old key; the member answers with the link since the epoch named, and
// the service follows it.
func TestReconnectAfterRestoreFollowsRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	r := m.RotateIdentity(40, false)
	f.pump()
	if !suite.EqualPublic(f.p.conns[cid].Peer.IK, ikOf(m.IK)) {
		t.Fatal("rotation not followed before the restore")
	}
	m.Rotations = []*handshake.Rotation{r} // since the epoch the service names
	f.restore(b, true)
	f.pump()
	c := f.p.conns[cid]
	if !suite.EqualPublic(c.Peer.IK, ikOf(m.IK)) || len(c.Chain) != 1 {
		t.Fatal("the member's rotation not followed by the reconnect")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A service vault answering a member keeps the exact ctx (§6.6, 0.72.0):
// a reconnect naming an earlier epoch of the connection is refused, one
// naming the last is taken.
func TestMemberReconnectNamesLastEpochOnly(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	first := m.KR.Current().ID()
	m.StartRekey()
	f.pump()
	before := f.p.conns[cid].kr.Current().ID()
	m.IgnoreStray = true
	m.ReconnectNaming(first)
	f.pump()
	if f.p.conns[cid].kr.Current().ID() != before {
		t.Fatal("a reconnect naming an earlier epoch was answered")
	}
	m.Reconnect()
	f.pump()
	if got := f.p.conns[cid].kr.Current().ID(); got == before || got != m.KR.Current().ID() {
		t.Fatal("reconnect naming the last epoch refused")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A member's reconnect changes nothing before its hs.fin: answering it
// leaves the held tokens and the state as they were (§6.6, 0.72.0).
func TestMemberReconnectDeferredToFin(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	held := f.p.conns[cid].Standing
	m.Reconnect()
	if _, err := f.p.Step(context.Background(), 0); err != nil { // the hs.init, answered
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; c.Standing != held || len(f.p.awaiting) != 1 {
		t.Fatal("the hs.init changed the connection before hs.fin")
	}
	f.pump()
	if c := f.p.conns[cid]; c.Standing == held || len(f.p.awaiting) != 0 {
		t.Fatal("hs.fin did not apply the reconnect")
	}
}

// A restart while the reconnect awaits its hs.resp, with a member link we
// followed: the stored initiator keeps that chain, so the member's answer
// (beginning with the link) is taken, with no new try.
func TestReconnectResumedAfterRestart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r := m.RotateIdentity(40, true) // the link waits for the next epoch
	m.SendRotation(r)               // identity.rotate arrives
	f.pump()
	if len(f.p.conns[cid].Chain) != 1 {
		t.Fatal("identity.rotate not followed")
	}
	b := f.backup() // before the rekey under the new key
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	f.start() // a deploy before the member answers: the stored hs.init stays
	if c := f.p.conns[cid]; !c.Reconnecting || c.ReconnectTries != 1 {
		t.Fatalf("reconnecting %v, tries %d", c.Reconnecting, c.ReconnectTries)
	}
	m.IgnoreRevoked = true // its answer to the replaced hs.init is refused
	f.pump()
	c := f.p.conns[cid]
	if c.Reconnecting || c.kr.Current().ID() != m.KR.Current().ID() || m.Reconnects != 1 {
		t.Fatalf("resumed reconnect: reconnecting %v, member answered %d", c.Reconnecting, m.Reconnects)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// While the reconnect is open nothing is sealed in the restored session,
// and a member's reconnect hs.init answered once is not answered again.
func TestReconnectWindowAndReplay(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	if _, err := f.p.Authenticate(context.Background(), cid, "Sign in", time.Minute); err == nil {
		t.Fatal("a challenge sealed in the restored session")
	}
	f.pump()
	if f.p.conns[cid].Reconnecting {
		t.Fatal("reconnect not completed")
	}

	m.Reconnect()
	f.pump()
	before := f.p.conns[cid].kr.Current().ID()
	if before != m.KR.Current().ID() {
		t.Fatal("member reconnect")
	}
	m.ResendReconnect() // the same hs.init again, as a relay replaying it
	f.pump()
	if f.p.conns[cid].kr.Current().ID() != before || len(f.p.awaiting) != 0 {
		t.Fatal("a replayed reconnect hs.init was answered")
	}
}

// A reconnect that cannot start (the member's reconnect token expired)
// fails at once: the connection is stale and needs a new invitation.
func TestReconnectNotPossible(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.clk.Advance(366 * 24 * time.Hour)
	f.restore(b, true)
	if c := f.p.conns[cid]; c.Reconnecting || c.ReconnectTries != 0 || c.State != StateStale {
		t.Fatalf("a reconnect on an expired token: reconnecting %v, state %s", c.Reconnecting, c.State)
	}
	for _, og := range f.p.outgoing {
		if og.ini.Purpose() == handshake.PurposeReconnect {
			t.Fatal("a reconnect on an expired token")
		}
	}
}

// A reconnect unanswered for a day raises reconnect_slow once and stays
// open (the member's vault may be locked); its answer is still taken.
func TestReconnectSlow(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	f.clk.Advance(ReconnectSlowAfter + time.Minute)
	f.tick()
	c := f.p.conns[cid]
	if !c.Reconnecting || !c.ReconnectSlow {
		t.Fatalf("reconnecting %v, slow %v", c.Reconnecting, c.ReconnectSlow)
	}
	f.pump() // the member's vault is unlocked
	if c := f.p.conns[cid]; c.Reconnecting || c.ReconnectSlow || !f.signIn(m, cid) {
		t.Fatal("the late answer was not taken")
	}
}

// A reconnect not completed in 7 days fails: the connection is stale, and
// the member's late answer is not taken.
func TestReconnectTimeout(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	f.clk.Advance(ReconnectTimeout + time.Minute)
	f.tick()
	c := f.p.conns[cid]
	if c.Reconnecting || c.State != StateStale || len(f.p.outgoing) != 0 {
		t.Fatalf("reconnecting %v, state %s, %d outgoing", c.Reconnecting, c.State, len(f.p.outgoing))
	}
	m.IgnoreRevoked, m.IgnoreStray = true, true
	f.pump()
	if f.p.conns[cid].State != StateStale {
		t.Fatal("a reconnect taken after its timeout")
	}
	if _, err := f.p.Authenticate(context.Background(), cid, "Sign in", time.Minute); err == nil {
		t.Fatal("a challenge on a stale connection")
	}
}

// Counters that come back with the backup (taken while an earlier
// reconnect was open) start again for the new restore.
func TestReconnectCountersPerRestore(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	c.Reconnecting, c.ReconnectTries, c.ReconnectSince = true, MaxReconnectTries, f.clk.Now().Add(-30*24*time.Hour)
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := f.backup()
	f.restore(b, true)
	if c := f.p.conns[cid]; !c.Reconnecting || c.ReconnectTries != 1 || c.State != StateActive {
		t.Fatalf("reconnecting %v, tries %d, state %s", c.Reconnecting, c.ReconnectTries, c.State)
	}
	f.pump()
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// The member's own reconnect, completed while ours is open, settles it.
func TestReconnectCrossing(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.restore(b, true) // nothing changed since the backup: the epochs match
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Reconnect()
	f.pump()
	c := f.p.conns[cid]
	if c.Reconnecting || c.State != StateActive || c.kr.Current().ID() != m.KR.Current().ID() || len(f.p.outgoing) != 0 {
		t.Fatalf("reconnecting %v, state %s", c.Reconnecting, c.State)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the crossing reconnects")
	}
}

// A restart keeps the open reconnect (§6.6, 0.72.1): no new hs.init, no
// try used, and the member's answer to the stored one completes it.
func TestReconnectRestartKeepsHsInit(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	var th1 []byte
	for _, og := range f.p.outgoing {
		th1 = og.Th1
	}
	f.start()
	if len(f.p.outgoing) != 1 || f.p.conns[cid].ReconnectTries != 1 {
		t.Fatalf("%d outgoing, tries %d", len(f.p.outgoing), f.p.conns[cid].ReconnectTries)
	}
	for _, og := range f.p.outgoing {
		if !bytes.Equal(og.Th1, th1) {
			t.Fatal("a new hs.init at the restart")
		}
	}
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || m.Reconnects != 1 || !f.signIn(m, cid) {
		t.Fatalf("reconnecting %v, member answered %d", c.Reconnecting, m.Reconnects)
	}
}

// Having yielded to a member's reconnect, a restart starts nothing; the
// member's hs.fin settles it.
func TestReconnectRestartWhileYielded(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.restore(b, true) // no rekey since: the member's own reconnect names our epoch
	m.Reconnect()
	m.IgnoreStray, m.IgnoreRevoked = true, true
	if _, err := f.p.Step(context.Background(), 0); err != nil { // answers the member's, yields
		t.Fatal(err)
	}
	f.start()
	if len(f.p.outgoing) != 0 || f.p.conns[cid].ReconnectTries != 1 {
		t.Fatalf("%d outgoing, tries %d after a restart while yielded", len(f.p.outgoing), f.p.conns[cid].ReconnectTries)
	}
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || !f.signIn(m, cid) {
		t.Fatal("the member's reconnect did not settle it")
	}
}

// The member answers our reconnect before ours yields to its own (its
// hs.init is ahead of its hs.resp in our mailbox): the hs.resp to the
// abandoned hs.init is acked and audited, not left for redelivery, and
// the member's reconnect settles it.
func TestReconnectLateRespAcked(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.restore(b, true) // our hs.init goes out
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Reconnect() // the member's, first in our mailbox
	m.Step()      // then its hs.resp to ours
	f.step()
	f.lateRespAcked()
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || c.State != StateActive || !f.signIn(m, cid) {
		t.Fatal("the member's reconnect did not settle it")
	}
}

// lateRespAcked checks that the member's hs.resp to our abandoned hs.init
// was audited and acked: nothing is left in the service's mailbox.
func (f *fixture) lateRespAcked() {
	f.t.Helper()
	if !strings.Contains(f.logs.String(), "reason=unknown_kid") {
		f.t.Fatal("the late hs.resp was not audited")
	}
	f.clk.Advance(time.Hour) // past any lease
	if msgs, err := f.sv.Collect(context.Background(), 0, 32); err != nil || len(msgs) != 0 {
		f.t.Fatalf("%d messages left unacked (%v)", len(msgs), err)
	}
}

// A member's reconnect we yielded to whose hs.fin does not come in
// YieldWait: a new try of ours.
func TestReconnectYieldExpires(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.restore(b, true)
	m.Reconnect()
	m.IgnoreStray, m.IgnoreRevoked = true, true
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(YieldWait + time.Minute)
	f.tick()
	if c := f.p.conns[cid]; !c.Reconnecting || c.ReconnectTries != 2 || len(f.p.outgoing) != 1 || len(f.p.awaiting) != 0 {
		t.Fatalf("reconnecting %v, tries %d, %d outgoing, %d awaiting", c.Reconnecting, c.ReconnectTries, len(f.p.outgoing), len(f.p.awaiting))
	}
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || c.State != StateActive || !f.signIn(m, cid) {
		t.Fatal("the new try did not complete")
	}
}

// step runs the service once (collect, handle, drain), without the members.
func (f *fixture) step() {
	f.t.Helper()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		f.t.Fatal(err)
	}
}

// yielded restores b (marked), lets the member's reconnect in and has the
// service answer it, yielding its own; deposits to the member's mailbox
// fail with hold while set. It returns the connection.
func (f *fixture) yielded(m *peertest.Member, cid string, b *MemStore) *Connection {
	f.t.Helper()
	f.restore(b, true)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Reconnect()
	f.step()
	c := f.p.conns[cid]
	if !c.Reconnecting || len(f.p.outgoing) != 0 || len(f.p.awaiting) != 1 {
		f.t.Fatalf("not yielded: reconnecting %v, %d outgoing, %d awaiting", c.Reconnecting, len(f.p.outgoing), len(f.p.awaiting))
	}
	return c
}

// respEntry is the outbox entry of the hs.resp to a member's reconnect:
// a deposit on a token of the member's other than the reconnect token.
func (f *fixture) respEntry(c *Connection) *outboxEntry {
	for _, e := range f.p.outbox {
		if e.ConnID == c.ID && e.Op == opDeposit && e.Token != "" && e.Token != c.Reconnect.Token {
			return e
		}
	}
	return nil
}

var errUnavailable = &relayclient.Error{Status: 503, Code: "unavailable"}

// Two reconnects of the member while ours yields: when the first one's
// hs.fin has not come in YieldWait, the second's is still awaited, so no
// new try goes out (§6.6, 0.72.1); the second settles it.
func TestReconnectYieldWaitsForTheOther(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.yielded(m, cid, b)
	f.clk.Advance(30 * time.Minute)
	m.Reconnect()
	f.step()
	if len(f.p.awaiting) != 2 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	f.clk.Advance(YieldWait - 30*time.Minute + time.Minute) // the first expires
	f.tick()
	c := f.p.conns[cid]
	if !c.Reconnecting || len(f.p.outgoing) != 0 || len(f.p.awaiting) != 1 || c.ReconnectTries != 1 {
		t.Fatalf("reconnecting %v, %d outgoing, %d awaiting, tries %d", c.Reconnecting, len(f.p.outgoing), len(f.p.awaiting), c.ReconnectTries)
	}
	f.pump()
	if c = f.p.conns[cid]; c.Reconnecting || c.State != StateActive || !f.signIn(m, cid) {
		t.Fatal("the member's second reconnect did not settle it")
	}
}

// A member's reconnect from before the backup, awaiting its hs.fin, that
// expires while our reconnect is in flight: ours is left as it is (no new
// hs.init, no try used).
func TestReconnectMemberAwaitingExpiresWhileOursInFlight(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Reconnect()
	f.step() // answered: awaiting its hs.fin, which never comes
	f.clk.Advance(HandshakeTTL - time.Hour)
	b := f.backup()
	f.restore(b, true)
	var th1 []byte
	for _, og := range f.p.outgoing {
		th1 = og.Th1
	}
	if len(f.p.outgoing) != 1 || len(f.p.awaiting) != 1 {
		t.Fatalf("%d outgoing, %d awaiting", len(f.p.outgoing), len(f.p.awaiting))
	}
	f.clk.Advance(2 * time.Hour) // the member's expires; ours is an hour old
	f.tick()
	c := f.p.conns[cid]
	if len(f.p.awaiting) != 0 || len(f.p.outgoing) != 1 || c.ReconnectTries != 1 || !c.Reconnecting {
		t.Fatalf("%d awaiting, %d outgoing, tries %d, reconnecting %v", len(f.p.awaiting), len(f.p.outgoing), c.ReconnectTries, c.Reconnecting)
	}
	for _, og := range f.p.outgoing {
		if !bytes.Equal(og.Th1, th1) {
			t.Fatal("our hs.init in flight was replaced")
		}
	}
}

// A yield that expires before its hs.resp was deposited: the hs.resp,
// answering a handshake that is over, is not sent.
func TestReconnectYieldExpiresDropsItsResp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	mb := ""
	f.failDeposit = func(mailbox, _ string) error {
		if mailbox == mb {
			return errUnavailable
		}
		return nil
	}
	mb = f.p.conns[cid].Peer.Relay.Mailbox
	c := f.yielded(m, cid, b)
	resp := f.respEntry(c)
	if resp == nil {
		t.Fatal("no hs.resp waiting")
	}
	f.clk.Advance(YieldWait + time.Minute)
	f.tick()
	if f.respEntry(f.p.conns[cid]) != nil && f.respEntry(f.p.conns[cid]).Token == resp.Token {
		t.Fatal("the hs.resp of the expired handshake is still queued")
	}
	if c = f.p.conns[cid]; c.ReconnectTries != 2 || len(f.p.outgoing) != 1 {
		t.Fatalf("tries %d, %d outgoing", c.ReconnectTries, len(f.p.outgoing))
	}
	f.failDeposit = nil
	f.clk.Advance(time.Hour) // past the backoff of the held deposits
	f.pump()
	if c = f.p.conns[cid]; c.Reconnecting || !f.signIn(m, cid) {
		t.Fatal("the new try did not complete")
	}
}

// A deposit that ends a handshake during a drain (the hs.resp of a
// member's reconnect we yielded to, refused for good) starts a new try,
// which changes the outbox: every other entry is still sent exactly once.
func TestOutboxChangedDuringDrain(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	mb, refuse := "", false
	f.failDeposit = func(mailbox, token string) error {
		switch {
		case mailbox != mb:
			return nil
		case refuse && token != f.p.conns[cid].Reconnect.Token:
			return &relayclient.Error{Status: 401, Code: codeTokenRevoked}
		case !refuse:
			return errUnavailable
		}
		return nil
	}
	mb = f.p.conns[cid].Peer.Relay.Mailbox
	c := f.yielded(m, cid, b)
	if f.respEntry(c) == nil {
		t.Fatal("no hs.resp waiting")
	}
	// Behind it: session messages (dropped by the new try) and an entry
	// the try leaves alone.
	now := f.clk.Now()
	for i := range 6 {
		f.p.queueDeposit(&outboxEntry{ConnID: cid, Mailbox: mb, Payload: []byte{byte(i)}}, now)
	}
	f.p.queueRevoke("jti-x", now)
	refuse = true
	f.clk.Advance(time.Hour) // past the hs.resp's backoff
	// Room to grow in place, as a long-running outbox has: a change made
	// during the drain then lands in the array the drain is reading.
	f.p.outbox = slices.Grow(f.p.outbox, 16)
	f.step()
	if n := f.revokes["jti-x"]; n != 1 {
		t.Fatalf("the entry behind was sent %d times", n)
	}
	if c = f.p.conns[cid]; c.ReconnectTries != 2 || len(f.p.outgoing) != 1 || len(f.p.awaiting) != 0 {
		t.Fatalf("tries %d, %d outgoing, %d awaiting", c.ReconnectTries, len(f.p.outgoing), len(f.p.awaiting))
	}
}

// A member's reconnect whose stored record no longer applies at its
// hs.fin (unreadable rotation links): with nothing else of the reconnect
// open, a new try goes out instead of the reconnect staying open.
func TestReconnectRecordBadRetries(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	f.yielded(m, cid, b)
	for _, aw := range f.p.awaiting {
		aw.Reconnect.Links = []json.RawMessage{json.RawMessage(`"x"`)}
	}
	f.pump()
	if !strings.Contains(f.logs.String(), "reason=reconnect_record_bad") {
		t.Fatal("no reconnect_record_bad")
	}
	// The restore's try, then the one after the bad record.
	if n := strings.Count(f.logs.String(), `msg="reconnect started"`); n != 2 {
		t.Fatalf("%d reconnects started", n)
	}
	if c := f.p.conns[cid]; c.Reconnecting || c.State != StateActive || !f.signIn(m, cid) {
		t.Fatalf("reconnecting %v, state %s", c.Reconnecting, c.State)
	}
}
