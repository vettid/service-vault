package peer

import (
	"bytes"
	"context"
	"maps"
	"testing"
	"time"

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
