package peer

import (
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

// The service accepts a member's reconnect naming an earlier epoch of the
// connection, and refuses one naming no epoch of it.
func TestReconnectNamesEarlierEpoch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	first := m.KR.Current().ID()
	m.StartRekey()
	f.pump()
	if n := len(f.p.conns[cid].Epochs); n != 2 {
		t.Fatalf("%d epochs in the history", n)
	}
	before := f.p.conns[cid].kr.Current().ID()
	var unknown [suite.EpochIDSize]byte
	m.ReconnectNaming(unknown)
	f.pump()
	if f.p.conns[cid].kr.Current().ID() != before {
		t.Fatal("a reconnect naming no epoch of the connection was answered")
	}
	m.ReconnectNaming(first)
	f.pump()
	if got := f.p.conns[cid].kr.Current().ID(); got == before || got != m.KR.Current().ID() {
		t.Fatal("reconnect naming the first epoch refused")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// The history keeps a year of epochs, at most MaxEpochs.
func TestEpochHistoryPruned(t *testing.T) {
	c := &Connection{}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range MaxEpochs + 10 {
		c.recordEpoch([]byte{byte(i), byte(i >> 8), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, now.Add(time.Duration(i)*time.Hour))
	}
	if len(c.Epochs) != MaxEpochs || c.Epochs[0].ID[0] != 10 {
		t.Fatalf("%d epochs, first %d", len(c.Epochs), c.Epochs[0].ID[0])
	}
	c.recordEpoch(make([]byte, 16), now.Add(EpochHistory+time.Duration(MaxEpochs)*time.Hour))
	if c.Epochs[0].At.Before(now.Add(time.Duration(MaxEpochs) * time.Hour)) {
		t.Fatalf("an epoch older than a year kept: %v", c.Epochs[0].At)
	}
	var id [suite.EpochIDSize]byte
	copy(id[:], c.Epochs[3].ID)
	if !c.knownEpoch(handshake.EpochCtx(id)) || c.knownEpoch(handshake.EpochCtx([suite.EpochIDSize]byte{0xff, 0xff})) {
		t.Fatal("knownEpoch")
	}
}
