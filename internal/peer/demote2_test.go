package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// eid is a test epoch id.
func eid(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }

// chainOf2 makes the connection follow A->B and B->C (no position: no
// demotion) and returns the three keys and both links.
func chainOf2(t *testing.T, f *fixture, m *peertest.Member, c *Connection) (a, b, cc ed25519.PublicKey, ab, bc *handshake.Rotation) {
	t.Helper()
	a = m.IK.Public().(ed25519.PublicKey)
	ab = m.RotateIdentity(40, true)
	bc = m.RotateIdentity(50, true)
	f.p.followRotation(c, bc.NewIK, bc.NewKEM, []*handshake.Rotation{ab, bc}, nil, false)
	return a, ab.NewIK, bc.NewIK, ab, bc
}

// Strict F1 applies only while the current epoch is signed by the link's
// old key; it takes later epochs signed by that key or an ancestor, never
// destroyed ones; the reconnect names E even when a newer usable epoch
// exists (E is not newestUsable's choice).
func TestStrictF1Scope(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a, b, cc, _, bc := chainOf2(t, f, m, c)
	// The current epoch is signed by A, an ancestor of the link's old key B:
	// no strict F1 for B->C.
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: a}, {ID: eid(2), Signer: a}}
	c.LastEpochID = eid(2)
	if !f.p.f1Demote(c, []*handshake.Rotation{bc}, eid(1), false, f.clk.Now()) || c.Epochs[1].Demoted {
		t.Fatal("strict F1 ran while the current epoch is not signed by the link's old key")
	}
	// Current signed by B: the later epochs signed by B or A are demoted, a
	// destroyed one is left, one signed by C is not taken.
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: b}, {ID: eid(2), Signer: cc}, {ID: eid(3), Signer: a, Destroyed: true}, {ID: eid(5), Signer: a}, {ID: eid(4), Signer: b}}
	c.LastEpochID = eid(4)
	if !f.p.f1Demote(c, []*handshake.Rotation{bc}, eid(1), false, f.clk.Now()) {
		t.Fatal("suspended")
	}
	if c.Epochs[0].Demoted || c.Epochs[1].Demoted || c.Epochs[2].Demoted || !c.Epochs[3].Demoted || !c.Epochs[4].Demoted {
		t.Fatalf("demoted: %v %v %v %v %v", c.Epochs[0].Demoted, c.Epochs[1].Demoted, c.Epochs[2].Demoted, c.Epochs[3].Demoted, c.Epochs[4].Demoted)
	}
	// With restart, the reconnect names E, not the newest usable epoch.
	c.Epochs[3].Demoted, c.Epochs[4].Demoted = false, false
	f.p.f1Demote(c, []*handshake.Rotation{bc}, eid(1), true, f.clk.Now())
	if !bytes.Equal(c.reconnectTarget(), eid(1)) || bytes.Equal(c.newestUsable(), eid(1)) {
		t.Fatalf("target %x, newest usable %x", c.reconnectTarget(), c.newestUsable())
	}
}

// newestUsable skips demoted and destroyed epochs; the strict F1 target
// counts only while the current epoch is demoted, and is cleared when an
// epoch becomes current.
func TestReconnectTargetLifecycle(t *testing.T) {
	c := &Connection{Epochs: []EpochMeta{{ID: eid(1)}, {ID: eid(2), Destroyed: true}, {ID: eid(3), Demoted: true}}, LastEpochID: eid(3)}
	if !bytes.Equal(c.newestUsable(), eid(1)) {
		t.Fatalf("newest usable %x", c.newestUsable())
	}
	c.ReconnectNamed = eid(2)
	if !bytes.Equal(c.reconnectTarget(), eid(2)) {
		t.Fatal("the strict F1 target is not used while demoted")
	}
	c.Epochs = append(c.Epochs, EpochMeta{ID: eid(4)})
	c.LastEpochID = eid(4)
	if !bytes.Equal(c.reconnectTarget(), eid(4)) {
		t.Fatalf("a stale strict F1 target named %x after a new current epoch", c.reconnectTarget())
	}
	f := newFixture(t)
	f.p.recordActivated(c, eid(5), false, epochPos{}, time.Now())
	if c.ReconnectNamed != nil {
		t.Fatal("not cleared when an epoch became current")
	}
}

// K9 judges only abandoned epochs established after E whose hs.resp was
// signed by the link's old key or an ancestor, also when every link of
// the identity.rotate was already followed.
func TestK9Scope(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a, b, cc, ab, bc := chainOf2(t, f, m, c)
	t0 := f.clk.Now()
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000005"}}
	c.LastEpochID = eid(1)
	c.AbandonedMeta = []AbandonedEpoch{
		{ID: eid(2), At: t0, Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000003"},  // before E
		{ID: eid(3), At: t0, Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000007"},  // after E, signed by A
		{ID: eid(4), At: t0, Signer: cc, EstAt: t0, EstMsg: "01M00000000000000000000008"}, // after E, signed by C
		{ID: eid(5), At: t0, Signer: b, EstAt: t0, EstMsg: "01M00000000000000000000009"},  // after E, signed by B
	}
	// Every link already followed: ignored, K9 still judged.
	f.p.identityRotate(c, peertest.RotateBody(bc, ab, bc), eid(1), f.clk.Now())
	got := []bool{c.AbandonedMeta[0].Ended, c.AbandonedMeta[1].Ended, c.AbandonedMeta[2].Ended, c.AbandonedMeta[3].Ended}
	if c.State != StateActive || got[0] || !got[1] || got[2] || !got[3] {
		t.Fatalf("state %s, ended %v", c.State, got)
	}
}

// Strict F1 at a member reconnect's hs.fin (0.90.4): E is the epoch it
// named. The copy's E2 is demoted (then destroyed by rule E).
func TestStrictF1AtReconnectFin(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	m.RotateIdentity(40, true)
	m.Reconnect() // names E1, the member's current and the service's confirmed epoch
	f.pump()
	if e2 := c.epochMeta(id2[:]); c.State != StateActive || e2 == nil || !e2.Demoted {
		t.Fatalf("state %s, E2 demoted %v", c.State, e2 != nil && e2.Demoted)
	}
}

// K5: the reconnect after a demotion does not start while an epoch of our
// own is pending.
func TestDemotedWaitsForPending(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.p.startRekey(c, f.clk.Now())
	f.p.drainOutbox(context.Background())
	m.Step()
	f.stepP()
	if c.Pending == nil {
		t.Fatal("no pending epoch")
	}
	demoteCurrent(c, f.clk.Now())
	f.p.tickDemoted(c, f.clk.Now())
	if reconnectOutgoing(f, cid) || c.Pending == nil || c.State != StateActive {
		t.Fatal("the reconnect started over our pending epoch")
	}
}

// Demotion by position skips a record from before positions were kept.
func TestDemotionSkipsNoPosition(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	e1, e2 := &c.Epochs[0], c.epochMeta(id2[:])
	e2.EstAt, e2.EstMsg = time.Time{}, ""
	r := m.RotateIdentity(40, true)
	f.p.relayAt, f.p.msgID = e1.EstAt, e1.EstMsg
	f.p.followRotation(c, r.NewIK, r.NewKEM, []*handshake.Rotation{r}, nil, false)
	f.p.relayAt, f.p.msgID = time.Time{}, ""
	if e2.Demoted || c.State != StateActive {
		t.Fatal("a record without a position was demoted")
	}
}

// Abandoned records go with their receive keys.
func TestAbandonedPruned(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	c.AbandonedMeta = []AbandonedEpoch{{ID: eid(1), At: f.clk.Now()}}
	f.p.pruneAbandoned(c, f.clk.Now().Add(time.Hour))
	if len(c.AbandonedMeta) != 1 {
		t.Fatal("pruned too soon")
	}
	f.p.pruneAbandoned(c, f.clk.Now().Add(handshake.ReceiveKeyRetention+storeMargin+time.Hour))
	if len(c.AbandonedMeta) != 0 {
		t.Fatal("not pruned")
	}
}

// Positions compare by msg_id in the one mailbox, whatever deposited_at
// says; deposited_at only when an id is missing.
func TestPosAfterByMsgID(t *testing.T) {
	t0 := time.Now()
	if posAfter(t0.Add(time.Hour), "01A", t0, "01B") || !posAfter(t0, "01B", t0.Add(time.Hour), "01A") {
		t.Fatal("not by msg_id")
	}
	if !posAfter(t0.Add(time.Second), "", t0, "01A") {
		t.Fatal("no deposited_at fallback")
	}
}

// K9 for an identity.rotate that traveled under one of our abandoned
// epochs (E): E's position comes from its record; the later abandoned
// epoch signed by the old key is ended; E itself, whose flag the message
// just set, is not judged (it would suspend an honest member).
func TestK9UnderAbandonedEpoch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a, _, _, ab, bc := chainOf2(t, f, m, c)
	t0 := f.clk.Now()
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000005"}}
	c.LastEpochID = eid(1)
	c.AbandonedMeta = []AbandonedEpoch{
		{ID: eid(2), At: t0, Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000006", Received: true}, // E
		{ID: eid(3), At: t0, Signer: a, EstAt: t0, EstMsg: "01M00000000000000000000007"},                 // after E
	}
	f.p.identityRotate(c, peertest.RotateBody(bc, ab, bc), eid(2), f.clk.Now())
	if c.State != StateActive || c.AbandonedMeta[0].Ended || !c.AbandonedMeta[1].Ended {
		t.Fatalf("state %s, E ended %v, later ended %v", c.State, c.AbandonedMeta[0].Ended, c.AbandonedMeta[1].Ended)
	}
}
