package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// abandonedThenCopy is the blind pair's H1 sequence (GC #10088): the
// service's own rekey makes X pending; an old copy holding E1 rekeys before
// the member's first message under X, so X is abandoned at the crossing
// and the copy's Ec (signed by the member's key A) is installed; the copy
// sends under Ec (its flag is set). The member then takes our hs.fin and is
// on X. It returns X's id.
func abandonedThenCopy(t *testing.T, f *fixture, m *peertest.Member, cid string, used bool) []byte {
	t.Helper()
	c := f.p.conns[cid]
	s1 := m.SaveEpoch()
	f.p.startRekey(c, f.clk.Now())
	f.p.drainOutbox(context.Background())
	m.Step()  // the member answers our rekey
	f.stepP() // X pending, our hs.fin deposited
	if c.Pending == nil {
		t.Fatal("no pending epoch")
	}
	x := bytes.Clone(c.Pending.ID)
	f.clk.Advance(time.Second)
	ini := m.RekeyInitUnder(s1) // the old copy, under E1
	f.stepP()                   // X abandoned (crossing), the copy answered
	ec := m.FinishRekey(ini)
	if ec == nil {
		t.Fatal("no hs.resp for the copy")
	}
	f.stepP() // Ec installed
	if used {
		raw, err := ec.Seal(&envelope.Inner{ID: m.NewID(), Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		m.DepositTo(m.SvcStand, raw) // the copy uses Ec
		f.stepP()
	}
	id := ec.ID()
	if e := c.epochMeta(id[:]); e == nil || e.Received != used || !bytes.Equal(c.LastEpochID, id[:]) || c.abandonedMeta(x) == nil {
		t.Fatal("setup: Ec is not current with the expected flag, or X is not abandoned")
	}
	m.Step() // the member takes our hs.fin: X is current on its side
	return x
}

// H1, identity.rotate: the member's identity.rotate under X (abandoned at
// the service) runs strict F1 with E = X: Ec, later and signed by the old
// key, has its flag set: suspended.
func TestStrictF1AbandonedEIdentityRotate(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	abandonedThenCopy(t, f, m, cid, true)
	r := m.RotateIdentity(40, true)
	m.SendRotations(r) // under X, the member's current
	f.stepP()
	if c := f.p.conns[cid]; c.State != StateSuspended {
		t.Fatalf("state %s: the copy's epoch stayed current", c.State)
	}
}

// H1, a member reconnect naming X: a reconnect may name an abandoned epoch
// while no newer epoch is confirmed (so here the copy has not used Ec yet).
// At its hs.fin strict F1 runs with E = X: Ec, later and signed by the old
// key, is demoted (its flag clear); also for an answer stored without its
// signer (the older record's path).
func TestStrictF1AbandonedEReconnectFin(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		abandonedThenCopy(t, f, m, cid, false)
		c := f.p.conns[cid]
		ec := bytes.Clone(c.LastEpochID)
		m.RotateIdentity(40, true)
		m.Reconnect() // names X
		f.stepP()     // answered
		if legacy {
			for _, aw := range f.p.awaiting {
				if aw.Reconnect != nil {
					aw.Reconnect.Signer = nil // as stored before signers were kept
				}
			}
		}
		f.pump()
		if e := c.epochMeta(ec); c.State != StateActive || e == nil || !e.Demoted || bytes.Equal(c.LastEpochID, ec) {
			t.Fatalf("legacy %v: state %s, Ec demoted %v", legacy, c.State, e != nil && e.Demoted)
		}
	}
}

// f1Demote with E an abandoned epoch, at the unit: the later epochs (by
// position) signed by the old key are demoted, flag clear; a current
// epoch established before E is left.
func TestStrictF1AbandonedEUnit(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a, b, _, ab, _ := chainOf2(t, f, m, c)
	t0 := f.clk.Now()
	pos := func(n byte) string { return "01M0000000000000000000000" + string('0'+n) }
	c.AbandonedMeta = []AbandonedEpoch{{ID: eid(9), At: t0, Signer: a, EstAt: t0, EstMsg: pos(5)}}
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: a, EstAt: t0, EstMsg: pos(3)}, {ID: eid(2), Signer: a, EstAt: t0, EstMsg: pos(7)}}
	c.LastEpochID = eid(2)
	_ = b
	if !f.p.f1Demote(c, []*handshake.Rotation{ab}, eid(9), false, f.clk.Now()) || c.Epochs[0].Demoted || !c.Epochs[1].Demoted {
		t.Fatalf("demoted %v %v", c.Epochs[0].Demoted, c.Epochs[1].Demoted)
	}
	// The current epoch established before E: not later, nothing.
	c.Epochs[1].Demoted = false
	c.AbandonedMeta[0].EstMsg = pos(8)
	f.p.f1Demote(c, []*handshake.Rotation{ab}, eid(9), false, f.clk.Now())
	if c.Epochs[1].Demoted {
		t.Fatal("demoted although the current epoch is not later than E")
	}
}

// L1: reconnect tries count per named epoch: three tries spent naming one
// epoch do not keep the reconnect after a demotion, naming another, from
// starting.
func TestReconnectTriesPerNamedEpoch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, _ = copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	c.Reconnecting, c.ReconnectTries, c.ReconnectTriesFor = true, MaxReconnectTries, bytes.Clone(c.LastEpochID)
	demoteCurrent(c, f.clk.Now())
	f.p.reconnectIfIdle(c, f.clk.Now())
	if c.State != StateActive || !reconnectOutgoing(f, cid) {
		t.Fatalf("state %s: the tries for another epoch stopped the reconnect naming E1", c.State)
	}
}

// L2: removing a connection whose current epoch is demoted seals nothing
// under it (no connection.removed); the removal goes on.
func TestRemoveWhileDemotedSendsNothing(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == cid })
	demoteCurrent(c, f.clk.Now())
	deposits := func() int {
		n := 0
		for _, e := range f.p.outbox {
			if e.Op == opDeposit {
				n++
			}
		}
		return n
	}
	n := deposits()
	f.p.removeConnection(c, "out", f.clk.Now())
	if deposits() != n {
		t.Fatal("a connection.removed was sealed under a demoted epoch")
	}
	if _, ok := f.p.conns[cid]; ok {
		t.Fatal("not removed")
	}
}

// L3 (RK1): the reconnect after a demotion ends our open answers to the
// member's rekeys in the write that starts it.
func TestDemotedReconnectEndsRekeyAnswers(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	m.StartRekey()
	f.stepP() // answered, awaiting hs.fin
	answers := func() int {
		n := 0
		for _, aw := range f.p.awaiting {
			if aw.ConnID == cid && aw.Purpose == handshake.PurposeRekey {
				n++
			}
		}
		return n
	}
	if answers() != 1 {
		t.Fatal("setup: no answer")
	}
	// Another usable epoch to name.
	c.Epochs = append([]EpochMeta{{ID: eid(1)}}, c.Epochs...)
	demoteCurrent(c, f.clk.Now())
	f.p.restartAfterDemotion(c, f.clk.Now())
	if !reconnectOutgoing(f, cid) || answers() != 0 {
		t.Fatalf("reconnect %v, answers %d", reconnectOutgoing(f, cid), answers())
	}
}

// Our own epoch records where it was established (its hs.resp) and the key
// that signed it, at its confirmation.
func TestOwnEpochPositionRecorded(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.p.startRekey(c, f.clk.Now())
	f.pump()
	e := c.epochMeta(c.LastEpochID)
	if e == nil || !e.Mine || e.EstMsg == "" || !bytes.Equal(e.Signer, m.IK.Public().(ed25519.PublicKey)) {
		t.Fatalf("%+v", e)
	}
}

// With no epoch left that is neither demoted nor destroyed (and nothing of
// ours open or pending), the connection goes stale.
func TestNoUsableEpochGoesStale(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	for i := range c.Epochs {
		c.Epochs[i].Demoted = true
	}
	f.p.restartAfterDemotion(c, f.clk.Now())
	if c.State != StateStale || reconnectOutgoing(f, cid) {
		t.Fatalf("state %s", c.State)
	}
}

// Our reconnect open when strict F1 demotes the current epoch: one new try
// starts (naming E), not two (H5's restart is skipped).
func TestF1WithOwnReconnectStartsOnce(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	s1, _ := copyEpoch(t, f, m, cid)
	f.beginReconnectNow(cid)
	n := strings.Count(f.logs.String(), `msg="reconnect started"`)
	r := m.RotateIdentity(40, true)
	sendUnder(t, m, s1, TypeIdentityRotate, peertest.RotateBody(r), f.clk.Now())
	f.stepP()
	if got := strings.Count(f.logs.String(), `msg="reconnect started"`) - n; got != 1 {
		t.Fatalf("%d reconnects started", got)
	}
}

// Housekeeping prunes abandoned records whose receive keys are gone.
func TestHousekeepingPrunesAbandoned(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	c.AbandonedMeta = []AbandonedEpoch{{ID: eid(1), At: f.clk.Now().Add(-handshake.ReceiveKeyRetention - storeMargin - time.Hour)}}
	f.p.housekeeping(f.clk.Now())
	if len(c.AbandonedMeta) != 0 {
		t.Fatal("not pruned")
	}
}

// A by-position demotion of the current epoch from an identity.rotate
// (restart) starts the reconnect at once, naming the newest usable epoch.
func TestByPositionRestartsAtOnce(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	e1 := &c.Epochs[0]
	r := m.RotateIdentity(40, true)
	f.p.relayAt, f.p.msgID = e1.EstAt, e1.EstMsg
	f.p.followRotation(c, r.NewIK, r.NewKEM, []*handshake.Rotation{r}, nil, true)
	f.p.relayAt, f.p.msgID = time.Time{}, ""
	if e2 := c.epochMeta(id2[:]); !e2.Demoted || !reconnectOutgoing(f, cid) {
		t.Fatal("no reconnect at once after the by-position demotion")
	}
}
