package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// sendUnder deposits a message from the member sealed under a saved epoch
// (the member's side still on that epoch, or an old copy holding it).
func sendUnder(t *testing.T, m *peertest.Member, s handshake.EpochState, typ string, body []byte, ts time.Time) {
	t.Helper()
	ep, err := handshake.ImportEpoch(s)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ep.Seal(&envelope.Inner{ID: m.NewID(), Type: typ, TS: ts, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	m.DepositTo(m.SvcStand, raw)
}

func (f *fixture) stepP() {
	f.t.Helper()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		f.t.Fatal(err)
	}
}

// copyEpoch has an old copy of the member, holding its keys and its
// current epoch E1, rekey with the service: the service activates E2
// (signed by the member's current key A) at the copy's hs.fin. The member
// itself stays on E1. It returns E1's saved state and E2.
func copyEpoch(t *testing.T, f *fixture, m *peertest.Member, cid string) (handshake.EpochState, *handshake.Epoch) {
	t.Helper()
	s1 := m.SaveEpoch()
	ini := m.RekeyInitUnder(s1)
	f.stepP()
	ep2 := m.FinishRekey(ini)
	if ep2 == nil {
		t.Fatal("no hs.resp")
	}
	f.stepP()
	c := f.p.conns[cid]
	if id := ep2.ID(); !bytes.Equal(c.LastEpochID, id[:]) {
		t.Fatal("the copy's epoch is not current")
	}
	return s1, ep2
}

// R29-K7, strict F1: the member rotates A->B and sends identity.rotate
// under E1, while the service's current epoch E2, after E1, is signed by A
// (an old copy's). E2 is demoted, its flag being clear; the service sends
// the member nothing but the handshake and reconnects naming E1, which the
// member accepts; what waited is then sealed under the new epoch and
// delivered.
func TestStrictF1DemotesAndReconnectsNamingE(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	s1, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	r := m.RotateIdentity(40, true) // A->B, on the member's side, still on E1
	sendUnder(t, m, s1, TypeIdentityRotate, peertest.RotateBody(r), f.clk.Now())
	f.stepP()
	e2 := c.epochMeta(id2[:])
	if c.State != StateActive || e2 == nil || !e2.Demoted || !c.currentDemoted() {
		t.Fatalf("state %s, E2 demoted %v", c.State, e2 != nil && e2.Demoted)
	}
	var named []byte
	for _, og := range f.p.outgoing {
		if og.ConnID == cid && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
			named = og.Named
		}
	}
	if !bytes.Equal(named, s1.ID) {
		t.Fatalf("the reconnect names %x, want E1", named)
	}
	// A message to the member made now waits (TestHeldWhileDemoted covers
	// the hold itself) and is delivered under the new epoch.
	id := f.p.sendTo(c, "test.note", []byte(`{}`), f.clk.Now())
	if id == "" {
		t.Fatal("not queued")
	}
	f.pump() // the member answers the reconnect, confirms, and receives what waited
	if c.currentDemoted() || c.State != StateActive {
		t.Fatalf("still demoted: state %s", c.State)
	}
	got := false
	for _, in := range m.Received("test.note") {
		got = got || in.ID == id
	}
	if !got {
		t.Fatal("the held message was not delivered under the new epoch")
	}
}

// Strict F1 with E2's received flag set (the copy used E2): suspended.
func TestStrictF1FlagSetSuspends(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	s1, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	raw, err := ep2.Seal(&envelope.Inner{ID: m.NewID(), Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	m.DepositTo(m.SvcStand, raw) // the copy sends under E2: its flag is set
	f.stepP()
	r := m.RotateIdentity(40, true)
	sendUnder(t, m, s1, TypeIdentityRotate, peertest.RotateBody(r), f.clk.Now())
	f.stepP()
	if c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
}

// After a demotion, a message under the demoted epoch deposited after the
// link is refused (ancestor_ik), and nothing changes.
func TestDemotedEpochMessageRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	s1, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	r := m.RotateIdentity(40, true)
	sendUnder(t, m, s1, TypeIdentityRotate, peertest.RotateBody(r), f.clk.Now())
	f.stepP()
	f.clk.Advance(time.Second)
	raw, err := ep2.Seal(&envelope.Inner{ID: m.NewID(), Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	m.DepositTo(m.SvcStand, raw)
	f.stepP()
	if c.State != StateActive || !f.audited("ancestor_ik") {
		t.Fatalf("state %s", c.State)
	}
	if id2 := ep2.ID(); c.epochMeta(id2[:]).Received {
		t.Fatal("a refused message set the flag")
	}
}

// A message under a demoted epoch deposited before the demotion, processed
// after it, would set the flag: suspended ("judged whenever it is set").
func TestDemotedEpochEarlierMessageSuspends(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	e2 := c.epochMeta(id2[:])
	// Demoted at a position after the message below.
	e2.Demoted, e2.DemotedAt, e2.DemotedMsg = true, f.clk.Now().Add(time.Hour), "ZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	raw, err := ep2.Seal(&envelope.Inner{ID: m.NewID(), Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	m.DepositTo(m.SvcStand, raw)
	f.stepP()
	if c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
}

// R29-K9: a pending epoch of the service's own, signed by A and abandoned,
// is ended at the member's identity.rotate A->B under an earlier epoch: a
// later message under it is fork evidence. With its flag set before the
// identity.rotate, the connection is suspended at once.
func TestK9EndsAbandonedPending(t *testing.T) {
	for _, flag := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		c := f.p.conns[cid]
		s1 := m.SaveEpoch()
		f.p.startRekey(c, f.clk.Now())
		f.p.drainOutbox(context.Background())
		m.Step()  // the member answers
		f.stepP() // pending at the service until a message under it
		if c.Pending == nil {
			t.Fatal("no pending epoch")
		}
		pid := bytes.Clone(c.Pending.ID)
		f.p.abandonPending(c, "replaced", false, f.clk.Now())
		if flag {
			m.Step()                                    // the member takes our hs.fin: the epoch is current on its side
			m.Send(handshake.TypeConfirm, []byte(`{}`)) // under the abandoned epoch: its flag is set
			f.stepP()
		}
		r := m.RotateIdentity(40, true)
		sendUnder(t, m, s1, TypeIdentityRotate, peertest.RotateBody(r), f.clk.Now())
		f.stepP()
		a := c.abandonedMeta(pid)
		if flag {
			if c.State != StateSuspended {
				t.Fatalf("flag set: state %s", c.State)
			}
			continue
		}
		if c.State != StateActive || a == nil || !a.Ended {
			t.Fatalf("flag clear: state %s, ended %v", c.State, a != nil && a.Ended)
		}
		for _, x := range c.Abandoned {
			if bytes.Equal(x, pid) {
				t.Fatal("an ended epoch is still kept for a reconnect's ctx")
			}
		}
		m.Step()                                    // the member (a copy) takes our hs.fin
		m.Send(handshake.TypeConfirm, []byte(`{}`)) // the copy, under the ended epoch
		f.stepP()
		if c.State != StateSuspended {
			t.Fatalf("a message under an ended epoch: state %s", c.State)
		}
	}
}

// K2: a pending epoch abandoned by a link is demoted from the start: a
// message under it is refused.
func TestLinkAbandonedPendingRefused(t *testing.T) {
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
	f.p.abandonPending(c, "link", false, f.clk.Now())
	m.Step()
	m.Send(handshake.TypeConfirm, []byte(`{}`))
	f.stepP()
	if c.State != StateActive || !f.audited("ancestor_ik") {
		t.Fatalf("state %s", c.State)
	}
}

// R29-K4, demotion by position, without strict F1 (links applied beside a
// handshake: no E): an epoch signed by the link's old key and established
// by a message deposited after the link is demoted, flag clear, or
// suspends, flag set; one established before the link is not touched.
// (The test relay cannot reorder deposits, so the link's position is set.)
func TestDemotionByPosition(t *testing.T) {
	for _, flag := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		_, ep2 := copyEpoch(t, f, m, cid)
		c := f.p.conns[cid]
		id2 := ep2.ID()
		e1, e2 := &c.Epochs[0], c.epochMeta(id2[:])
		e2.Received = flag
		r := m.RotateIdentity(40, true)
		// The link's position: after E1's establishment, before E2's.
		f.p.relayAt, f.p.msgID = e1.EstAt, e1.EstMsg
		if !posAfter(e2.EstAt, e2.EstMsg, f.p.relayAt, f.p.msgID) {
			t.Fatal("E2 is not after E1")
		}
		f.p.followRotation(c, r.NewIK, r.NewKEM, []*handshake.Rotation{r}, nil, false)
		f.p.relayAt, f.p.msgID = time.Time{}, ""
		if !flag && reconnectOutgoing(f, cid) {
			t.Fatal("a reconnect started beside a handshake (restart false)")
		}
		switch {
		case flag && c.State != StateSuspended:
			t.Fatalf("flag set: state %s", c.State)
		case !flag && (c.State != StateActive || !e2.Demoted || e1.Demoted):
			t.Fatalf("flag clear: state %s, E2 demoted %v, E1 demoted %v\n%+v", c.State, e2.Demoted, e1.Demoted, c.Epochs)
		}
	}
}

// demoteCurrent demotes the current epoch as a demotion by position beside
// a handshake would (no reconnect started).
func demoteCurrent(c *Connection, at time.Time) {
	e := c.epochMeta(c.LastEpochID)
	e.Demoted, e.DemotedAt, e.DemotedMsg = true, at, "0"
}

// K5: while the current epoch is demoted, nothing but handshake messages
// goes: a message made then waits (held), hs.confirm is not queued, no
// rekey starts; housekeeping starts the reconnect naming the newest epoch
// that is neither demoted nor destroyed.
func TestHeldWhileDemoted(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, _ = copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id1 := bytes.Clone(c.Epochs[0].ID)
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == cid }) // the hs.confirm and the rest
	demoteCurrent(c, f.clk.Now())
	id := f.p.sendTo(c, "test.note", []byte(`{}`), f.clk.Now())
	f.p.drainOutbox(context.Background())
	held := false
	for _, e := range f.p.outbox {
		held = held || e.ConnID == cid && !e.Handshake && !e.Tried
	}
	if id == "" || !held {
		t.Fatal("the message was not held")
	}
	if f.p.queueConfirm(c, f.clk.Now()) {
		t.Fatal("hs.confirm queued while demoted")
	}
	f.p.startRekey(c, f.clk.Now())
	for _, og := range f.p.outgoing {
		if og.ConnID == cid && og.ini != nil && og.ini.Purpose() == handshake.PurposeRekey {
			t.Fatal("a rekey started in a demoted epoch")
		}
	}
	f.p.housekeeping(f.clk.Now())
	var named []byte
	for _, og := range f.p.outgoing {
		if og.ConnID == cid && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
			named = og.Named
		}
	}
	if !bytes.Equal(named, id1) {
		t.Fatalf("the reconnect names %x, want E1 %x", named, id1)
	}
}

// Strict F1 for links applied at hs.fin (0.90.4): the member's rekey under
// E1 carrying A->B, answered while the service's current epoch is the
// copy's E2 (signed by A), demotes E2 at its hs.fin, then rule E destroys
// it; no reconnect starts (the hs.fin makes the next epoch).
func TestStrictF1AtFin(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	m.RotateIdentity(40, true) // A->B
	m.StartRekeyWithLinks()    // under E1, the member's current
	f.pump()
	e2 := c.epochMeta(id2[:])
	if c.State != StateActive || e2 == nil || !e2.Demoted || !e2.Destroyed {
		t.Fatalf("state %s, E2 demoted %v destroyed %v", c.State, e2 != nil && e2.Demoted, e2 != nil && e2.Destroyed)
	}
	if c.currentDemoted() || c.Reconnecting {
		t.Fatal("a reconnect beside the member's handshake")
	}
}

// §6.6 "The links of a refused reconnect" (X4): while our own reconnect is
// pending, a member's reconnect naming another epoch is refused, but its
// identity links are applied; following them ends our pending reconnect
// (pinned to the old key), which starts again.
func TestRefusedReconnectLinksApplied(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.beginReconnectNow(cid)
	m.Step()  // the member answers our reconnect
	f.stepP() // our reconnect's epoch is pending
	if !c.pendingReconnect() {
		t.Fatal("our reconnect is not pending")
	}
	r := m.RotateIdentity(40, true) // A->B
	m.Reconnect()                   // naming E1, the member's current: refused while ours is pending
	f.stepP()
	if !f.audited("reconnect_refused") || !f.audited("refused_reconnect_links") {
		t.Fatal("not refused with its links applied")
	}
	if !suite.EqualPublic(c.Peer.IK, r.NewIK) || len(c.Chain) != 1 {
		t.Fatalf("links not followed: chain %d", len(c.Chain))
	}
	if c.pendingReconnect() || !reconnectOutgoing(f, cid) {
		t.Fatal("our reconnect was not started again")
	}
}

func reconnectOutgoing(f *fixture, cid string) bool {
	for _, og := range f.p.outgoing {
		if og.ConnID == cid && og.ini != nil && og.ini.Purpose() == handshake.PurposeReconnect {
			return true
		}
	}
	return false
}

// "Fork by ctx" skips an epoch demoted with its received flag clear
// (0.88.2): only a used epoch signed by an ancestor is evidence.
func TestForkByCtxSkipsDemotedUnused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	orig := m.IK.Public().(ed25519.PublicKey)
	r := m.RotateIdentity(40, true)
	f.p.followRotation(c, r.NewIK, r.NewKEM, []*handshake.Rotation{r}, nil, false) // no position: no demotion
	id := func(b byte) []byte { return bytes.Repeat([]byte{b}, 16) }
	c.Epochs = []EpochMeta{{ID: id(1), Signer: orig}, {ID: id(2), Signer: orig, Demoted: true}, {ID: id(3), Signer: r.NewIK}}
	c.Confirmed = id(3)
	if f.p.forkEpoch(c, id(1), nil) {
		t.Fatal("a demoted, unused epoch taken as evidence")
	}
	c.Epochs[1].Received = true
	if !f.p.forkEpoch(c, id(1), nil) {
		t.Fatal("a demoted epoch that was used is evidence")
	}
	c.Epochs[1].Demoted, c.Epochs[1].Received = false, false
	if !f.p.forkEpoch(c, id(1), nil) {
		t.Fatal("an epoch signed by an ancestor is evidence")
	}
}
