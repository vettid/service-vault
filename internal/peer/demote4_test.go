package peer

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ctxOf is the ctx naming a test epoch id.
func ctxOf(id []byte) string {
	var e [suite.EpochIDSize]byte
	copy(e[:], id)
	return handshake.EpochCtx(e)
}

// refusedSetup gives a connection whose own reconnect is pending (a fake
// pending record: refusedReconnectLinks only reads it), with epochs as
// given, and returns the member's key A and its private key.
func refusedSetup(t *testing.T, f *fixture, m *peertest.Member, c *Connection, epochs []EpochMeta, current []byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	c.Epochs, c.LastEpochID, c.Confirmed = epochs, current, current
	c.Pending = &PendingEpoch{ID: eid(0xEE), Purpose: handshake.PurposeReconnect, FinAt: f.clk.Now()}
	return m.IK.Public().(ed25519.PublicKey), m.IK
}

// X4 with an abandoned E: the refused reconnect names X, one of our
// abandoned epochs; its links run strict F1 with E = X, demoting Ec (later
// than X, signed by the old key, flag clear).
func TestRefusedReconnectAbandonedE(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	t0 := f.clk.Now()
	pos := func(n byte) string { return "01M0000000000000000000000" + string('0'+n) }
	a, aPriv := refusedSetup(t, f, m, c, nil, nil)
	c.Epochs = []EpochMeta{{ID: eid(1), Signer: a, EstAt: t0, EstMsg: pos(3)}, {ID: eid(2), Signer: a, EstAt: t0, EstMsg: pos(7)}}
	c.LastEpochID, c.Confirmed = eid(2), eid(1)
	c.Abandoned = [][]byte{eid(9)}
	c.AbandonedMeta = []AbandonedEpoch{{ID: eid(9), At: t0, Signer: a, EstAt: t0, EstMsg: pos(5)}}
	ab, b := link(t, aPriv, 40)
	body := &handshake.Init{Purpose: handshake.PurposeReconnect, Ctx: ctxOf(eid(9)),
		From: handshake.Principal{IK: b.Public().(ed25519.PublicKey), KEM: ab.NewKEM}, Rotations: []*handshake.Rotation{ab}}
	f.p.refusedReconnectLinks(c, body, f.clk.Now())
	if len(c.Chain) != 1 || !c.Epochs[1].Demoted || c.Epochs[0].Demoted {
		t.Fatalf("chain %d, demoted %v %v", len(c.Chain), c.Epochs[0].Demoted, c.Epochs[1].Demoted)
	}
}

// X4 all or nothing: a chain one of whose links Table B refuses (here a
// new key the chain already passed) has none of its links followed.
func TestRefusedReconnectAllOrNothing(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	cur := bytes.Clone(c.LastEpochID)
	a, aPriv := refusedSetup(t, f, m, c, []EpochMeta{{ID: cur, Signer: m.IK.Public().(ed25519.PublicKey)}}, cur)
	_ = a
	ab, bPriv := link(t, aPriv, 40)
	bc, cPriv := link(t, bPriv, 50)
	kemX, err := suite.NewPrivateKey(bytes.Repeat([]byte{77}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cb, err := handshake.NewRotation(cPriv, bPriv, kemX.Public()) // back to B, a key the chain passed
	if err != nil {
		t.Fatal(err)
	}
	body := &handshake.Init{Purpose: handshake.PurposeReconnect, Ctx: ctxOf(cur),
		From: handshake.Principal{IK: bPriv.Public().(ed25519.PublicKey), KEM: kemX.Public()}, Rotations: []*handshake.Rotation{ab, bc, cb}}
	f.p.refusedReconnectLinks(c, body, f.clk.Now())
	if len(c.Chain) != 0 || !f.audited("refused_reconnect_links_none") {
		t.Fatalf("chain %d: links followed", len(c.Chain))
	}
}

// X4's fork exclusion: a refused reconnect whose ctx would be fork evidence
// (an epoch older than the confirmed one, a later one signed by a key the
// links leave behind) has none of its links followed.
func TestRefusedReconnectForkExcluded(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a := m.IK.Public().(ed25519.PublicKey)
	refusedSetup(t, f, m, c, []EpochMeta{{ID: eid(1), Signer: a}, {ID: eid(2), Signer: a}}, eid(2))
	ab, b := link(t, m.IK, 40)
	body := &handshake.Init{Purpose: handshake.PurposeReconnect, Ctx: ctxOf(eid(1)),
		From: handshake.Principal{IK: b.Public().(ed25519.PublicKey), KEM: ab.NewKEM}, Rotations: []*handshake.Rotation{ab}}
	f.p.refusedReconnectLinks(c, body, f.clk.Now())
	if len(c.Chain) != 0 {
		t.Fatal("the links of a fork-evidence reconnect were followed")
	}
}

// f1Demote with an abandoned E and the current epoch established before E:
// nothing is judged, not even a listed epoch established after E.
func TestStrictF1AbandonedECurrentBefore(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	a, _, _, ab, _ := chainOf2(t, f, m, c)
	t0 := f.clk.Now()
	pos := func(n byte) string { return "01M0000000000000000000000" + string('0'+n) }
	c.AbandonedMeta = []AbandonedEpoch{{ID: eid(9), At: t0, Signer: a, EstAt: t0, EstMsg: pos(8)}}
	c.Epochs = []EpochMeta{{ID: eid(3), Signer: a, EstAt: t0, EstMsg: pos(9)}, {ID: eid(2), Signer: a, EstAt: t0, EstMsg: pos(7)}}
	c.LastEpochID = eid(2)
	f.p.f1Demote(c, []*handshake.Rotation{ab}, eid(9), false, f.clk.Now())
	if c.Epochs[0].Demoted || c.Epochs[1].Demoted {
		t.Fatal("strict F1 ran with the current epoch established before E")
	}
}

// Positions order by msg_id when deposited_at is missing: a demotion by
// position and K9 still judge.
func TestPositionsWithoutDepositedAt(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, ep2 := copyEpoch(t, f, m, cid)
	c := f.p.conns[cid]
	id2 := ep2.ID()
	for i := range c.Epochs {
		c.Epochs[i].EstAt = time.Time{}
	}
	e1, e2 := &c.Epochs[0], c.epochMeta(id2[:])
	r := m.RotateIdentity(40, true)
	f.p.relayAt, f.p.msgID = time.Time{}, e1.EstMsg // no deposited_at
	f.p.followRotation(c, r.NewIK, r.NewKEM, []*handshake.Rotation{r}, nil, false)
	f.p.relayAt, f.p.msgID = time.Time{}, ""
	if !e2.Demoted || e1.Demoted {
		t.Fatalf("by position without deposited_at: E2 demoted %v, E1 %v", e2.Demoted, e1.Demoted)
	}

	// K9 with no deposited_at anywhere.
	g := newFixture(t)
	m2 := g.member(10)
	cid2 := g.connect(m2, "")
	c2 := g.p.conns[cid2]
	a, _, _, ab, bc := chainOf2(t, g, m2, c2)
	pos := func(n byte) string { return "01M0000000000000000000000" + string('0'+n) }
	c2.Epochs = []EpochMeta{{ID: eid(1), Signer: a, EstMsg: pos(5)}}
	c2.LastEpochID = eid(1)
	c2.AbandonedMeta = []AbandonedEpoch{{ID: eid(3), At: g.clk.Now(), Signer: a, EstMsg: pos(7)}}
	g.p.identityRotate(c2, peertest.RotateBody(bc, ab, bc), eid(1), g.clk.Now())
	if !c2.AbandonedMeta[0].Ended {
		t.Fatal("K9 did not judge by msg_id without deposited_at")
	}
}
