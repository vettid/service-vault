package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// link makes a valid identity link from old to the key of seed.
func link(t *testing.T, old ed25519.PrivateKey, seed byte) (*handshake.Rotation, ed25519.PrivateKey) {
	t.Helper()
	nk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := handshake.NewRotation(old, nk, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	return r, nk
}

// R29-K1 (S8): an identity.rotate whose earlier statement was lost carries
// the whole chain in `rotations`; the service follows every link from the
// stored key. Before, it read `rotation` alone and refused it
// (bad_rotation) until a rekey brought the chain.
func TestIdentityRotateWholeChain(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ab := m.RotateIdentity(40, true) // A->B, its identity.rotate lost
	bc := m.RotateIdentity(50, true) // B->C
	m.SendRotations(ab, bc)
	f.pump()
	c := f.p.conns[cid]
	if len(c.Chain) != 2 || !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || f.audited("bad_rotation") {
		t.Fatalf("chain %d, followed to C: %v", len(c.Chain), m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK))
	}
	// Sent again: every link already followed, ignored.
	m.SendRotations(ab, bc)
	f.pump()
	if len(c.Chain) != 2 || f.audited("bad_rotation") || f.audited("unexpected") || c.State != StateActive {
		t.Fatalf("a chain already followed was not ignored: chain %d, state %s", len(c.Chain), c.State)
	}
}

// A `rotations` whose last link is not `rotation` is malformed: refused,
// nothing followed.
func TestIdentityRotateRotationNotLast(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ab := m.RotateIdentity(40, true)
	bc := m.RotateIdentity(50, true)
	m.Send("identity.rotate", peertest.RotateBody(ab, ab, bc))
	f.pump()
	if c := f.p.conns[cid]; len(c.Chain) != 0 || !f.audited("bad_rotation") {
		t.Fatalf("chain %d", len(c.Chain))
	}
}

// Table B: a chain whose first link not followed starts at a key that is
// neither the stored key nor an ancestor is refused unknown_ik.
func TestIdentityRotateUnknownIK(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	r, _ := link(t, stranger, 78)
	m.SendRotations(r)
	f.pump()
	if c := f.p.conns[cid]; len(c.Chain) != 0 || !f.audited("unknown_ik") || c.State != StateActive {
		t.Fatalf("chain %d, state %s", len(c.Chain), c.State)
	}
}

// R29-K8, rule C with seen links: a rekey hs.init carrying A->B that passed
// its own checks records the link as seen while its answer waits for
// hs.fin; another copy's identity.rotate with A->X is then a second
// successor of A at once, not followed.
func TestSeenLinkSuspendsSecondSuccessor(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	m.RotateIdentity(50, true) // A->B
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil { // answered; its hs.fin not yet sent
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	if len(c.Seen) != 1 || len(c.Chain) != 0 {
		t.Fatalf("seen %d, chain %d", len(c.Seen), len(c.Chain))
	}
	ax, _ := link(t, orig, 40) // the other copy's A->X
	m.SendRotations(ax)
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c.State != StateSuspended || len(c.Chain) != 0 || !suite.EqualPublic(c.Peer.IK, orig.Public().(ed25519.PublicKey)) {
		t.Fatalf("state %s, chain %d", c.State, len(c.Chain))
	}
}

// acceptFrom step 3: rule C runs before anything may refuse the message.
// An identity.rotate with a second successor of a followed key, outside
// the ts window (refused stale_or_future), still suspends.
func TestEvidenceFirstBeforeRefusal(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	m.SendRotation(m.RotateIdentity(40, true)) // A->B, followed
	f.pump()
	ax, _ := link(t, orig, 60)
	m.SendInner(&envelope.Inner{ID: m.NewID(), Type: TypeIdentityRotate, TS: f.clk.Now().Add(-30 * 24 * time.Hour),
		Body: peertest.RotateBody(ax, ax)})
	f.pump()
	if c := f.p.conns[cid]; c.State != StateSuspended {
		t.Fatalf("state %s: a second successor in a refused message went unseen", c.State)
	}
}

// Rule C on the hs.resp to the service's own rekey: a link A->X that
// contradicts a seen A->B suspends, and nothing is followed or installed.
func TestSeenLinkJudgedAtResp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	epoch := c.kr.Current().ID()
	orig := m.IK
	ab, _ := link(t, orig, 50)
	c.Seen = append(c.Seen, ab.Marshal()) // A->B seen (a copy's handshake, not completed)
	ax := m.RotateIdentity(40, true)      // this copy: A->X, answered in the hs.resp
	m.RespRotations = []*handshake.Rotation{ax}
	f.p.startRekey(c, f.clk.Now())
	f.pump()
	if c.State != StateSuspended || len(c.Chain) != 0 || c.kr.Current().ID() != epoch {
		t.Fatalf("state %s, chain %d, epoch moved %v", c.State, len(c.Chain), c.kr.Current().ID() != epoch)
	}
}

// Seen links are bounded (MaxSeen), only relevant ones are kept, and a
// followed link stops being only seen.
func TestSeenLinksBoundedAndPruned(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	now := f.clk.Now()
	// A link from a key the connection has never had is not relevant.
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, 32))
	r, _ := link(t, stranger, 91)
	if f.p.rotationConflictRec(c, r, true, now) || len(c.Seen) != 0 {
		t.Fatalf("an unrelated link was kept: %d", len(c.Seen))
	}
	// A chain from the current key, longer than the bound.
	k := m.IK
	var first *handshake.Rotation
	for i := 0; i < MaxSeen+3; i++ {
		var r *handshake.Rotation
		r, k = link(t, k, byte(100+2*i))
		if i == 0 {
			first = r
		}
		if f.p.rotationConflictRec(c, r, true, now) {
			t.Fatal("conflict")
		}
	}
	if len(c.Seen) != MaxSeen {
		t.Fatalf("seen %d, want %d", len(c.Seen), MaxSeen)
	}
	// Recording the same link again adds nothing.
	f.p.rotationConflictRec(c, first, true, now)
	if len(c.Seen) != MaxSeen {
		t.Fatalf("seen %d after a repeat", len(c.Seen))
	}
	// Following the first link prunes it (and keeps the rest, reached from
	// the new key).
	f.p.followRotation(c, first.NewIK, first.NewKEM, []*handshake.Rotation{first}, false)
	if len(c.Seen) != MaxSeen-1 {
		t.Fatalf("seen %d after following one", len(c.Seen))
	}
}

// A rekey hs.init that passes its own checks records its links as seen
// even when it is then refused (here: a reconnect of the service's is
// open), as vettid-vault does: another copy's A->X is a second successor.
func TestSeenLinkFromRefusedRekey(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	f.beginReconnectNow(cid)
	m.RotateIdentity(50, true) // A->B
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	if !f.audited("rekey_while_reconnecting") || len(c.Seen) != 1 {
		t.Fatalf("seen %d", len(c.Seen))
	}
	ax, _ := link(t, orig, 40)
	m.SendRotations(ax)
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
}

// The same on the hs.resp to the service's own reconnect: suspended, no
// epoch, nothing followed.
func TestSeenLinkJudgedAtReconnectResp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	epoch := c.kr.Current().ID()
	ab, _ := link(t, m.IK, 50)
	c.Seen = append(c.Seen, ab.Marshal()) // A->B seen
	m.RotateIdentity(40, true)            // this copy: A->X, carried in its hs.resp
	f.beginReconnectNow(cid)
	f.pump()
	if c.State != StateSuspended || len(c.Chain) != 0 || c.kr.Current().ID() != epoch || c.Pending != nil {
		t.Fatalf("state %s, chain %d, epoch moved %v", c.State, len(c.Chain), c.kr.Current().ID() != epoch)
	}
}

// Table B: a chain whose first link not followed starts at an ancestor
// (here a followed link A->B signed again with another KEM, so it is not
// "already followed", yet no second successor) is refused unexpected.
func TestIdentityRotateAncestorFirstUnexpected(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	m.SendRotation(m.RotateIdentity(40, true)) // A->B, followed
	f.pump()
	c := f.p.conns[cid]
	if len(c.Chain) != 1 {
		t.Fatalf("chain %d", len(c.Chain))
	}
	kem2, err := suite.NewPrivateKey(bytes.Repeat([]byte{99}, 32))
	if err != nil {
		t.Fatal(err)
	}
	again, err := handshake.NewRotation(orig, m.IK, kem2.Public()) // A->B, another KEM
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotations(again)
	f.pump()
	if len(c.Chain) != 1 || !f.audited("unexpected") || c.State != StateActive {
		t.Fatalf("chain %d, state %s", len(c.Chain), c.State)
	}
}

// A rekey hs.init's links are checked by rule C before anything else, but
// recorded as seen only once it passes its own checks: one outside the ts
// window records nothing.
func TestRekeyLinksNotSeenBeforePrecheck(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.RotateIdentity(50, true) // A->B
	m.StartRekeyWithLinks()
	f.clk.Advance(envelope.MaxDurableAge + time.Hour) // stale when it is handled
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; len(c.Seen) != 0 {
		t.Fatalf("seen %d: a rekey that failed its own checks recorded its links", len(c.Seen))
	}
}

// A rekey hs.init whose from.relay.pk is not its sender fails
// rekeyPrecheck: its links are checked by rule C but never recorded as
// seen, whatever check refuses it later.
func TestRekeyFailingPrecheckRecordsNothing(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.RotateIdentity(50, true) // A->B
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32)).Public().(ed25519.PublicKey)
	m.Addr = handshake.RelayAddr{URL: m.Addr.URL, Mailbox: relayauth.MailboxID(other), PK: other} // not its sender
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; len(c.Seen) != 0 {
		t.Fatalf("seen %d", len(c.Seen))
	}
}

// The whole chain is kept: after more links than MaxRotations, a second
// successor of the first key still suspends (it is still an ancestor).
func TestLongChainKeepsAncestors(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	for i := 0; i < handshake.MaxRotations+2; i++ {
		r := m.RotateIdentity(byte(100+2*i), true)
		m.SendRotation(r)
		f.pump()
	}
	c := f.p.conns[cid]
	if len(c.Chain) != handshake.MaxRotations+2 || !isAncestor(c, orig.Public().(ed25519.PublicKey)) {
		t.Fatalf("chain %d", len(c.Chain))
	}
	ax, _ := link(t, orig, 30) // another successor of the first key
	m.SendRotations(ax)
	f.pump()
	if c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
}

// A link in an identity.rotate refused for its ts stays seen (rule C runs
// first).
func TestRefusedRotateLinkStaysSeen(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r := m.RotateIdentity(40, true)
	m.SendInner(&envelope.Inner{ID: m.NewID(), Type: TypeIdentityRotate, TS: f.clk.Now().Add(-30 * 24 * time.Hour),
		Body: peertest.RotateBody(r, r)})
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; len(c.Seen) != 1 || len(c.Chain) != 0 || !f.audited("stale_or_future") {
		t.Fatalf("seen %d, chain %d", len(c.Seen), len(c.Chain))
	}
}
