package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// signIn runs one sign-in challenge to the member and its signed answer,
// and reports whether it was approved.
func (f *fixture) signIn(m *peertest.Member, cid string) bool {
	f.t.Helper()
	before := len(f.ev.of(EventSignInApproved))
	id, err := f.p.Authenticate(context.Background(), cid, "Sign in — match code 42", 5*time.Minute)
	if err != nil {
		f.t.Fatalf("Authenticate: %v", err)
	}
	f.pump()
	var ch *peerwire.ConnAuthChallenge
	for _, c := range m.Challenges {
		if c.RequestID == id {
			ch = c
		}
	}
	if ch == nil {
		return false
	}
	r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), ch, f.clk.Now(), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	return len(f.ev.of(EventSignInApproved)) == before+1
}

func ikOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// A member's vault rotates its identity and KEM keys (a transfer to a new
// phone, §3.4): the service follows the link, answers the rekey under the
// new key, and the connection carries on: sign-in, profile.
func TestMemberIdentityRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	old := ikOf(m.IK)
	epoch := m.KR.Current().ID()
	m.RotateIdentity(40, false)
	f.pump()
	c := f.p.conns[cid]
	if !suite.EqualPublic(c.Peer.IK, ikOf(m.IK)) || suite.EqualPublic(c.Peer.IK, old) || len(c.Chain) != 1 {
		t.Fatalf("identity not followed: chain %d", len(c.Chain))
	}
	if m.KR.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("no rekey under the new key")
	}
	m.Send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(2, "Nora", "Moved", ikOf(m.IK), nil))
	f.pump()
	if got, _ := f.p.Connection(cid); got.Name != "Nora Moved" {
		t.Fatalf("profile under the new ik: %q", got.Name)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the rotation")
	}
	// The same statement again changes nothing; it survives a restart.
	f.start()
	if c := f.p.conns[cid]; len(c.Chain) != 1 || !suite.EqualPublic(c.Peer.IK, ikOf(m.IK)) {
		t.Fatal("rotation lost on restart")
	}
}

// A statement that does not verify, or does not start at the stored key,
// is dropped.
func TestBadRotationDropped(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stored := append(ed25519.PublicKey(nil), f.p.conns[cid].Peer.IK...)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	newIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{79}, 32))
	r, err := handshake.NewRotation(other, newIK, kem.Public()) // not from the stored key
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotation(r)
	r2, _ := handshake.NewRotation(m.IK, newIK, kem.Public())
	r2.SigNew[0] ^= 1 // one signature broken
	m.SendRotation(r2)
	f.pump()
	if c := f.p.conns[cid]; !suite.EqualPublic(c.Peer.IK, stored) || len(c.Chain) != 0 || c.State != StateActive {
		t.Fatal("a bad rotation was followed")
	}
}

// A member's vault rotates its relay key: relay.address.update, deposited
// with the old key, moves the connection to the new mailbox; the service
// answers with tokens for the new key; traffic flows both ways after it.
// A message from the old key still in flight is accepted; the first
// message from the new key ends that grace and revokes the old key's
// tokens.
func TestMemberRelayRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	oldPK := append(ed25519.PublicKey(nil), f.p.conns[cid].Peer.Relay.PK...)
	oldStand := m.SvcStand // the service's token for the old key
	oldView := m.RotateRelay(f.w, 50)
	// In flight: deposited with the old key after the update.
	cur, curStand := m.R, m.SvcStand
	m.R, m.SvcStand = oldView, oldStand
	m.Send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(2, "Nora", "Late", ikOf(m.IK), nil))
	m.R, m.SvcStand = cur, curStand
	f.pump()
	c := f.p.conns[cid]
	if !suite.EqualPublic(c.Peer.Relay.PK, m.Addr.PK) || c.Peer.Relay.Mailbox != m.Addr.Mailbox {
		t.Fatal("address not followed")
	}
	if got, _ := f.p.Connection(cid); got.Name != "Nora Late" {
		t.Fatalf("the message in flight from the old key: %q", got.Name)
	}
	if !suite.EqualPublic(c.PrevRelayPK, oldPK) {
		t.Fatal("previous key not kept")
	}
	f.start() // the grace survives a restart
	if c = f.p.conns[cid]; !suite.EqualPublic(c.PrevRelayPK, oldPK) {
		t.Fatal("previous key lost on restart")
	}
	if issued := m.Received(peerwire.TypeTokenIssued); len(issued) < 2 {
		t.Fatalf("tokens for the new key: %d", len(issued))
	}
	// Service to member, in the new mailbox; member to service with the
	// new key, which ends the grace.
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the relay rotation")
	}
	c = f.p.conns[cid]
	if len(c.PrevRelayPK) != 0 || f.p.connByRelayKey(oldPK, f.clk.Now()) != nil {
		t.Fatal("the old key outlived the first message from the new key")
	}
	if _, err := oldView.Deposit(context.Background(), m.SvcMailbox(), oldStand, []byte("x")); err == nil {
		t.Fatal("the old key's token still works")
	}
}

// Only the current key may move the connection: from the old key, an
// update to yet another key is refused. From the new key, an update to a
// key whose token doesn't check out (here the old key), a key another
// connection uses, and another relay are refused.
func TestRelayUpdateRefusals(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	other := f.member(30)
	cid := f.connect(m, "")
	f.connect(other, "")
	oldStand := m.SvcStand
	oldView := m.RotateRelay(f.w, 50)
	newPK := append(ed25519.PublicKey(nil), m.Addr.PK...)
	cur, curStand := m.R, m.SvcStand
	m.R, m.SvcStand = oldView, oldStand
	m.SendAddressUpdate(f.w, 51, "") // from the old key, in its grace
	m.R, m.SvcStand = cur, curStand
	f.pump()
	if c := f.p.conns[cid]; !suite.EqualPublic(c.Peer.Relay.PK, newPK) {
		t.Fatal("the old key moved the connection")
	}
	m.SendAddressUpdateTo(f.w, ikOf(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{12}, 32))), "") // the old key, no valid token
	m.SendAddressUpdateTo(f.w, other.Addr.PK, "")
	m.SendAddressUpdate(f.w, 52, "https://relay.example.org")
	f.pump()
	if c := f.p.conns[cid]; !suite.EqualPublic(c.Peer.Relay.PK, newPK) {
		t.Fatal("a refused update moved the connection")
	}
}

// A member's vault rotated while the session was down: the reconnect
// carries the link (§6.6), the service follows it and the new session works.
func TestReconnectWithRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.RotateIdentity(40, true)
	m.Reconnect()
	f.pump()
	c := f.p.conns[cid]
	if !suite.EqualPublic(c.Peer.IK, ikOf(m.IK)) || len(c.Chain) != 1 {
		t.Fatal("reconnect's rotation not followed")
	}
	if c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("no session after the reconnect")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// Two different successors of one key (§3.4 "One successor per key"):
// the connection is suspended, nothing is accepted or sent, and a new
// invitation from the member replaces it.
func TestRotationConflictSuspends(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	oldKey := m.IK
	m.RotateIdentity(40, false)
	f.pump()
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, 32))
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{91}, 32))
	other, err := handshake.NewRotation(oldKey, b, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotation(other)
	f.pump()
	if c := f.p.conns[cid]; c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
	// The application learns it once.
	m.SendRotation(other)
	f.pump()
	if evs := f.ev.of(EventConnectionSuspended); len(evs) != 1 || evs[0].ConnectionID != cid || evs[0].Reason != SuspendRotationConflict {
		t.Fatalf("connection.suspended %+v", evs)
	}
	if _, err := f.p.Authenticate(context.Background(), cid, "Sign in", time.Minute); err == nil {
		t.Fatal("a challenge to a suspended connection")
	}
	m.Send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(5, "Nora", "Ignored", ikOf(m.IK), nil))
	f.pump()
	if got, _ := f.p.Connection(cid); got.Name == "Nora Ignored" {
		t.Fatal("a message from a suspended connection was taken")
	}
	// The member connects again with a new invitation: the new connection
	// replaces the suspended one.
	m2 := f.member(20) // a new relay key; the identity the member rotated to
	m2.IK = m.IK
	cid2 := f.connect(m2, "")
	if _, ok := f.p.Connection(cid); ok {
		t.Fatal("the suspended connection was not replaced")
	}
	if !f.signIn(m2, cid2) {
		t.Fatal("sign-in on the new connection")
	}
	if evs := f.ev.of(EventConnectionRemoved); len(evs) != 1 || evs[0].ConnectionID != cid {
		t.Fatalf("connection.removed for the suspended connection %+v", evs)
	}
}

// identity.rotate was followed but the rekey after it was lost: the
// member's reconnect carries the link again (every rotation since its
// last epoch), and the service accepts it from the link's old key.
func TestReconnectAfterFollowedRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r := m.RotateIdentity(40, true) // kept for the reconnect
	m.SendRotation(r)               // and sent; no rekey follows
	f.pump()
	if c := f.p.conns[cid]; !suite.EqualPublic(c.Peer.IK, ikOf(m.IK)) {
		t.Fatal("rotation not followed")
	}
	m.Reconnect()
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() != m.KR.Current().ID() || len(c.Chain) != 1 {
		t.Fatalf("reconnect after a followed link: chain %d", len(c.Chain))
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A rekey the service started before the member rotated names the old
// keys: it is dropped, so the next one can start.
func TestServiceRekeyDroppedOnRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.startRekey(f.p.conns[cid], f.clk.Now()) // its hs.init is still unread by the member
	if len(f.p.outgoing) != 1 {
		t.Fatal("no rekey in flight")
	}
	r := m.RotateIdentity(40, true)
	m.SendRotation(r)
	f.p.Step(context.Background(), 0)
	if len(f.p.outgoing) != 0 {
		t.Fatal("the stale rekey stays")
	}
}

// A reconnect whose chain gives a key a second successor suspends the
// connection, as a statement in the session does.
func TestReconnectConflictSuspends(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	oldKey := m.IK
	m.RotateIdentity(40, false)
	f.pump()
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{90}, 32))
	kem, _ := suite.NewPrivateKey(bytes.Repeat([]byte{91}, 32))
	other, err := handshake.NewRotation(oldKey, b, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.Rotations = []*handshake.Rotation{other}
	m.IK = b
	m.Reconnect()
	f.pump()
	if c := f.p.conns[cid]; c.State != StateSuspended {
		t.Fatalf("state %s", c.State)
	}
	if len(f.ev.of(EventConnectionSuspended)) != 1 {
		t.Fatal("no connection.suspended")
	}
}

// A link counts as already followed only with the same old_ik, new_ik
// and new_kem (VAULT-MESSAGING 0.69.1 §6.6).
func TestKnownSuccessorMatchesKEM(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	old := m.IK
	r := m.RotateIdentity(40, false)
	f.pump()
	c := f.p.conns[cid]
	if !f.p.knownSuccessor(c, r) {
		t.Fatal("the followed link")
	}
	otherKEM, _ := suite.NewPrivateKey(bytes.Repeat([]byte{99}, 32))
	r2, err := handshake.NewRotation(old, m.IK, otherKEM.Public())
	if err != nil {
		t.Fatal(err)
	}
	if f.p.knownSuccessor(c, r2) {
		t.Fatal("a link with another new_kem counted as followed")
	}
}
