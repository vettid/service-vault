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
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// A rekey that carries identity links the service has not followed
// (VAULT-MESSAGING 0.87.0 S8, as a release-29 member vault sends its
// whole chain on every rekey) is answered, and the links are followed at
// its verified hs.fin: the stored key moves to the one the epoch was made
// with, the link is recorded, the member is sent hs.confirm under the new
// epoch, and a sign-in goes through in it.
func TestRekeyWithLinksFollowed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	m.RotateIdentity(40, true) // a link the service has not followed
	if len(m.Rotations) != 1 {
		t.Fatal("no link queued")
	}
	got := len(m.Got)
	m.StartRekeyWithLinks()
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the rekey did not complete")
	}
	if !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 1 {
		t.Fatalf("link not followed: chain %d", len(c.Chain))
	}
	if !confirmed(m, got) {
		t.Fatal("no hs.confirm")
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the rekey")
	}
}

// confirmed reports whether the member received an hs.confirm (§6.3.1
// Responder) since got messages.
func confirmed(m *peertest.Member, got int) bool {
	for _, in := range m.Got[got:] {
		if in.Type == handshake.TypeConfirm && string(in.Body) == "{}" && in.Re == "" {
			return true
		}
	}
	return false
}

// An hs.resp to the service's own rekey that carries identity links the
// service has not followed (S8) completes the rekey: the links are
// followed before the epoch is installed, hs.fin goes out, and a sign-in
// goes through in the new epoch.
func TestServiceRekeyRespWithLinksFollowed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	r := m.RotateIdentity(40, true) // a link the service has not followed
	m.RespRotations = []*handshake.Rotation{r}
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.pump()
	c := f.p.conns[cid]
	if len(f.p.outgoing) != 0 || c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the rekey did not complete")
	}
	if !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 1 {
		t.Fatalf("link not followed: chain %d", len(c.Chain))
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the rekey")
	}
}

// Once the service followed a link (here from identity.rotate), an hs.resp
// that carries it again, as a release-29 member's does on every rekey,
// completes the service's rekey without following it twice.
func TestServiceRekeyRespWithKnownLink(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r := m.RotateIdentity(40, true)
	m.SendRotation(r)
	f.pump()
	m.RespRotations = []*handshake.Rotation{r}
	epoch := f.p.conns[cid].kr.Current().ID()
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.pump()
	c := f.p.conns[cid]
	if len(f.p.outgoing) != 0 || c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() || len(c.Chain) != 1 {
		t.Fatalf("rekey with a known link: %d outgoing, chain %d", len(f.p.outgoing), len(c.Chain))
	}
}

// A rekey from a member whose handshake messages carry inner features, as
// a release-29 vault's do, completes; so does the service's own rekey
// when the member's hs.resp carries them.
func TestRekeyWithFeaturesFromRelease29(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	m.HSFeatures = []string{"hs_confirm", "relay_follow", "vote"}
	cid := f.connect(m, "")
	old := m.KR.Current().ID()
	m.StartRekey()
	f.pump()
	if m.KR.Current().ID() == old || f.p.conns[cid].kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the member's rekey did not complete")
	}
	old = m.KR.Current().ID()
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.pump()
	if len(f.p.outgoing) != 0 || m.KR.Current().ID() == old || f.p.conns[cid].kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the service's rekey did not complete")
	}
	if _, err := f.p.Authenticate(context.Background(), cid, "after rekey", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(m.Challenges) != 1 {
		t.Fatal("no challenge in the new epoch")
	}
}

// An hs.confirm (0.86.0, §6.3.1) is acked and ignored: not answered (it
// is not a request), not audited, and the connection stays active. A
// message whose inner part carries a valid features list is handled. (A
// malformed list is refused by the library, like any malformed known
// member, §5.3: vettid-vault's envelope.TestInnerFeatures; this package's
// test member cannot encode one.)
func TestRelease29MessagesTolerated(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	confirm := m.NewID()
	logs := len(f.logs.String())
	m.SendInner(&envelope.Inner{ID: confirm, Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte("{}")})
	f.pump()
	if c := f.p.conns[cid]; c.State != StateActive {
		t.Fatalf("state %s after hs.confirm", c.State)
	}
	for _, in := range m.Got {
		if in.Re == confirm {
			t.Fatal("hs.confirm answered")
		}
	}
	if strings.Contains(f.logs.String()[logs:], "reason=") {
		t.Fatalf("hs.confirm audited:\n%s", f.logs.String()[logs:])
	}
	ik := m.IK.Public().(ed25519.PublicKey)
	m.SendInner(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate, TS: f.clk.Now(),
		Body: peerwire.ProfileUpdateBody(2, "Nora", "Renamed", ik, nil), Features: []string{"hs_confirm", "relay_follow", "vote"}})
	f.pump()
	if got, _ := f.p.Connection(cid); got.Name != "Nora Renamed" {
		t.Fatalf("name %q: a message with inner features was not handled", got.Name)
	}
}

// A real release-29 member (0.87.0 S8): its identity.rotate is followed,
// then its rekey still carries the link from the epoch's signer, as a
// release-29 vault sends the whole chain on every rekey to every peer.
// The rekey completes, the link is not followed twice, and the key stays
// the followed one.
func TestRelease29RotatedMemberRekey(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	r := m.RotateIdentity(40, true)
	m.SendRotation(r)
	f.pump()
	followed := m.IK.Public().(ed25519.PublicKey)
	if !followed.Equal(f.p.conns[cid].Peer.IK) {
		t.Fatal("identity.rotate not followed")
	}
	m.StartRekeyWithLinks() // the link from the epoch's signer, already followed
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the rekey did not complete")
	}
	if !followed.Equal(c.Peer.IK) || len(c.Chain) != 1 {
		t.Fatalf("the followed key changed: chain %d", len(c.Chain))
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the rekey")
	}
}

// A rekey whose links are followed waits for its hs.fin across a restart:
// what it brought is stored with the answer.
func TestRekeyLinksFollowedAfterRestart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.RotateIdentity(40, true)
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil { // answered
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	f.start()
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() != m.KR.Current().ID() || !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) {
		t.Fatal("the links were not followed after the restart")
	}
}

// A rekey whose chain does not lead from the stored key (a link from a
// stranger's key) is refused: no answer, nothing followed.
func TestRekeyForgedChainRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stored := f.p.conns[cid].Peer.IK
	epoch := f.p.conns[cid].kr.Current().ID()
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := handshake.NewRotation(stranger, m.IK, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.Rotations = []*handshake.Rotation{forged}
	m.StartRekeyWithLinks()
	f.pump()
	c := f.p.conns[cid]
	if len(f.p.awaiting) != 0 || c.kr.Current().ID() != epoch || m.KR.Current().ID() != epoch {
		t.Fatal("a forged chain was answered")
	}
	if !ed25519.PublicKey(stored).Equal(c.Peer.IK) || len(c.Chain) != 0 {
		t.Fatal("a forged chain was followed")
	}
	if !strings.Contains(f.logs.String(), "reason=rekey_refused") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// A rekey carrying a valid link that gives the member's key a second
// successor (one followed already from identity.rotate) suspends the
// connection (§3.4 "One successor per key"), as at a reconnect.
func TestRekeyRotationConflictSuspends(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	r := m.RotateIdentity(40, true)
	m.SendRotation(r)
	f.pump()
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{60}, 32))
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{61}, 32))
	if err != nil {
		t.Fatal(err)
	}
	second, err := handshake.NewRotation(orig, other, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.Rotations = []*handshake.Rotation{second}
	m.StartRekeyWithLinks()
	f.pump()
	if c := f.p.conns[cid]; c.State != StateSuspended || len(f.p.awaiting) != 0 {
		t.Fatalf("state %s, %d awaiting", c.State, len(f.p.awaiting))
	}
}

// An hs.resp to the service's rekey whose chain is forged (a link that
// does not start at the member's key) aborts the rekey: no epoch move,
// no hs.fin, nothing followed (vettid-vault's handshake refuses the
// chain). The next rekey then waits RekeyBackoff, doubled at a second
// failure, instead of starting again at the next tick.
func TestServiceRekeyRespForgedChain(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stored := f.p.conns[cid].Peer.IK
	epoch := f.p.conns[cid].kr.Current().ID()
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{78}, 32))
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{79}, 32))
	if err != nil {
		t.Fatal(err)
	}
	forged, err := handshake.NewRotation(stranger, next, kem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.RespRotations = []*handshake.Rotation{forged}
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.pump()
	c := f.p.conns[cid]
	if len(f.p.outgoing) != 0 {
		t.Fatal("the rekey is still outgoing")
	}
	if c.kr.Current().ID() != epoch || m.KR.Current().ID() != epoch {
		t.Fatal("the epoch moved on a forged chain")
	}
	if !ed25519.PublicKey(stored).Equal(c.Peer.IK) {
		t.Fatal("the stored identity key changed")
	}
	if !strings.Contains(f.logs.String(), "reason=hs_resp_aborted") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
	f.clk.Advance(time.Minute)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("a rekey started again at the next tick")
	}
	f.clk.Advance(RekeyBackoff)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatal("no rekey after the backoff")
	}
	f.pump() // fails again
	f.clk.Advance(RekeyBackoff + time.Minute)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("the backoff did not double")
	}
	f.clk.Advance(RekeyBackoff)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatal("no rekey after the doubled backoff")
	}
	m.RespRotations = nil // the member answers plainly: the backoff ends
	f.pump()
	c = f.p.conns[cid]
	if c.kr.Current().ID() == epoch || c.RekeyFailures != 0 || !c.RekeyNotBefore.IsZero() {
		t.Fatalf("rekey after the backoff: failures %d", c.RekeyFailures)
	}
}

// A stored outgoing handshake whose hs.init names another identity key
// than this service's is dropped at start, with an alarm, instead of
// stopping the service from starting; the drop is stored.
func TestStaleOutgoingDroppedAtStart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.startRekey(f.p.conns[cid], f.clk.Now())
	f.p.Step(context.Background(), 0) // flushed
	if len(f.p.outgoing) != 1 {
		t.Fatal("no rekey stored")
	}
	ik := f.keys.IK
	f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	f.start() // fails the test if the load is refused; Start flushes
	if len(f.p.outgoing) != 0 {
		t.Fatal("the stale handshake was kept")
	}
	if !strings.Contains(f.logs.String(), "level=ERROR") || !strings.Contains(f.logs.String(), "alarm=outgoing_identity_changed") {
		t.Fatalf("no alarm:\n%s", f.logs.String())
	}
	if recs, err := f.store.Load(context.Background(), kindOutgoing); err != nil || len(recs) != 0 {
		t.Fatalf("%d outgoing records stored, %v", len(recs), err)
	}
	f.keys.IK = ik // the key put right: the record, had it stayed, would load
	f.start()
	if len(f.p.outgoing) != 0 {
		t.Fatal("the stale handshake is back after a restart")
	}
}

// A stored reconnect hs.init under another identity key is dropped at
// start and its tokens revoked, but the reconnect stays open: a fresh try
// starts at once, a second start under the same key keeps it, and once
// the key is put right, that try is dropped in turn (a second alarm) and
// the next one completes.
func TestStaleReconnectDroppedAtStart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true) // the reconnect's hs.init is stored, with its tokens
	var issued []string
	for _, og := range f.p.outgoing {
		issued = og.Issued
	}
	if len(issued) == 0 || f.p.conns[cid].ReconnectTries != 1 {
		t.Fatalf("no reconnect stored: %d tokens, tries %d", len(issued), f.p.conns[cid].ReconnectTries)
	}
	ik := f.keys.IK
	f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	f.start()
	if !strings.Contains(f.logs.String(), "alarm=outgoing_identity_changed") {
		t.Fatalf("no alarm:\n%s", f.logs.String())
	}
	if strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatal("the reconnect was ended")
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s of the dropped hs.init not revoked", j)
		}
	}
	c := f.p.conns[cid]
	if !c.Reconnecting || c.State != StateActive || c.ReconnectTries != 2 || len(f.p.outgoing) != 1 {
		t.Fatalf("reconnecting %v, state %s, tries %d, %d outgoing", c.Reconnecting, c.State, c.ReconnectTries, len(f.p.outgoing))
	}
	f.start() // still the wrong key: its own try loads and is kept
	c = f.p.conns[cid]
	if n := strings.Count(f.logs.String(), "alarm=outgoing_identity_changed"); n != 1 || !c.Reconnecting || c.ReconnectTries != 2 || len(f.p.outgoing) != 1 {
		t.Fatalf("%d alarms, reconnecting %v, tries %d, %d outgoing", n, c.Reconnecting, c.ReconnectTries, len(f.p.outgoing))
	}
	f.keys.IK = ik // put right: the try made under the wrong key is dropped in turn
	f.start()
	c = f.p.conns[cid]
	if n := strings.Count(f.logs.String(), "alarm=outgoing_identity_changed"); n != 2 || !c.Reconnecting || c.ReconnectTries != 3 {
		t.Fatalf("%d alarms, reconnecting %v, tries %d", n, c.Reconnecting, c.ReconnectTries)
	}
	m.IgnoreRevoked = true // its answer to the first hs.init is refused
	m.IgnoreForeign = true // the one signed under the wrong key is dropped
	f.pump()
	c = f.p.conns[cid]
	if c.Reconnecting || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatalf("not reconnected: reconnecting %v", c.Reconnecting)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A reconnect already on its second try when the key goes wrong spends
// its last try under the wrong key, so once the key is put right it
// cannot start another and ends: the member must connect again.
func TestStaleReconnectLastTryEnds(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	f.p.conns[cid].ReconnectTries = 2 // as after a second try
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	ik := f.keys.IK
	f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	f.start()
	if c := f.p.conns[cid]; !c.Reconnecting || c.ReconnectTries != 3 {
		t.Fatalf("reconnecting %v, tries %d", c.Reconnecting, c.ReconnectTries)
	}
	f.keys.IK = ik
	f.start()
	c := f.p.conns[cid]
	if c.Reconnecting || c.State != StateStale || !strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("reconnecting %v, state %s:\n%s", c.Reconnecting, c.State, f.logs.String())
	}
}

// A rekey of ours that no hs.resp answers within HandshakeTTL is dropped,
// and the next one waits RekeyBackoff.
func TestRekeyUnansweredBacksOff(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick() // the member never steps: no answer
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.clk.Advance(HandshakeTTL)
	f.tick()
	c := f.p.conns[cid]
	if len(f.p.outgoing) != 0 || c.RekeyFailures != 1 {
		t.Fatalf("%d outgoing, failures %d", len(f.p.outgoing), c.RekeyFailures)
	}
	f.clk.Advance(time.Minute)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("a rekey started again at the next tick")
	}
}
