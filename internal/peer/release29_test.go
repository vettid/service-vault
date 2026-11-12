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

// The service advertises no features, so a release-29 member vault sends
// it no identity links in a rekey (VAULT-MESSAGING 0.86.2 erratum 1). One
// that does is refused, as before the handshake library parsed them: no
// answer, and the epoch and the stored identity key don't move.
func TestRekeyWithLinksRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stored := f.p.conns[cid].Peer.IK
	epoch := f.p.conns[cid].kr.Current().ID()
	m.RotateIdentity(40, true) // a link the service has not followed
	if len(m.Rotations) != 1 {
		t.Fatal("no link queued")
	}
	m.StartRekeyWithLinks()
	f.pump()
	if m.KR.Current().ID() != epoch {
		t.Fatal("the member got an answer: its epoch moved")
	}
	c := f.p.conns[cid]
	if c.kr.Current().ID() != epoch {
		t.Fatal("the epoch moved on a rekey with links")
	}
	if !ed25519.PublicKey(stored).Equal(c.Peer.IK) {
		t.Fatal("the stored identity key changed")
	}
	if len(f.p.awaiting) != 0 {
		t.Fatal("the rekey was answered")
	}
	if !strings.Contains(f.logs.String(), "reason=rekey_rejected") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// An hs.resp to the service's own rekey that carries identity links
// aborts the rekey, as before: no hs.fin, the epoch and the stored key
// stay, and the rekey is dropped.
func TestServiceRekeyRespWithLinksAborted(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	stored := f.p.conns[cid].Peer.IK
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
	if len(f.p.outgoing) != 0 {
		t.Fatal("the rekey is still outgoing")
	}
	if m.KR.Current().ID() != epoch {
		t.Fatal("the member got an hs.fin: its epoch moved")
	}
	if c.kr.Current().ID() != epoch {
		t.Fatal("the epoch moved on an hs.resp with links")
	}
	if !ed25519.PublicKey(stored).Equal(c.Peer.IK) {
		t.Fatal("the stored identity key changed")
	}
	if !strings.Contains(f.logs.String(), "reason=hs_resp_aborted") {
		t.Fatalf("not audited:\n%s", f.logs.String())
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

// An hs.confirm (0.86.0, §6.3.1), which this service does not implement,
// is answered unsupported_type like any type it does not know, and the
// connection stays active. A message whose inner part carries a valid
// features list is handled. (A malformed list is now refused by the
// library, like any malformed known member, §5.3: vettid-vault's
// envelope.TestInnerFeatures; this package's test member cannot encode
// one.)
func TestRelease29MessagesTolerated(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	confirm := m.NewID()
	m.SendInner(&envelope.Inner{ID: confirm, Type: handshake.TypeConfirm, TS: f.clk.Now(), Body: []byte("{}")})
	f.pump()
	if c := f.p.conns[cid]; c.State != StateActive {
		t.Fatalf("state %s after hs.confirm", c.State)
	}
	answered := false
	for _, in := range m.Got {
		if in.Re == confirm && in.Error != nil && in.Error.Code == "unsupported_type" {
			answered = true
		}
	}
	if !answered {
		t.Fatal("hs.confirm not answered unsupported_type")
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
// The rekey is refused (pinning today's behaviour until this service
// follows S8 links), and the key the service followed stays.
func TestRelease29RotatedMemberRekeyRefused(t *testing.T) {
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
	if c.kr.Current().ID() != epoch || m.KR.Current().ID() != epoch {
		t.Fatal("the epoch moved")
	}
	if !followed.Equal(c.Peer.IK) {
		t.Fatal("the followed key changed")
	}
	if !strings.Contains(f.logs.String(), "reason=rekey_rejected") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// An hs.resp to the service's rekey whose chain is forged (a link that
// does not start at the member's key) aborts the rekey: no epoch move,
// no hs.fin. This pins vettid-vault's own refusal of the chain (the
// handshake fails before the service sees the links);
// TestServiceRekeyRespWithLinksAborted pins the service's guard.
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

// staleReconnect stores a reconnect hs.init (after a marked restore),
// then restarts under another identity key; it returns the original key
// and the dropped hs.init's tokens.
func staleReconnect(t *testing.T, f *fixture, m *peertest.Member) (ed25519.PrivateKey, []string) {
	t.Helper()
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true) // the reconnect's hs.init is stored, with its tokens
	var issued []string
	for _, og := range f.p.outgoing {
		issued = og.Issued
	}
	if len(issued) == 0 || len(f.p.outgoing) != 1 {
		t.Fatalf("no reconnect stored: %d tokens, %d outgoing", len(issued), len(f.p.outgoing))
	}
	ik := f.keys.IK
	f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	f.start()
	return ik, issued
}

// held checks a reconnect held under a wrong key: still open, on its
// first try, nothing outgoing, and the key it was made under marked.
func held(t *testing.T, f *fixture, cid string, ik ed25519.PrivateKey) {
	t.Helper()
	c := f.p.conns[cid]
	if !c.Reconnecting || c.State != StateActive || c.ReconnectTries != 1 || len(f.p.outgoing) != 0 ||
		!bytes.Equal(c.ReconnectIK, ik.Public().(ed25519.PublicKey)) {
		t.Fatalf("reconnecting %v, state %s, tries %d, %d outgoing, mark %x", c.Reconnecting, c.State, c.ReconnectTries, len(f.p.outgoing), c.ReconnectIK)
	}
}

// A stored reconnect hs.init under another identity key is dropped at
// start, its tokens revoked, and the reconnect held: starts under a wrong
// key (the same one, or yet another) start no try, deposit and revoke
// nothing and raise no new alarm, and the mark survives each restart.
// The first start with the right key resumes it with one try, and it
// completes.
func TestStaleReconnectHeldUntilKeyRight(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ik, issued := staleReconnect(t, f, m)
	if strings.Count(f.logs.String(), "alarm=outgoing_identity_changed") != 1 || strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("alarms:\n%s", f.logs.String())
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s of the dropped hs.init not revoked", j)
		}
	}
	held(t, f, cid, ik)
	deposits, revokes := 0, len(f.revokes)
	f.failDeposit = func(string, string) error { deposits++; return nil }
	for i, seed := range []byte{88, 88, 89} { // the same wrong key, then another
		f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
		f.start()
		f.tick()
		held(t, f, cid, ik)
		if deposits != 0 || len(f.revokes) != revokes {
			t.Fatalf("start %d: %d deposits, %d revocations more", i, deposits, len(f.revokes)-revokes)
		}
	}
	if n := strings.Count(f.logs.String(), "alarm=outgoing_identity_changed"); n != 1 {
		t.Fatalf("%d alarms under the wrong key", n)
	}
	f.failDeposit = nil
	f.keys.IK = ik // put right: one try, no new alarm
	f.start()
	c := f.p.conns[cid]
	if !c.Reconnecting || c.ReconnectTries != 2 || len(c.ReconnectIK) != 0 || len(f.p.outgoing) != 1 ||
		strings.Count(f.logs.String(), "alarm=outgoing_identity_changed") != 1 {
		t.Fatalf("reconnecting %v, tries %d, mark %x, %d outgoing", c.Reconnecting, c.ReconnectTries, c.ReconnectIK, len(f.p.outgoing))
	}
	m.IgnoreRevoked = true // its answer to the dropped hs.init is refused
	f.pump()
	c = f.p.conns[cid]
	if c.Reconnecting || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatalf("not reconnected: reconnecting %v", c.Reconnecting)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A reconnect held under a wrong key that is never put right ends at
// ReconnectTimeout from its start (reconnect_failed), and the mark goes.
func TestStaleReconnectHeldTimesOut(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ik, _ := staleReconnect(t, f, m)
	held(t, f, cid, ik)
	f.clk.Advance(ReconnectTimeout)
	f.tick()
	c := f.p.conns[cid]
	if c.Reconnecting || c.State != StateStale || len(c.ReconnectIK) != 0 || !strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("reconnecting %v, state %s, mark %x", c.Reconnecting, c.State, c.ReconnectIK)
	}
}
