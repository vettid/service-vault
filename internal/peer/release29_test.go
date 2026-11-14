package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
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
// than the table's (a mixed table: its identity record names the
// configured key) is dropped at start, with an alarm, instead of stopping
// the service from starting; the drop is stored, and its hs.init, still
// waiting in the outbox, is dropped with it (GC #9109).
func TestStaleOutgoingDroppedAtStart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.failDeposit = func(string, string) error { return errUnavailable } // the hs.init waits
	f.p.startRekey(f.p.conns[cid], f.clk.Now())
	f.p.Step(context.Background(), 0) // flushed
	f.failDeposit = nil
	var entry string
	for _, og := range f.p.outgoing {
		entry = og.InitEntry
	}
	if len(f.p.outgoing) != 1 || entry == "" || !slices.ContainsFunc(f.p.outbox, func(e *outboxEntry) bool { return e.ID == entry }) {
		t.Fatalf("no rekey waiting: %d outgoing, entry %q", len(f.p.outgoing), entry)
	}
	ik := f.keys.IK
	f.keys.IK = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	setIdentityRecord(t, f.store, f.keys.IKPublic())
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
	if recs, err := f.store.Load(context.Background(), kindOutbox); err != nil || slices.ContainsFunc(recs, func(r Record) bool { return r.ID == entry }) {
		t.Fatalf("the dropped hs.init is still in the outbox (%v)", err)
	}
	f.keys.IK = ik // the old key: the table's record now names the other one
	if err := f.startErr(); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("started under a key the record doesn't name: %v", err)
	}
}

// A start under another identity key than the table's spends no
// reconnect try and changes nothing: identity_test.go (GC #9109).

// A stored reconnect hs.init under another key than the table's (a mixed
// table: the record names the configured key) is dropped at start, its
// tokens revoked and its waiting hs.init dropped, but the reconnect stays
// open and a fresh try starts under the table's key; one already on its
// second try starts its third and last.
func TestStaleReconnectDroppedAtStart(t *testing.T) {
	for _, tc := range []struct {
		name        string
		tries, want int
	}{{"first try", 1, 2}, {"second try", 2, 3}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			m := f.member(10)
			cid := f.connect(m, "")
			b := f.backup()
			m.StartRekey()
			f.pump()
			f.failDeposit = func(string, string) error { return errUnavailable } // the hs.init waits
			f.restore(b, true)
			f.failDeposit = nil
			c := f.p.conns[cid]
			c.ReconnectTries = tc.tries
			f.p.markDirty(kindConn, cid)
			if err := f.p.flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			var issued []string
			var entry string
			for _, og := range f.p.outgoing {
				issued, entry = og.Issued, og.InitEntry
			}
			if len(issued) == 0 || entry == "" {
				t.Fatalf("no reconnect waiting: %d tokens, entry %q", len(issued), entry)
			}
			f.keys.IK = wrongKey
			setIdentityRecord(t, f.store, f.keys.IKPublic())
			f.start()
			if !strings.Contains(f.logs.String(), "alarm=outgoing_identity_changed") || strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
				t.Fatalf("alarms:\n%s", f.logs.String())
			}
			for _, j := range issued {
				if tk := f.p.issued[j]; tk == nil || !tk.Denied {
					t.Fatalf("token %s of the dropped hs.init not revoked", j)
				}
			}
			if slices.ContainsFunc(f.p.outbox, func(e *outboxEntry) bool { return e.ID == entry }) {
				t.Fatal("the dropped hs.init is still waiting")
			}
			c = f.p.conns[cid]
			if !c.Reconnecting || c.State != StateActive || c.ReconnectTries != tc.want || len(f.p.outgoing) != 1 {
				t.Fatalf("reconnecting %v, state %s, tries %d, %d outgoing", c.Reconnecting, c.State, c.ReconnectTries, len(f.p.outgoing))
			}
		})
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

// answerLinkedRekey has the member rotate A->B (the link not followed) and
// rekey from B carrying it; the service answers. It returns the link and
// the service's epoch before.
func answerLinkedRekey(t *testing.T, f *fixture, m *peertest.Member, cid string) (*handshake.Rotation, [suite.EpochIDSize]byte) {
	t.Helper()
	epoch := f.p.conns[cid].kr.Current().ID()
	r := m.RotateIdentity(40, true)
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	return r, epoch
}

// The member's identity.rotate statements A->B and B->C overtake the
// hs.fin of its rekey from B (the relay keeps no order): following them
// drops that answer (§3.4.1 H5), and the late hs.fin installs nothing,
// so the stored key stays C and nothing is followed twice.
func TestLateRekeyFinAfterRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1, epoch := answerLinkedRekey(t, f, m, cid)
	m.SendRotation(r1)
	m.SendRotation(m.RotateIdentity(50, true)) // B->C
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	keyC := m.IK.Public().(ed25519.PublicKey)
	c := f.p.conns[cid]
	if !keyC.Equal(c.Peer.IK) || len(c.Chain) != 2 || len(f.p.awaiting) != 0 {
		t.Fatalf("chain %d, %d awaiting", len(c.Chain), len(f.p.awaiting))
	}
	if !strings.Contains(f.logs.String(), "reason=rekey_answer_dropped") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
	got := len(m.Got)
	m.IgnoreStray = true
	f.pump() // the member's hs.fin from B arrives
	c = f.p.conns[cid]
	if !keyC.Equal(c.Peer.IK) || len(c.Chain) != 2 || c.kr.Current().ID() != epoch || confirmed(m, got) {
		t.Fatalf("the late hs.fin rolled back: chain %d", len(c.Chain))
	}
}

// At the hs.fin itself, the signer is checked again against the key and
// links followed meanwhile (here moved past it without the answer being
// dropped first): the epoch is not installed, nothing is followed, and
// ancestor_ik is audited.
func TestRekeyFinCheckedAgainstFollowed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1, epoch := answerLinkedRekey(t, f, m, cid)
	r2 := m.RotateIdentity(50, true) // B->C
	c := f.p.conns[cid]
	c.Chain = append(c.Chain, r1.Marshal(), r2.Marshal())
	c.Peer.IK = m.IK.Public().(ed25519.PublicKey)
	f.pump()
	c = f.p.conns[cid]
	if !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 2 || c.kr.Current().ID() != epoch {
		t.Fatalf("installed past the followed key: chain %d", len(c.Chain))
	}
	if !strings.Contains(f.logs.String(), "reason=ancestor_ik") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// Another copy's identity.rotate A->X arrives while the member's rekey
// carrying A->B awaits hs.fin: A has two successors, and the connection
// is suspended (§3.4), not left on X.
func TestRotationConflictWithPendingRekey(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	answerLinkedRekey(t, f, m, cid)
	x := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32))
	xkem, err := suite.NewPrivateKey(bytes.Repeat([]byte{67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rx, err := handshake.NewRotation(orig, x, xkem.Public())
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotation(rx)
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; c.State != StateSuspended || len(f.p.awaiting) != 0 {
		t.Fatalf("state %s, %d awaiting", c.State, len(f.p.awaiting))
	}
}

// The same conflict judged at the hs.fin (the chain moved without the
// answer being judged first): suspended, nothing installed.
func TestRotationConflictAtFin(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	_, epoch := answerLinkedRekey(t, f, m, cid)
	x := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{66}, 32))
	xkem, err := suite.NewPrivateKey(bytes.Repeat([]byte{67}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rx, err := handshake.NewRotation(orig, x, xkem.Public())
	if err != nil {
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	c.Chain = append(c.Chain, rx.Marshal())
	c.Peer.IK = x.Public().(ed25519.PublicKey)
	m.IgnoreStray = true
	f.pump()
	c = f.p.conns[cid]
	if c.State != StateSuspended || c.kr.Current().ID() != epoch {
		t.Fatalf("state %s", c.State)
	}
}

// A member's reconnect whose signer the links followed since no longer
// lead to (its identity.rotate statements overtook its hs.fin) is not
// applied at hs.fin: the stored key stays, nothing is followed twice.
func TestLateReconnectFinAfterRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1 := m.RotateIdentity(40, true) // A->B
	m.Reconnect()                    // from B, carrying A->B
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	m.SendRotation(r1)
	m.Rotations = nil
	m.SendRotation(m.RotateIdentity(50, true)) // B->C
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	keyC := m.IK.Public().(ed25519.PublicKey)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c := f.p.conns[cid]
	if !keyC.Equal(c.Peer.IK) || len(c.Chain) != 2 {
		t.Fatalf("the late reconnect hs.fin rolled back: chain %d", len(c.Chain))
	}
	if !strings.Contains(f.logs.String(), "reason=ancestor_ik") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// A member's reconnect, completed at its hs.fin, is confirmed with
// hs.confirm under the new epoch (§6.3.1 Responder), as a rekey is.
func TestMemberReconnectConfirmed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	got := len(m.Got)
	m.Reconnect()
	f.pump()
	if c := f.p.conns[cid]; c.kr.Current().ID() != m.KR.Current().ID() || !confirmed(m, got) {
		t.Fatal("no hs.confirm after the member's reconnect")
	}
}

// The backoff doubles up to RekeyBackoffMax and no further; a stored
// wait longer than that (the clock went back) does not hold a rekey.
func TestRekeyBackoffCap(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.p.startRekey(c, f.clk.Now())
	var og *outgoing
	for _, o := range f.p.outgoing {
		og = o
	}
	now := f.clk.Now()
	for i, want := range []time.Duration{1, 2, 4, 8, 16, 24, 24} {
		f.p.rekeyFailed(og, now)
		if got := c.RekeyNotBefore.Sub(now); got != want*time.Hour {
			t.Fatalf("failure %d: waits %v, want %vh", i+1, got, want)
		}
	}
	f.p.dropOutgoing(og.ID)
	c.RekeyNotBefore = now.Add(RekeyBackoffMax + time.Hour)
	f.p.startRekey(c, now)
	if len(f.p.outgoing) != 1 {
		t.Fatal("a wait past the most held the rekey")
	}
}

// Crossing rekeys between a rotated member and the service, each
// carrying the link: the lower th1 wins (§6.5), and either way the pair
// ends on one epoch with the link followed once.
func TestRekeyCrossingWithLinks(t *testing.T) {
	for i := 0; i < 6; i++ {
		f := newFixture(t)
		m := f.member(byte(10 + i))
		cid := f.connect(m, "")
		epoch := f.p.conns[cid].kr.Current().ID()
		r := m.RotateIdentity(byte(40+i), true)
		m.RespRotations = []*handshake.Rotation{r}
		f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
		m.StartRekeyWithLinks() // in the member's mailbox for us, not yet read
		f.tick()                // ours starts too
		if len(f.p.outgoing) != 1 {
			t.Fatalf("run %d: no crossing: %d outgoing", i, len(f.p.outgoing))
		}
		m.IgnoreStray = true
		f.pump()
		c := f.p.conns[cid]
		if c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() {
			t.Fatalf("run %d: the pair is not on one new epoch", i)
		}
		if !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 1 || len(f.p.outgoing) != 0 {
			t.Fatalf("run %d: chain %d, %d outgoing", i, len(c.Chain), len(f.p.outgoing))
		}
	}
}

// The member's identity.rotate A->B arrives after its rekey from B
// (carrying A->B) was answered: following it moves the stored key to the
// one the answer was signed with, so the answer stays, and its hs.fin
// completes the rekey without following the link twice.
func TestRekeyAnswerKeptWhenRotationCatchesUp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1, epoch := answerLinkedRekey(t, f, m, cid)
	m.SendRotation(r1)
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 || len(f.p.conns[cid].Chain) != 1 {
		t.Fatalf("%d awaiting, chain %d", len(f.p.awaiting), len(f.p.conns[cid].Chain))
	}
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() == epoch || c.kr.Current().ID() != m.KR.Current().ID() || len(c.Chain) != 1 {
		t.Fatalf("rekey not completed: chain %d", len(c.Chain))
	}
}

// Two copies of a member: one reconnects from B with [A->B], the other
// rekeys from X with [A->X]; both are answered. At the reconnect's hs.fin,
// following A->B judges the rekey answer's A->X: a second successor of A
// suspends the connection, and the reconnect does not undo it (no epoch,
// state stays suspended).
func TestForkJudgedAtReconnectFinStaysSuspended(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	orig := m.IK
	m.RotateIdentity(50, true) // A->B
	m.Reconnect()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	f.p.conns[cid].Seen = nil // as a record from before seen links (R29-K8): the fork is judged at hs.fin
	m.IK, m.Rotations = orig, nil
	m.RotateIdentity(40, true) // A->X, the other copy
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 2 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Step() // both hs.fin, the reconnect's first
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	if c.State != StateSuspended || c.kr.Current().ID() != epoch || len(f.p.awaiting) != 0 {
		t.Fatalf("state %s, %d awaiting", c.State, len(f.p.awaiting))
	}
	if strings.Contains(f.logs.String(), "reason=reconnect_record_bad") {
		t.Fatal("a suspension reported as a bad record")
	}
}

// The same fork judged at a rekey's hs.fin: two rekey answers, from B
// with [A->B] and from X with [A->X]; the first hs.fin suspends the
// connection and installs no epoch.
func TestForkJudgedAtRekeyFinStaysSuspended(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	orig := m.IK
	m.RotateIdentity(50, true) // A->B
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	f.p.conns[cid].Seen = nil // as a record from before seen links (R29-K8): the fork is judged at hs.fin
	m.IK, m.Rotations = orig, nil
	m.RotateIdentity(40, true) // A->X
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 2 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Step()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	if c.State != StateSuspended || c.kr.Current().ID() != epoch {
		t.Fatalf("state %s", c.State)
	}
}

// A rekey from C carrying [A->B, B->C] is answered; the late
// identity.rotate statements A->B, then B->C, move the stored key toward
// its signer, so the answer stays, and its hs.fin completes the rekey.
func TestRekeyAnswerReachedKeptAcrossRotations(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1 := m.RotateIdentity(40, true) // A->B
	r2 := m.RotateIdentity(50, true) // B->C
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for _, r := range []*handshake.Rotation{r1, r2} {
		m.SendRotation(r)
		if _, err := f.p.Step(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
		if len(f.p.awaiting) != 1 {
			t.Fatal("a legitimate answer was dropped")
		}
	}
	f.pump()
	c := f.p.conns[cid]
	if c.kr.Current().ID() != m.KR.Current().ID() || !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 2 {
		t.Fatalf("rekey not completed: chain %d", len(c.Chain))
	}
}

// A rekey answer stored before signers were kept (no Follow) is dropped
// when the service follows a rotation: its signer is unknown.
func TestLegacyRekeyAnswerDroppedAtRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for _, aw := range f.p.awaiting {
		aw.Follow = nil // as stored by the previous release
	}
	m.SendRotation(m.RotateIdentity(40, true))
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 0 || len(f.p.conns[cid].Chain) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
}

// A member's reconnect from A without links, answered; its identity.rotate
// A->B is then followed, and the reconnect's late hs.fin, signed with A, is
// refused (ancestor_ik, audited once): the stored key stays B.
func TestLateLinklessReconnectFinRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Reconnect() // from A, no links
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	m.SendRotation(m.RotateIdentity(40, true))
	m.Rotations = nil
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	keyB := m.IK.Public().(ed25519.PublicKey)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c := f.p.conns[cid]
	if !keyB.Equal(c.Peer.IK) || len(c.Chain) != 1 {
		t.Fatalf("chain %d", len(c.Chain))
	}
	if !strings.Contains(f.logs.String(), "reason=ancestor_ik") || strings.Contains(f.logs.String(), "reason=reconnect_record_bad") {
		t.Fatalf("audit:\n%s", f.logs.String())
	}
}

// A reconnect answer stored by the previous build (no Signer, its links
// as computed then) goes through the same check at its hs.fin.
func TestLegacyReconnectRecordChecked(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r1 := m.RotateIdentity(40, true) // A->B
	m.Reconnect()                    // from B, carrying A->B
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for _, aw := range f.p.awaiting {
		if aw.Reconnect == nil || len(aw.Reconnect.Links) != 1 {
			t.Fatal("no legacy links recorded")
		}
		aw.Reconnect.Signer = nil // as stored by the previous build
	}
	m.SendRotation(r1)
	m.Rotations = nil
	m.SendRotation(m.RotateIdentity(50, true)) // B->C
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	keyC := m.IK.Public().(ed25519.PublicKey)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c := f.p.conns[cid]
	if !keyC.Equal(c.Peer.IK) || len(c.Chain) != 2 || !strings.Contains(f.logs.String(), "reason=ancestor_ik") {
		t.Fatalf("legacy record rolled back: chain %d", len(c.Chain))
	}
}

// A rekey answer dropped at a rotation takes its hs.resp with it when that
// is not yet deposited.
func TestDroppedAnswerTakesItsResp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	f.failDeposit = func(mailbox, _ string) error {
		if mailbox == mb {
			return errUnavailable
		}
		return nil
	}
	r1 := m.RotateIdentity(40, true) // A->B
	m.StartRekeyWithLinks()          // from B
	r2 := m.RotateIdentity(50, true) // B->C
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var entry string
	for _, aw := range f.p.awaiting {
		entry = aw.RespEntry
	}
	held := false
	for _, e := range f.p.outbox {
		held = held || e.ID == entry
	}
	if entry == "" || !held {
		t.Fatal("the hs.resp is not waiting in the outbox")
	}
	m.SendRotation(r1)
	m.SendRotation(r2) // the stored key moves past B
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 0 {
		t.Fatal("the answer was kept")
	}
	for _, e := range f.p.outbox {
		if e.ID == entry {
			t.Fatal("the dropped answer's hs.resp is still in the outbox")
		}
	}
}

// A reconnect answer stored by the previous build without links (no
// Signer) is dropped at any rotation: its signer is unknown, so a holder
// of the rotated-away key could otherwise still finish it.
func TestLegacyLinklessReconnectDroppedAtRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	m.Reconnect() // from A, no links
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var issued []string
	for _, aw := range f.p.awaiting {
		aw.Reconnect.Signer = nil // as stored by the previous build
		issued = aw.Reconnect.Issued
	}
	if len(issued) == 0 {
		t.Fatal("no tokens minted for the answer")
	}
	m.SendRotation(m.RotateIdentity(40, true))
	m.Rotations = nil
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 0 || !strings.Contains(f.logs.String(), "reason=reconnect_answer_dropped") {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s of the dropped answer not revoked", j)
		}
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	if c := f.p.conns[cid]; c.kr.Current().ID() != epoch || len(c.Chain) != 1 {
		t.Fatalf("the legacy reconnect completed: chain %d", len(c.Chain))
	}
}

// Our reconnect (after a restore) while another copy's rekey answer
// carrying [A->X] is still open: the member's hs.resp carries [A->B], and
// following it judges A->X. The connection stays suspended: no epoch, no
// hs.fin, our reconnect's tokens revoked.
func TestForkJudgedAtOurReconnectRespStaysSuspended(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	orig := m.IK
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	f.failDeposit = func(mailbox, _ string) error {
		if mailbox == mb {
			return errUnavailable // the rekey's hs.resp waits; the restore's reconnect drops it
		}
		return nil
	}
	m.RotateIdentity(40, true) // A->X, one copy
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	f.failDeposit = nil
	f.restore(f.backup(), true) // our reconnect starts; the answer stays
	// As a record from before seen links (R29-K8): the fork is found only
	// once the hs.resp's links are followed, which this test covers.
	f.p.conns[cid].Seen = nil
	for _, aw := range f.p.awaiting {
		rid := aw.RespEntry
		f.p.dropOutbox(func(e *outboxEntry) bool { return e.ID == rid }) // its hs.resp is lost
	}
	var issued []string
	for _, og := range f.p.outgoing {
		issued = og.Issued
	}
	if len(issued) == 0 || len(f.p.awaiting) != 1 {
		t.Fatalf("no reconnect: %d tokens, %d awaiting", len(issued), len(f.p.awaiting))
	}
	m.IK, m.Rotations = orig, nil
	m.RotateIdentity(50, true) // A->B, the other copy, answers our reconnect
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c := f.p.conns[cid]
	if c.State != StateSuspended || c.kr.Current().ID() != epoch {
		t.Fatalf("state %s", c.State)
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s of our reconnect not revoked", j)
		}
	}
	if strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatal("reconnect_failed on a suspended connection")
	}
	if n := strings.Count(f.logs.String(), `msg="reconnect started"`); n != 1 {
		t.Fatalf("%d reconnects started", n)
	}
}

// A legacy reconnect record carrying [A->B] (no Signer) and another copy's
// rekey answer carrying [A->X]: at the reconnect's hs.fin, following A->B
// judges A->X, and the connection stays suspended.
func TestForkJudgedAtLegacyReconnectFinStaysSuspended(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	orig := m.IK
	m.RotateIdentity(50, true) // A->B
	m.Reconnect()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for _, aw := range f.p.awaiting {
		aw.Reconnect.Signer = nil // as stored by the previous build
	}
	f.p.conns[cid].Seen = nil // as a record from before seen links (R29-K8): the fork is judged at hs.fin
	m.IK, m.Rotations = orig, nil
	m.RotateIdentity(40, true) // A->X
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 2 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Step()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if c := f.p.conns[cid]; c.State != StateSuspended || c.kr.Current().ID() != epoch {
		t.Fatalf("state %s", c.State)
	}
}

// A cycle (A->B followed, then B->A) is refused, so that a later A->X is
// still judged against A's successor B (§3.4).
func TestRotationCycleRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	m.SendRotation(m.RotateIdentity(40, true)) // A->B
	f.pump()
	keyB := m.IK.Public().(ed25519.PublicKey)
	akem, err := suite.NewPrivateKey(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	back, err := handshake.NewRotation(m.IK, orig, akem.Public()) // B->A
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotation(back)
	f.pump()
	c := f.p.conns[cid]
	if !keyB.Equal(c.Peer.IK) || len(c.Chain) != 1 || !strings.Contains(f.logs.String(), "reason=ik_rollback") {
		t.Fatalf("a cycle was followed: chain %d", len(c.Chain))
	}
}

// cycleLinks returns A->B and B->A for the member's key A (and its own
// KEM, as the service stored it), leaving the member on A: a chain that
// resolves back to A.
func cycleLinks(t *testing.T, f *fixture, m *peertest.Member, cid string) []*handshake.Rotation {
	t.Helper()
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{40}, 32))
	bkem, err := suite.NewPrivateKey(bytes.Repeat([]byte{41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	akem, err := suite.ParsePublicKey(f.p.conns[cid].Peer.KEM)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := handshake.NewRotation(m.IK, b, bkem.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := handshake.NewRotation(b, m.IK, akem)
	if err != nil {
		t.Fatal(err)
	}
	return []*handshake.Rotation{ab, ba}
}

// A member's rekey carrying a cycle [A->B, B->A], signed by A: the
// handshake resolves it to A, but following it would revisit A, so the
// hs.fin is refused and nothing is followed.
func TestRekeyCycleRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	m.Rotations = cycleLinks(t, f, m, cid)
	m.StartRekeyWithLinks()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatal("the rekey was not answered (the handshake refused the cycle itself)")
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c := f.p.conns[cid]
	if len(c.Chain) != 0 || c.kr.Current().ID() != epoch || !strings.Contains(f.logs.String(), "reason=bad_rotation") {
		t.Fatalf("a cycle was followed: chain %d", len(c.Chain))
	}
}

// The member's hs.resp to our rekey carries a cycle: the rekey is aborted
// (no hs.fin, no epoch, nothing followed) and backs off.
func TestServiceRekeyRespCycleRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	m.RespRotations = cycleLinks(t, f, m, cid)
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	f.pump()
	c := f.p.conns[cid]
	if len(c.Chain) != 0 || c.kr.Current().ID() != epoch || m.KR.Current().ID() != epoch || c.RekeyFailures != 1 {
		t.Fatalf("a cycle was followed: chain %d, failures %d", len(c.Chain), c.RekeyFailures)
	}
	if !strings.Contains(f.logs.String(), "reason=bad_rotation") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// The member's hs.resp to our reconnect carries a cycle: the reconnect
// ends (reconnect_failed), nothing is followed.
func TestOurReconnectRespCycleRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Rotations = cycleLinks(t, f, m, cid)
	f.restore(f.backup(), true)
	var issued []string
	for _, og := range f.p.outgoing {
		issued = og.Issued
	}
	f.pump()
	c := f.p.conns[cid]
	if len(c.Chain) != 0 || c.Reconnecting || !strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("a cycle was followed: chain %d, reconnecting %v", len(c.Chain), c.Reconnecting)
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s not revoked", j)
		}
	}
}

// A member's rekey from A without links, answered; identity.rotate A->B
// is followed, which drops the answer (its signer is no longer the stored
// key), and the late hs.fin installs nothing.
func TestLateLinklessRekeyFinAfterRotation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	epoch := f.p.conns[cid].kr.Current().ID()
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	m.SendRotation(m.RotateIdentity(40, true))
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 0 {
		t.Fatal("the answer was kept")
	}
	m.IgnoreStray = true
	f.pump()
	if c := f.p.conns[cid]; c.kr.Current().ID() != epoch || len(c.Chain) != 1 {
		t.Fatalf("the late hs.fin installed: chain %d", len(c.Chain))
	}
}

// A cycle back past the stored key's predecessor (A->B, B->C followed,
// then C->A) is refused as well: the check covers the whole chain.
func TestRotationCycleTwoBack(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	orig := m.IK
	m.SendRotation(m.RotateIdentity(40, true)) // A->B
	m.SendRotation(m.RotateIdentity(50, true)) // B->C
	m.Rotations = nil
	f.pump()
	if len(f.p.conns[cid].Chain) != 2 {
		t.Fatalf("chain %d", len(f.p.conns[cid].Chain))
	}
	akem, err := suite.NewPrivateKey(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	back, err := handshake.NewRotation(m.IK, orig, akem.Public()) // C->A
	if err != nil {
		t.Fatal(err)
	}
	m.SendRotation(back)
	f.pump()
	c := f.p.conns[cid]
	if !m.IK.Public().(ed25519.PublicKey).Equal(c.Peer.IK) || len(c.Chain) != 2 || !strings.Contains(f.logs.String(), "reason=ik_rollback") {
		t.Fatalf("a cycle was followed: chain %d", len(c.Chain))
	}
}
