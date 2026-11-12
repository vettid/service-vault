package peer

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
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
	f.p.Step(context.Background(), 0)
	if len(f.p.outbox) != 0 {
		t.Fatalf("%d deposits queued: the rekey was answered", len(f.p.outbox))
	}
	f.pump()
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
