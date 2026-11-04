package peer

import (
	"context"
	"crypto/ed25519"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The governance key is pinned at the first signed response and moves with
// no later sign-in: AuthKey follows every sign-in (ordinary sign-ins keep
// working), GovKey only a re-pin.
func TestGovKeyDoesNotMoveBySignIn(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	signIn := func(key ed25519.PrivateKey) *Event {
		t.Helper()
		before := len(f.ev.of(EventSignInApproved))
		if _, err := f.p.Authenticate(ctx, cid, "Approve", peerwire.PurposeApproval, 2*time.Minute); err != nil {
			t.Fatal(err)
		}
		f.pump()
		ch := m.Challenges[len(m.Challenges)-1]
		r, err := peerwire.SignConnAuth(key, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), ch, f.clk.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
		f.pump()
		ap := f.ev.of(EventSignInApproved)
		if len(ap) != before+1 {
			t.Fatalf("not approved: %d", len(ap))
		}
		return ap[before]
	}
	if e := signIn(m.Cred); e.KeyChanged || e.GovKeyChanged {
		t.Fatalf("first pin: %+v", e)
	}
	gov := append([]byte(nil), f.p.conns[cid].GovKey...)
	if !ed25519.PublicKey(gov).Equal(m.Cred.Public()) {
		t.Fatal("governance key not pinned with the first")
	}
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	if e := signIn(other); !e.KeyChanged || !e.GovKeyChanged {
		t.Fatalf("a changed key: %+v", e)
	}
	// The ordinary pin moved; the governance key did not.
	if !ed25519.PublicKey(f.p.conns[cid].AuthKey).Equal(other.Public()) || string(f.p.conns[cid].GovKey) != string(gov) {
		t.Fatal("pins")
	}
	// Every later sign-in with the new key: no longer a change from the
	// ordinary pin, still not the governance key.
	if e := signIn(other); e.KeyChanged || !e.GovKeyChanged {
		t.Fatalf("a later sign-in: %+v", e)
	}
	// A re-pin for another key than the credential key does nothing.
	if ok, err := f.p.RepinGov(ctx, cid, gov); err != nil || ok {
		t.Fatalf("re-pin to a stale key: %v %v", ok, err)
	}
	if ok, err := f.p.RepinGov(ctx, cid, other.Public().(ed25519.PublicKey)); err != nil || !ok {
		t.Fatalf("re-pin: %v %v", ok, err)
	}
	if e := signIn(other); e.KeyChanged || e.GovKeyChanged {
		t.Fatalf("after the re-pin: %+v", e)
	}
	if ci, _ := f.p.Connection(cid); string(ci.GovKey) != string(other.Public().(ed25519.PublicKey)) {
		t.Fatal("ConnectionInfo.GovKey")
	}
}

// An admin from before the governance key: PinGov with onlyIfEmpty pins it
// to the credential key once, and a connection with no governance key
// reports every approval as not on it.
func TestGovKeyMigration(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	if ok, _ := f.p.PinGov(ctx, cid, nil, true); ok {
		t.Fatal("pinned with no credential key")
	}
	if _, err := f.p.Authenticate(ctx, cid, "Approve", peerwire.PurposeApproval, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	f.p.mu.Lock()
	f.p.conns[cid].GovKey = nil // as stored before the governance key existed
	f.p.mu.Unlock()
	if ok, err := f.p.PinGov(ctx, cid, nil, true); err != nil || !ok {
		t.Fatalf("migrate: %v %v", ok, err)
	}
	if ok, _ := f.p.PinGov(ctx, cid, nil, true); ok {
		t.Fatal("pinned twice")
	}
	if ci, _ := f.p.Connection(cid); string(ci.GovKey) != string(ci.AuthKey) || len(ci.GovKey) == 0 {
		t.Fatal("not pinned to the credential key")
	}
}

// The service vault starts its approvals before the peer has loaded its
// state: PinGov and RepinGov then know no connection and say so (ErrNotFound)
// instead of reporting nothing to do, and the pin survives a restart.
func TestGovKeyBeforeAndAfterPeerLoad(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	if _, err := f.p.Authenticate(ctx, cid, "Approve", peerwire.PurposeApproval, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if ok, err := f.p.PinGov(ctx, "nobody", nil, true); ok || err != ErrNotFound {
		t.Fatalf("unknown connection: %v %v", ok, err)
	}
	// A new process: created, not started.
	p, err := New(Config{Log: f.p.cfg.Log, Keys: f.keys, Relay: testRelay{f.sv, f}, RelayURL: peertest.RelayURL, Store: f.store,
		Events: f.ev, Now: f.clk.Now, Profile: Profile{FirstName: "VettID", LastName: "Member Service"}, AfterRestore: f.afterRestore, Votes: f.votes})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := p.PinGov(ctx, cid, nil, true); ok || err != ErrNotFound {
		t.Fatalf("before the load: %v %v", ok, err)
	}
	if ok, err := p.RepinGov(ctx, cid, m.Cred.Public().(ed25519.PublicKey)); ok || err != ErrNotFound {
		t.Fatalf("re-pin before the load: %v %v", ok, err)
	}
	if err := p.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if ci, ok := p.Connection(cid); !ok || !ed25519.PublicKey(ci.GovKey).Equal(m.Cred.Public()) {
		t.Fatal("the governance key did not survive the restart")
	}
}

// A delivered connection.authenticate.rotated moves both pins along the
// chain from each (VAULT-MESSAGING 0.83.9 §10.4): a second delivery that
// starts before the pins, as the member's vault sends it, is followed from
// them; a chain that never starts at a pin moves nothing.
func TestRotatedChainFollowedFromPins(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	if _, err := f.p.Authenticate(ctx, cid, "Approve", peerwire.PurposeApproval, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[len(m.Challenges)-1], f.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	k0 := m.Cred
	k1 := ed25519.NewKeyFromSeed(bytesOf(0x51))
	k2 := ed25519.NewKeyFromSeed(bytesOf(0x52))
	r01, err := credwire.NewKeyRotation(k0, k1)
	if err != nil {
		t.Fatal(err)
	}
	r12, err := credwire.NewKeyRotation(k1, k2)
	if err != nil {
		t.Fatal(err)
	}
	pins := func(want ed25519.PrivateKey) {
		t.Helper()
		c := f.p.conns[cid]
		if !ed25519.PublicKey(c.AuthKey).Equal(want.Public()) || !ed25519.PublicKey(c.GovKey).Equal(want.Public()) {
			t.Fatalf("pins %x %x", c.AuthKey, c.GovKey)
		}
	}
	pins(k0)
	m.Send(peerwire.TypeConnAuthRotated, peerwire.ConnAuthRotatedBody([]*credwire.KeyRotation{r01}))
	f.pump()
	pins(k1)
	// The next chain starts at the key the member last signed with (K0).
	m.Send(peerwire.TypeConnAuthRotated, peerwire.ConnAuthRotatedBody([]*credwire.KeyRotation{r01, r12}))
	f.pump()
	pins(k2)
	// A repeated delivery, ending at the pins, changes nothing and is not
	// logged as a rejection.
	m.Send(peerwire.TypeConnAuthRotated, peerwire.ConnAuthRotatedBody([]*credwire.KeyRotation{r01, r12}))
	f.pump()
	pins(k2)
	if strings.Contains(f.logs.String(), "auth_rotation_rejected") {
		t.Fatalf("a repeated chain logged as rejected:\n%s", f.logs.String())
	}
	// A chain with no statement from the pins, ending before them, changes
	// nothing and is logged as rejected.
	m.Send(peerwire.TypeConnAuthRotated, peerwire.ConnAuthRotatedBody([]*credwire.KeyRotation{r01}))
	f.pump()
	pins(k2)
	if !strings.Contains(f.logs.String(), "auth_rotation_rejected") {
		t.Fatal("a chain ending before the pins was not logged as rejected")
	}
}

func bytesOf(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
