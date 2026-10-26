package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// fakeRelay keeps claims in memory and mints placeholder tokens.
type fakeRelay struct {
	claims map[string][]byte
	ttl    time.Duration
	aud    string
	jti    string
}

func (f *fakeRelay) MintOpenToken(aud string, ttl time.Duration, jti string) (string, error) {
	f.aud, f.ttl, f.jti = aud, ttl, jti
	return "v4.public.test-open-token", nil
}

func (f *fakeRelay) PutClaim(_ context.Context, data []byte, ttl time.Duration) (string, time.Time, error) {
	if f.claims == nil {
		f.claims = map[string][]byte{}
	}
	id := fmt.Sprintf("%026d", len(f.claims))
	id = strings.Map(func(r rune) rune { return 'a' + (r - '0') }, id) // base32 alphabet
	f.claims[id] = append([]byte(nil), data...)
	return id, time.Now().Add(ttl), nil
}

func testKeys(t *testing.T) *Keys {
	t.Helper()
	k, err := KeysFromSeeds(Seeds{
		IK:    bytes.Repeat([]byte{1}, 32),
		KEM:   bytes.Repeat([]byte{2}, 32),
		Relay: bytes.Repeat([]byte{3}, 32),
	})
	if err != nil {
		t.Fatalf("KeysFromSeeds: %v", err)
	}
	return k
}

func TestKeysSeedsRoundTrip(t *testing.T) {
	k, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Seeds()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := KeysFromSeeds(s)
	if err != nil {
		t.Fatal(err)
	}
	if !suite.EqualPublic(k.IKPublic(), k2.IKPublic()) || !suite.EqualPublic(k.RelayPublic(), k2.RelayPublic()) {
		t.Fatal("ed25519 keys differ after round trip")
	}
	if !k.KEM.Public().Equal(k2.KEM.Public()) {
		t.Fatal("KEM keys differ after round trip")
	}
	if k.Mailbox() != k2.Mailbox() || k.Mailbox() == "" {
		t.Fatalf("mailbox %q vs %q", k.Mailbox(), k2.Mailbox())
	}
}

func TestInviteOpensAsMemberVaultWould(t *testing.T) {
	keys := testKeys(t)
	relay := &fakeRelay{}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	iv := &Inviter{Keys: keys, Relay: relay, RelayURL: "https://relay.vettid.test",
		HintName: "VettID Member Service", Now: func() time.Time { return now }}

	inv, err := iv.Create(context.Background())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if relay.ttl != invite.TTLInPerson || relay.aud != "https://relay.vettid.test" || relay.jti != inv.OpenJTI {
		t.Fatalf("open token minted with ttl %v aud %q jti %q", relay.ttl, relay.aud, relay.jti)
	}

	// The member vault's side of §6.4 "Accepting": parse the
	// link, fetch the claim, check the commitment, open the bundle.
	q, err := invite.ParseLink(inv.Link)
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	if inv.URL != "https://relay.vettid.test/connect#"+inv.Link {
		t.Fatalf("URL %q", inv.URL)
	}
	if q.Kind != invite.KindConnection || q.Relay != "https://relay.vettid.test" || q.ClaimID != inv.ClaimID {
		t.Fatalf("QR %+v", q)
	}
	blob := relay.claims[q.ClaimID]
	if sha256.Sum256(blob) != q.Hash {
		t.Fatal("claim does not match the link's hash")
	}
	b, err := invite.OpenBundle(blob, q, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("OpenBundle: %v", err)
	}
	if b.Kind != "connection" || b.Remote || b.InviteID != inv.ID || b.HintName != "VettID Member Service" {
		t.Fatalf("bundle %+v", b)
	}
	if !suite.EqualPublic(b.Vault.IK, keys.IKPublic()) || !b.Vault.KEM.Equal(keys.KEM.Public()) ||
		b.Vault.Relay.Mailbox != keys.Mailbox() || !suite.EqualPublic(b.Vault.Relay.PK, keys.RelayPublic()) {
		t.Fatal("bundle principal is not the service's")
	}
	if invite.IsRemote(b.Exp.Sub(now)) {
		t.Fatalf("bundle exp %v makes the invite remote", b.Exp)
	}
	if want := now.Add(-time.Minute).Add(invite.TTLInPerson); !b.Exp.Equal(want) {
		t.Fatalf("exp %v, want %v", b.Exp, want)
	}

	// An expired invitation does not open.
	if _, err := invite.OpenBundle(blob, q, b.Exp.Add(time.Second)); err == nil {
		t.Fatal("expired bundle opened")
	}
}

func TestInviteHintNameBound(t *testing.T) {
	iv := &Inviter{Keys: testKeys(t), Relay: &fakeRelay{}, RelayURL: "https://relay.vettid.test",
		HintName: string(bytes.Repeat([]byte{'x'}, invite.MaxHintName+1)), Now: time.Now}
	if _, err := iv.Create(context.Background()); err != ErrHintName {
		t.Fatalf("err %v, want ErrHintName", err)
	}
}
