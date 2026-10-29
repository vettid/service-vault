package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// rfc9474Vector is RFC 9474 Appendix A's RSABSSA-SHA384-PSS-Randomized
// test vector (testdata, copied from circl's copy of the RFC's vectors).
type rfc9474Vector struct {
	P, Q, N, E, D string
	Msg           string `json:"msg"`
	MsgPrefix     string `json:"msg_prefix"`
	BlindedMsg    string `json:"blinded_msg"`
	BlindSig      string `json:"blind_sig"`
	Sig           string `json:"sig"`
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexInt(t *testing.T, s string) *big.Int {
	return new(big.Int).SetBytes(hexBytes(t, s))
}

// The RFC's vector: BlindSign of its blinded message gives its blind
// signature, and its final signature verifies over msg_prefix ‖ msg.
func TestCertKeyRFC9474Vector(t *testing.T) {
	raw, err := os.ReadFile("testdata/rfc9474-sha384-pss-randomized.json")
	if err != nil {
		t.Fatal(err)
	}
	var v rfc9474Vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	sk := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: hexInt(t, v.N), E: int(hexInt(t, v.E).Int64())},
		D:         hexInt(t, v.D),
		Primes:    []*big.Int{hexInt(t, v.P), hexInt(t, v.Q)},
	}
	sk.Precompute()
	if err := sk.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := blindSign(sk, hexBytes(t, v.BlindedMsg))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hexBytes(t, v.BlindSig)) {
		t.Fatal("blind signature differs from the RFC's")
	}
	if err := VerifyCert(&sk.PublicKey, hexBytes(t, v.MsgPrefix), hexBytes(t, v.Msg), hexBytes(t, v.Sig)); err != nil {
		t.Fatalf("the RFC's signature: %v", err)
	}
	if err := VerifyCert(&sk.PublicKey, hexBytes(t, v.MsgPrefix), append(hexBytes(t, v.Msg), 0), hexBytes(t, v.Sig)); err == nil {
		t.Fatal("a signature over another message verified")
	}
}

var (
	testCertKeyOnce sync.Once
	testCertKey     *CertKey
)

// certKey is one generated key for the tests (RSA-2048 generation is slow).
func certKey(t *testing.T) *CertKey {
	t.Helper()
	testCertKeyOnce.Do(func() {
		k, err := NewCertKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		testCertKey = k
	})
	return testCertKey
}

// The whole exchange with a certification key, the member side played by
// circl's client: blind, BlindSign, finalize, verify (BALLOT-PROTOCOL §5.2).
func TestCertKeyBlindSignRoundTrip(t *testing.T) {
	k := certKey(t)
	c, err := blindrsa.NewClient(blindrsa.SHA384PSSRandomized, k.Public())
	if err != nil {
		t.Fatal(err)
	}
	prefix := bytes.Repeat([]byte{7}, CertPrefixLen)
	msg := []byte("vettid/vote/1/cert\x00 example certified message")
	blinded, state, err := c.Blind(rand.Reader, append(append([]byte{}, prefix...), msg...))
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := k.BlindSign(blinded)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Finalize(state, blindSig)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCert(k.Public(), prefix, msg, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCert(k.Public(), bytes.Repeat([]byte{8}, CertPrefixLen), msg, sig); err == nil {
		t.Fatal("verified under another prefix")
	}
	if err := VerifyCert(k.Public(), prefix[:31], msg, sig); err == nil {
		t.Fatal("a short prefix accepted")
	}
	// Blinded messages of the wrong size, or not below the modulus.
	if _, err := k.BlindSign(blinded[1:]); err == nil {
		t.Fatal("a short blinded message signed")
	}
	if _, err := k.BlindSign(bytes.Repeat([]byte{0xff}, CertKeyBits/8)); err == nil {
		t.Fatal("a blinded message above the modulus signed")
	}
}

// The public key's encoding is fixed: it parses back to the same key,
// and nothing else parses.
func TestCertPublicKeyEncoding(t *testing.T) {
	k := certKey(t)
	der, err := CertPublicKeyDER(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	pk, err := ParseCertPublicKey(der)
	if err != nil || !pk.Equal(k.Public()) {
		t.Fatalf("round trip: %v", err)
	}
	// The algorithm identifier is id-RSASSA-PSS (1.2.840.113549.1.1.10)
	// with SHA-384 (2.16.840.1.101.3.4.2.2) and a salt of 48.
	for _, want := range [][]byte{
		{0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a},
		{0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02},
		{0xa2, 0x03, 0x02, 0x01, 0x30},
	} {
		if !bytes.Contains(der, want) {
			t.Fatalf("encoding lacks % x", want)
		}
	}
	// A changed byte in the header (algorithm, parameters, lengths) is
	// refused; one in the modulus may make another valid key, never this one.
	mod := bytes.Index(der, k.Public().N.Bytes())
	if mod < 0 {
		t.Fatal("modulus not found")
	}
	for i := range der {
		bad := bytes.Clone(der)
		bad[i] ^= 0x01
		pk, err := ParseCertPublicKey(bad)
		switch {
		case i < mod && err == nil:
			t.Fatalf("header byte %d changed: still parsed", i)
		case err == nil && pk.Equal(k.Public()):
			t.Fatalf("byte %d changed: parsed as the same key", i)
		}
	}
	if _, err := ParseCertPublicKey(append(bytes.Clone(der), 0)); err == nil {
		t.Fatal("trailing data parsed")
	}
	other := &rsa.PublicKey{N: k.Public().N, E: 3}
	if _, err := CertPublicKeyDER(other); err == nil {
		t.Fatal("e = 3 encoded")
	}
}

// Sealed under KMS and bound to its name, like any record.
func TestCertKeySealed(t *testing.T) {
	ctx := context.Background()
	kms := newFakeKMS("k1")
	k := certKey(t)
	s, err := SealCertKey(ctx, kms, "k1", "ballot/cert-key/01J0000000000000000000000A", k)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenCertKey(ctx, kms, "ballot/cert-key/01J0000000000000000000000A", s)
	if err != nil || !got.Public().Equal(k.Public()) {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenCertKey(ctx, kms, "ballot/cert-key/01J0000000000000000000000B", s); err == nil {
		t.Fatal("opened under another proposal's name")
	}
	got.Destroy()
	if got.sk != nil {
		t.Fatal("not destroyed")
	}
}
