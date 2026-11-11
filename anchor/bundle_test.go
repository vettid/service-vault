package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// swappingSigner names one key at construction and another after, and
// signs with the other.
type swappingSigner struct {
	first, other *ecdsa.PrivateKey
	swapped      bool
}

func (s *swappingSigner) Public() *ecdsa.PublicKey {
	if s.swapped {
		return &s.other.PublicKey
	}
	return &s.first.PublicKey
}

func (s *swappingSigner) SignDigest(_ context.Context, d []byte) ([]byte, error) {
	return ecdsa.SignASN1(rand.Reader, s.other, d)
}

// Sign checks against the key the Anchorer was made with, whatever the
// signer names later.
func TestSignUsesTheFixedKey(t *testing.T) {
	first, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &swappingSigner{first: first, other: other}
	a, err := NewWithSigner(s, Endpoints{Rekor: "http://127.0.0.1:1", TSA: "http://127.0.0.1:1/ts"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.swapped = true
	if _, _, err := a.Sign(context.Background(), []byte("doc")); err == nil {
		t.Fatal("a signature under a key named after construction was taken")
	}
}

// Bundle takes only a token for the signature, an entry for the digest and
// signature under this key, and the two within −60..600 s.
func TestBundleChecks(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		skew int64
		err  error
	}{{0, nil}, {-59, nil}, {599, nil}, {-61, ErrSignAgain}, {601, ErrSignAgain}} {
		a, f, _ := newFake(t)
		f.skew = c.skew
		d, sig, err := a.Sign(ctx, []byte("doc"))
		if err != nil {
			t.Fatal(err)
		}
		ts, err := a.Timestamp(ctx, sig)
		if err != nil {
			t.Fatal(err)
		}
		e, err := a.Enter(ctx, d, sig)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Bundle(d, sig, ts, e); !errors.Is(err, c.err) && (c.err != nil || err != nil) {
			t.Fatalf("skew %d: %v, want %v", c.skew, err, c.err)
		}
		if c.skew != 0 {
			continue
		}
		// Another signature's token, another document's entry.
		_, sig2, _ := a.Sign(ctx, []byte("doc 2"))
		ts2, err := a.Timestamp(ctx, sig2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Bundle(d, sig, ts2, e); err == nil {
			t.Fatal("another signature's token taken")
		}
		d3, sig3, _ := a.Sign(ctx, []byte("doc 3"))
		e3, err := a.Enter(ctx, d3, sig3)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Bundle(d, sig, ts, e3); err == nil {
			t.Fatal("another document's entry taken")
		}
		if _, err := a.Bundle(d, sig, []byte("junk"), e); err == nil {
			t.Fatal("a junk token taken")
		}
	}
}

// The steps' results make exactly the staging vector's bundle, byte for
// byte: the vector was made by Anchor, and Bundle is its last step.
func TestBundleBytes(t *testing.T) {
	raw, err := os.ReadFile("../vote/testdata/anchor-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		AnchorKey string          `json:"anchor_key"`
		Bundle    json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var b bundleJSON
	if err := json.Unmarshal(v.Bundle, &b); err != nil || len(b.VerificationMaterial.TlogEntries) != 1 ||
		len(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps) != 1 {
		t.Fatalf("the vector's bundle: %v", err)
	}
	spki, err := base64.StdEncoding.DecodeString(v.AnchorKey)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWithSigner(pubOnly{pk.(*ecdsa.PublicKey)}, Endpoints{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(b.VerificationMaterial.TlogEntries[0])
	got, err := a.Bundle(b.MessageSignature.MessageDigest.Digest, b.MessageSignature.Signature,
		b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp, entry)
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	if err := json.Compact(&want, v.Bundle); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("the steps' bundle differs from the vector's:\n%s\n%s", got, want.Bytes())
	}
}

// pubOnly names a key it can't sign with.
type pubOnly struct{ pub *ecdsa.PublicKey }

func (p pubOnly) Public() *ecdsa.PublicKey { return p.pub }
func (p pubOnly) SignDigest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("no private key")
}
