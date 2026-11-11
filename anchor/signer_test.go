package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// badSigner answers with a signature under another key.
type badSigner struct {
	pub   *ecdsa.PublicKey
	other *ecdsa.PrivateKey
	calls int
}

func (b *badSigner) Public() *ecdsa.PublicKey { return b.pub }
func (b *badSigner) SignDigest(_ context.Context, d []byte) ([]byte, error) {
	b.calls++
	return ecdsa.SignASN1(rand.Reader, b.other, d)
}

// A signer's signature is checked against the anchor key before it is
// used: one under another key stops the anchor, before the TSA or Rekor
// hear of it.
func TestSignChecksTheSigner(t *testing.T) {
	_, f, k := newFake(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bs := &badSigner{pub: &k.PublicKey, other: other}
	a, err := NewWithSigner(bs, Endpoints{Rekor: "http://127.0.0.1:1", TSA: "http://127.0.0.1:1/ts"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Anchor(context.Background(), []byte("doc")); err == nil || bs.calls != 1 || f.entered != nil {
		t.Fatalf("a bad signature: %v, %d calls", err, bs.calls)
	}
	if _, err := NewWithSigner(LocalSigner{Key: func() *ecdsa.PrivateKey {
		p, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return p
	}()}, Endpoints{}, nil); err == nil {
		t.Fatal("a P-384 key accepted")
	}
}

// The steps one by one, each result kept (as the signer function keeps
// them in its claim), give the bundle Anchor gives: the same signature,
// timestamp and entry, so a retry resumes from what was kept.
func TestStepsResume(t *testing.T) {
	ctx := context.Background()
	a, f, _ := newFake(t)
	doc := []byte(`{"proposal_id":"01JBQZ0000000000000000000A","v":1}`)
	digest, sig, err := a.Sign(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := a.Timestamp(ctx, sig)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := a.Enter(ctx, digest, sig)
	if err != nil {
		t.Fatal(err)
	}
	// Kept as JSON, as a claim would, then assembled.
	kept, _ := json.Marshal(struct {
		D, S, T []byte
		E       json.RawMessage
	}{digest, sig, ts, entry})
	var back struct {
		D, S, T []byte
		E       json.RawMessage
	}
	_ = json.Unmarshal(kept, &back)
	raw, err := a.Bundle(back.D, back.S, back.T, back.E)
	if err != nil {
		t.Fatal(err)
	}
	var b bundleJSON
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.MessageSignature.Signature, sig) || !bytes.Equal(b.VerificationMaterial.TimestampVerificationData.RFC3161Timestamps[0].SignedTimestamp, ts) ||
		!bytes.Equal(b.VerificationMaterial.TlogEntries[0].CanonicalizedBody, f.entered) {
		t.Fatal("the assembled bundle differs from its steps")
	}
	if _, err := a.Bundle(digest, sig, ts, json.RawMessage(`{`)); err == nil {
		t.Fatal("a garbled kept entry assembled")
	}
}
