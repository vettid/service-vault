package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

func TestAnchorKey(t *testing.T) {
	a, err := NewAnchorKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := a.Private()
	if err != nil || k.Curve != elliptic.P256() {
		t.Fatalf("Private: %v", err)
	}
	// Another curve is refused.
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	if _, err := (&AnchorKey{PKCS8: der}).Private(); err == nil {
		t.Fatal("a P-384 key accepted")
	}
}
