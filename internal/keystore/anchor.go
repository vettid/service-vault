package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
)

// AnchorKeyName is the record holding the service's anchor key
// (BALLOT-PROTOCOL §3.3): the long-lived ECDSA P-256 key every vote
// document is anchored in Rekor under.
const AnchorKeyName = "anchor-key"

// AnchorKey is the anchor key as the keystore keeps it.
type AnchorKey struct {
	PKCS8 []byte `json:"pkcs8"`
}

// NewAnchorKey makes a fresh P-256 key.
func NewAnchorKey() (*AnchorKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return &AnchorKey{PKCS8: der}, nil
}

// Private returns the key, refusing anything but P-256.
func (a *AnchorKey) Private() (*ecdsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(a.PKCS8)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("keystore: the anchor key is not P-256")
	}
	return ec, nil
}
