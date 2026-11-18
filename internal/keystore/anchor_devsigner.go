//go:build devsigner

package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
)

// NewAnchorKey makes a fresh P-256 key: devsigner builds only (local
// development and tests), never a release build.
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
