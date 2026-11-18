package keystore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
)

// AnchorKeyName is the record holding the service's anchor key
// (BALLOT-PROTOCOL §3.3): the long-lived ECDSA P-256 key every vote
// document is anchored in Rekor under. Release builds only ever open it;
// a new one is made by devsigner builds alone (NewAnchorKey; key
// protection, GC #7406 §7 step 1), and the anchor signer holds the key in
// KMS.
const AnchorKeyName = "anchor-key"

// AnchorKey is the anchor key as the keystore keeps it.
type AnchorKey struct {
	PKCS8 []byte `json:"pkcs8"`
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
