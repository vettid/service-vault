package ballot

import (
	"crypto/ed25519"
	"errors"

	"filippo.io/edwards25519"
)

var errSig = errors.New("ballot: signature refused")

// Verify checks an Ed25519 signature over label ‖ msg by BALLOT-PROTOCOL
// §2's rules, which every verifier applies so that they all agree:
//  1. A and R are canonical: y below p, and not x = 0 with the sign bit;
//  2. neither A nor R is of small order;
//  3. S < L, and 4. [S]B = R + [k]A, cofactorless (ed25519.Verify).
//
// Go's point decoding accepts a non-canonical y, so rules 1 and 2 are
// checked here.
func Verify(pub []byte, label string, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return errSig
	}
	if !strictPoint(pub) || !strictPoint(sig[:32]) {
		return errSig
	}
	m := make([]byte, 0, len(label)+len(msg))
	m = append(append(m, label...), msg...)
	if !ed25519.Verify(pub, m, sig) {
		return errSig
	}
	return nil
}

// p = 2^255 − 19, little-endian.
var fieldP = [32]byte{
	0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
}

// strictPoint reports whether b is a canonical encoding of a point that is
// not of small order (rules 1 and 2).
func strictPoint(b []byte) bool {
	// y (the encoding with the sign bit cleared) must be below p.
	var y [32]byte
	copy(y[:], b)
	y[31] &= 0x7f
	if !lessLE(y[:], fieldP[:]) {
		return false
	}
	pt, err := new(edwards25519.Point).SetBytes(b)
	if err != nil {
		return false
	}
	// A point that re-encodes differently had x = 0 with the sign bit set.
	if string(pt.Bytes()) != string(b) {
		return false
	}
	return new(edwards25519.Point).MultByCofactor(pt).Equal(edwards25519.NewIdentityPoint()) != 1
}

// lessLE reports a < b for little-endian numbers of equal length.
func lessLE(a, b []byte) bool {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
