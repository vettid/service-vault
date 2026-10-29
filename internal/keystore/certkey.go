package keystore

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// A proposal's certification key (BALLOT-PROTOCOL §2, §5): RSA with a
// modulus of exactly CertKeyBits bits and e = 65537, used for RFC 9474
// RSABSSA-SHA384-PSS-Randomized blind signatures. The private key is kept
// sealed like any other record (Seal under a KMS data key) and lives for
// one vote.
const (
	CertKeyBits = 2048
	certKeyE    = 65537
	// CertPrefixLen is the randomized variant's message prefix (RFC 9474 §4.1).
	CertPrefixLen = 32
	certSaltLen   = 48 // SHA-384's size
)

// CertKey is a proposal's certification private key.
type CertKey struct {
	sk *rsa.PrivateKey
}

// NewCertKey makes a fresh certification key.
func NewCertKey(random io.Reader) (*CertKey, error) {
	sk, err := rsa.GenerateKey(random, CertKeyBits)
	if err != nil {
		return nil, err
	}
	k := &CertKey{sk: sk}
	if err := k.check(); err != nil {
		return nil, err
	}
	return k, nil
}

func (k *CertKey) check() error {
	if k.sk.N.BitLen() != CertKeyBits || k.sk.E != certKeyE {
		return errors.New("keystore: certification key is not RSA-2048 with e = 65537")
	}
	return k.sk.Validate()
}

// SealCertKey seals the key under a fresh KMS data key; name binds the
// record to its proposal (Seal).
func SealCertKey(ctx context.Context, kms KMS, keyID, name string, k *CertKey) (*Sealed, error) {
	der := x509.MarshalPKCS1PrivateKey(k.sk)
	defer clear(der)
	return Seal(ctx, kms, keyID, name, der)
}

// OpenCertKey opens a key sealed by SealCertKey under the same name.
func OpenCertKey(ctx context.Context, kms KMS, name string, s *Sealed) (*CertKey, error) {
	der, err := Open(ctx, kms, name, s)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	sk, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, ErrOpen
	}
	k := &CertKey{sk: sk}
	if err := k.check(); err != nil {
		return nil, err
	}
	return k, nil
}

// BlindSign signs a member vault's blinded message (RFC 9474 §4.3). The
// result is checked before it is returned (circl's DecryptAndCheck), so a
// fault never leaks the key.
func (k *CertKey) BlindSign(blinded []byte) ([]byte, error) {
	return blindSign(k.sk, blinded)
}

func blindSign(sk *rsa.PrivateKey, blinded []byte) ([]byte, error) {
	if n := (sk.N.BitLen() + 7) / 8; len(blinded) != n {
		return nil, fmt.Errorf("keystore: blinded message is %d bytes, not %d", len(blinded), n)
	}
	if new(big.Int).SetBytes(blinded).Cmp(sk.N) >= 0 {
		return nil, errors.New("keystore: blinded message is not below the modulus")
	}
	return blindrsa.NewSigner(sk).BlindSign(blinded)
}

// Public returns the public key.
func (k *CertKey) Public() *rsa.PublicKey { return &k.sk.PublicKey }

// Destroy drops the key. (Go cannot reliably wipe a big.Int; the sealed
// record is deleted by the caller, which is what retires it.)
func (k *CertKey) Destroy() { k.sk = nil }

// The SubjectPublicKeyInfo of a certification key (BALLOT-PROTOCOL §2):
// id-RSASSA-PSS with RSASSA-PSS-params fixed to SHA-384, MGF1 with
// SHA-384 and a 48-byte salt (RFC 4055 §3.1; the trailer field is the
// default and omitted). SHA-2 AlgorithmIdentifiers are encoded with
// absent parameters (RFC 5754 §2). The encoding is fixed: ParseCertPublicKey
// accepts these bytes and no other form, and the member vault parses
// exactly them.
var (
	oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidSHA384    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
)

type pssParams struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF        mgfAlgorithm             `asn1:"explicit,tag:1"`
	SaltLength int                      `asn1:"explicit,tag:2"`
}

type mgfAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters pkix.AlgorithmIdentifier
}

type spki struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters pssParams
	}
	PublicKey asn1.BitString
}

// CertPublicKeyDER encodes a certification public key.
func CertPublicKeyDER(pk *rsa.PublicKey) ([]byte, error) {
	if pk.N.BitLen() != CertKeyBits || pk.E != certKeyE {
		return nil, errors.New("keystore: not a certification public key")
	}
	inner := x509.MarshalPKCS1PublicKey(pk)
	var s spki
	s.Algorithm.Algorithm = oidRSASSAPSS
	s.Algorithm.Parameters = pssParams{
		Hash:       pkix.AlgorithmIdentifier{Algorithm: oidSHA384},
		MGF:        mgfAlgorithm{Algorithm: oidMGF1, Parameters: pkix.AlgorithmIdentifier{Algorithm: oidSHA384}},
		SaltLength: certSaltLen,
	}
	s.PublicKey = asn1.BitString{Bytes: inner, BitLength: 8 * len(inner)}
	return asn1.Marshal(s)
}

// ParseCertPublicKey parses the bytes CertPublicKeyDER makes, and only
// those: it re-encodes the key and requires the same bytes, so a key with
// other parameters, another size or exponent, or a non-canonical encoding
// is refused.
func ParseCertPublicKey(der []byte) (*rsa.PublicKey, error) {
	var s spki
	rest, err := asn1.Unmarshal(der, &s)
	if err != nil || len(rest) != 0 || !s.Algorithm.Algorithm.Equal(oidRSASSAPSS) || s.PublicKey.BitLength%8 != 0 {
		return nil, errors.New("keystore: not a certification public key")
	}
	pk, err := x509.ParsePKCS1PublicKey(s.PublicKey.Bytes)
	if err != nil {
		return nil, errors.New("keystore: not a certification public key")
	}
	again, err := CertPublicKeyDER(pk)
	if err != nil || string(again) != string(der) {
		return nil, errors.New("keystore: not a certification public key")
	}
	return pk, nil
}

// VerifyCert checks a certificate: sig over prefix ‖ msg under pk
// (RFC 9474 §4.5, the randomized variant's prepared message).
func VerifyCert(pk *rsa.PublicKey, prefix, msg, sig []byte) error {
	if len(prefix) != CertPrefixLen {
		return errors.New("keystore: certificate prefix is not 32 bytes")
	}
	v, err := blindrsa.NewVerifier(blindrsa.SHA384PSSRandomized, pk)
	if err != nil {
		return err
	}
	prepared := append(append(make([]byte, 0, len(prefix)+len(msg)), prefix...), msg...)
	return v.Verify(prepared, sig)
}
