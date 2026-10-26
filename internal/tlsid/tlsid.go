// Package tlsid is the service vault's TLS identity for its private API:
// an ECDSA P-256 key kept with the service's other secrets, a self-signed
// certificate made from it at start, and the key's pin — SHA-256 of the
// SubjectPublicKeyInfo — which the application's client checks instead of
// a certificate authority. The certificate may be remade on every start;
// the pin changes only if the key does.
package tlsid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// GenerateKey makes a new TLS key, returned as PKCS #8 DER for the
// keystore.
func GenerateKey() ([]byte, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

// Certificate makes a self-signed certificate for the key (PKCS #8 DER)
// valid for dnsNames from now-1h to now+validity.
func Certificate(keyDER []byte, dnsNames []string, now time.Time, validity time.Duration) (tls.Certificate, string, error) {
	k, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("tlsid: key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return tls.Certificate{}, "", errors.New("tlsid: key is not ECDSA P-256")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "VettID service vault"},
		DNSNames:              dnsNames,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ek.PublicKey, ek)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ek, Leaf: leaf}, Pin(leaf), nil
}

// Pin is the pin of a certificate's key: "sha256/" and the unpadded
// base64url SHA-256 of its SubjectPublicKeyInfo.
func Pin(c *x509.Certificate) string {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.RawURLEncoding.EncodeToString(h[:])
}

// ServerConfig is the TLS configuration for the private API: TLS 1.3 only.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
}
