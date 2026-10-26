// Package pinned makes HTTP clients that reach the service vault's private
// API over TLS 1.3 and accept exactly one server key, identified by its
// pin ("sha256/" + base64url SHA-256 of the SubjectPublicKeyInfo), which
// the service vault publishes. No certificate authority is consulted, and
// the certificate's names and dates do not matter: the key is the
// identity.
package pinned

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

// ErrPin is returned by a handshake whose server key does not match.
var ErrPin = errors.New("pinned: server key does not match the pin")

// ParsePin checks a pin's form and returns its 32-byte hash.
func ParsePin(pin string) ([]byte, error) {
	s, ok := strings.CutPrefix(pin, "sha256/")
	b, err := base64.RawURLEncoding.DecodeString(s)
	if !ok || err != nil || len(b) != sha256.Size {
		return nil, errors.New("pinned: malformed pin")
	}
	return b, nil
}

// TLSConfig accepts only a server whose leaf key matches pin.
func TLSConfig(pin string) (*tls.Config, error) {
	want, err := ParsePin(pin)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The chain is not checked against any CA; VerifyPeerCertificate
		// checks the one thing that matters, the leaf key.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPin
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return ErrPin
			}
			got := sha256.Sum256(c.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return ErrPin
			}
			return nil
		},
	}, nil
}

// Client is an HTTP client for the pinned server.
func Client(pin string, timeout time.Duration) (*http.Client, error) {
	cfg, err := TLSConfig(pin)
	if err != nil {
		return nil, err
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = cfg
	t.Proxy = nil
	return &http.Client{Transport: t, Timeout: timeout}, nil
}
