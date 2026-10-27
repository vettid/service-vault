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
		// The chain is not checked against any CA; VerifyConnection checks
		// the one thing that matters, the leaf key. Unlike
		// VerifyPeerCertificate it also runs on resumed sessions.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPin
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
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
	// No redirects: the API never sends one, and following it would carry
	// the API key somewhere else.
	return &http.Client{Transport: t, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
