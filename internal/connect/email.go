// Package connect handles connections' lifecycle on the service side:
// invitations handed to the application, the email a member entered when
// connecting, and the connection records themselves.
package connect

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// MinPepperLen is the shortest pepper EmailIndex accepts.
const MinPepperLen = 32

// MaxEmailLen bounds an email address (RFC 5321 §4.5.3.1.3 path limit).
const MaxEmailLen = 254

// ErrEmail is returned for an address that is not a single plain
// addr-spec.
var ErrEmail = errors.New("connect: invalid email address")

// ErrPepper is returned for a pepper shorter than MinPepperLen.
var ErrPepper = errors.New("connect: pepper shorter than 32 bytes")

// EmailIndex turns an email address into the key the service stores and
// looks connections up by: HMAC-SHA256 under a server-side pepper of the
// normalized address (MEMBER-SERVICE-PLAN §4.1). The address itself is
// never stored. Without the pepper the keys cannot be tested against a
// list of addresses.
type EmailIndex struct {
	pepper []byte
}

// NewEmailIndex makes an index with pepper, which must be at least
// MinPepperLen bytes and is kept outside the database (the keystore).
func NewEmailIndex(pepper []byte) (*EmailIndex, error) {
	if len(pepper) < MinPepperLen {
		return nil, ErrPepper
	}
	return &EmailIndex{pepper: append([]byte(nil), pepper...)}, nil
}

// Key returns the lookup key for addr, or ErrEmail.
func (x *EmailIndex) Key(addr string) (string, error) {
	n, err := NormalizeEmail(addr)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, x.pepper)
	h.Write([]byte("vettid/service-vault/email-index/v1\x00"))
	h.Write([]byte(n))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// NormalizeEmail trims surrounding space and lower-cases the address
// (chosen: the local part is treated as case-insensitive, as nearly all
// providers do, so a member's capitalization does not stop sign-in). It
// accepts only a bare addr-spec: no display name, no angle brackets, no
// comments.
func NormalizeEmail(addr string) (string, error) {
	s := strings.TrimSpace(addr)
	if s == "" || len(s) > MaxEmailLen || !utf8.ValidString(s) || strings.ContainsAny(s, "<>()\" \t\r\n") {
		return "", ErrEmail
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return "", ErrEmail
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || !strings.Contains(s[at+1:], ".") {
		return "", ErrEmail
	}
	return strings.ToLower(s), nil
}
