// Package webhook signs and verifies the service vault's webhooks.
//
// A webhook is an HTTP POST with a JSON body and two headers:
//
//	VettID-Event-Id:  <ULID, unique per event, stable across retries>
//	VettID-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, t "." event_id "." body)>
//
// The timestamp and event id are inside the MAC, so a captured request
// cannot be replayed outside the tolerance window, and a receiver that
// remembers event ids for that window rejects replays inside it.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Header names.
const (
	HeaderEventID   = "VettID-Event-Id"
	HeaderSignature = "VettID-Signature"
)

// DefaultTolerance is how far a signature's timestamp may be from the
// receiver's clock.
const DefaultTolerance = 5 * time.Minute

// MinSecretLen is the shortest secret Sign and Verify accept.
const MinSecretLen = 32

// Errors returned by Verify.
var (
	ErrSecret    = errors.New("webhook: secret shorter than 32 bytes")
	ErrMalformed = errors.New("webhook: malformed signature header")
	ErrStale     = errors.New("webhook: timestamp outside tolerance")
	ErrMismatch  = errors.New("webhook: signature mismatch")
)

func mac(secret []byte, ts int64, eventID string, body []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(strconv.FormatInt(ts, 10)))
	h.Write([]byte{'.'})
	h.Write([]byte(eventID))
	h.Write([]byte{'.'})
	h.Write(body)
	return h.Sum(nil)
}

// Sign returns the VettID-Signature header value for body and eventID at t.
func Sign(secret []byte, t time.Time, eventID string, body []byte) (string, error) {
	if len(secret) < MinSecretLen {
		return "", ErrSecret
	}
	ts := t.Unix()
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac(secret, ts, eventID, body)), nil
}

// Verify checks header (the VettID-Signature value) against body and
// eventID, with the timestamp within tolerance of now. Any v1 entry may
// match, so a sender can sign with two secrets while one is rotated.
func Verify(secret []byte, header, eventID string, body []byte, now time.Time, tolerance time.Duration) error {
	if len(secret) < MinSecretLen {
		return ErrSecret
	}
	var ts int64
	var sigs [][]byte
	haveTS := false
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return ErrMalformed
		}
		switch k {
		case "t":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || haveTS {
				return ErrMalformed
			}
			ts, haveTS = n, true
		case "v1":
			b, err := hex.DecodeString(v)
			if err != nil || len(b) != sha256.Size {
				return ErrMalformed
			}
			sigs = append(sigs, b)
		}
	}
	if !haveTS || len(sigs) == 0 || eventID == "" {
		return ErrMalformed
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return ErrStale
	}
	want := mac(secret, ts, eventID, body)
	for _, s := range sigs {
		if hmac.Equal(s, want) {
			return nil
		}
	}
	return ErrMismatch
}
