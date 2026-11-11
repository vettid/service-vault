package anchor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	tsaverify "github.com/sigstore/timestamp-authority/v2/pkg/verification"
)

// The Sigstore trusted root of each instance, pinned in this release
// (trust/README.md: fetched through the instance's TUF repository). Only
// its timestampAuthorities are read: each a certificate chain, leaf first
// and root last, and the period it issues timestamps in (validFor).
//
//go:embed trust/staging.json trust/production.json
var trustedRoots embed.FS

// tsaPin is one timestamp authority of a trusted root.
type tsaPin struct {
	leaf          *x509.Certificate
	intermediates []*x509.Certificate
	root          *x509.Certificate
	start, end    time.Time // end zero: still valid
}

func (p tsaPin) covers(t time.Time) bool {
	return !t.Before(p.start) && (p.end.IsZero() || !t.After(p.end))
}

// parseTSAs reads the timestamp authorities of a trusted root.
func parseTSAs(data []byte) ([]tsaPin, error) {
	var r struct {
		TSAs []struct {
			CertChain struct {
				Certificates []struct {
					RawBytes []byte `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"certChain"`
			ValidFor struct {
				Start time.Time `json:"start"`
				End   time.Time `json:"end"`
			} `json:"validFor"`
		} `json:"timestampAuthorities"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("anchor: trusted root: %w", err)
	}
	var out []tsaPin
	for _, a := range r.TSAs {
		var certs []*x509.Certificate
		for _, c := range a.CertChain.Certificates {
			x, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return nil, fmt.Errorf("anchor: trusted root: %w", err)
			}
			certs = append(certs, x)
		}
		if len(certs) < 2 || a.ValidFor.Start.IsZero() {
			return nil, errors.New("anchor: trusted root: a timestamp authority with a short chain or no start")
		}
		out = append(out, tsaPin{leaf: certs[0], intermediates: certs[1 : len(certs)-1], root: certs[len(certs)-1],
			start: a.ValidFor.Start, end: a.ValidFor.End})
	}
	if len(out) == 0 {
		return nil, errors.New("anchor: trusted root: no timestamp authority")
	}
	return out, nil
}

func pinnedTSAs(instance string) ([]tsaPin, error) {
	if instance != Staging && instance != Production {
		return nil, fmt.Errorf("anchor: unknown Sigstore instance %q", instance)
	}
	data, err := trustedRoots.ReadFile("trust/" + instance + ".json")
	if err != nil {
		return nil, err
	}
	return parseTSAs(data)
}

// TimestampTime returns the RFC 3161 genTime (Unix seconds) of the bundle
// this service anchored for doc, after checking it as Sigstore does
// (github.com/sigstore/timestamp-authority verification, on
// digitorus/timestamp): the bundle's message digest is SHA-256 of doc, the
// bundle carries exactly one timestamp, whose message imprint is SHA-256 of
// the bundle's message signature (what the anchor timestamps), signed by
// a timestamp authority of the instance's pinned trusted root whose
// certificate chains to that root (judged at the token's own time) as an
// end-entity certificate with the single, critical time-stamping usage, and
// the genTime falls inside that authority's validFor. It refuses on any
// failure.
func TimestampTime(instance string, bundle json.RawMessage, doc []byte) (int64, error) {
	pins, err := pinnedTSAs(instance)
	if err != nil {
		return 0, err
	}
	return timestampTime(pins, bundle, doc)
}

// VerifyTimestamp returns the RFC 3161 genTime (Unix seconds) of resp, a
// TimeStampResp over data, checked as TimestampTime checks a bundle's: an
// authority of the instance's pinned trusted root, chained to it, and
// inside its validFor. It refuses on any failure.
func VerifyTimestamp(instance string, resp, data []byte) (int64, error) {
	pins, err := pinnedTSAs(instance)
	if err != nil {
		return 0, err
	}
	return verifyResp(pins, resp, data)
}

// AuthorityTime asks a's timestamp authority for a stamp over a fresh
// random value and returns its verified time (BALLOT-PROTOCOL §7, 0.13.12:
// the count waits for it). A stamp only: no transparency-log entry.
func AuthorityTime(ctx context.Context, a *Anchorer, instance string) (int64, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return 0, err
	}
	resp, err := a.Timestamp(ctx, nonce)
	if err != nil {
		return 0, err
	}
	return VerifyTimestamp(instance, resp, nonce)
}

func verifyResp(pins []tsaPin, resp, data []byte) (int64, error) {
	var errs []error
	for _, p := range pins {
		t, err := tsaverify.VerifyTimestampResponse(resp, bytes.NewReader(data),
			tsaverify.VerifyOpts{Roots: []*x509.Certificate{p.root}, Intermediates: p.intermediates, TSACertificate: p.leaf})
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !p.covers(t.Time) {
			errs = append(errs, errors.New("the timestamp is outside the authority's validity period"))
			continue
		}
		return t.Time.Unix(), nil
	}
	return 0, fmt.Errorf("anchor: the timestamp doesn't verify: %w", errors.Join(errs...))
}

func timestampTime(pins []tsaPin, bundle json.RawMessage, doc []byte) (int64, error) {
	var b struct {
		VerificationMaterial struct {
			TimestampVerificationData struct {
				Timestamps []struct {
					SignedTimestamp []byte `json:"signedTimestamp"`
				} `json:"rfc3161Timestamps"`
			} `json:"timestampVerificationData"`
		} `json:"verificationMaterial"`
		MessageSignature struct {
			MessageDigest struct {
				Digest []byte `json:"digest"`
			} `json:"messageDigest"`
			Signature []byte `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		return 0, errors.New("anchor: the bundle is unreadable")
	}
	ts := b.VerificationMaterial.TimestampVerificationData.Timestamps
	d := sha256.Sum256(doc)
	if len(ts) != 1 || len(b.MessageSignature.Signature) == 0 || !bytes.Equal(b.MessageSignature.MessageDigest.Digest, d[:]) {
		return 0, errors.New("anchor: the bundle is not one timestamped signature over the document")
	}
	return verifyResp(pins, ts[0].SignedTimestamp, b.MessageSignature.Signature)
}
