package ballot

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"time"
)

// TSATime returns the RFC 3161 genTime (Unix seconds, whole) of the
// bundle's single timestamp: the time the extension is judged by, as the
// site judges it (VOTES-SITE §4 "Anchor") and a vault does (VAULT-MESSAGING
// §10.19.6). It reads the token's TSTInfo and does not verify the
// authority's signature: it is only called on a bundle this service
// anchored itself and kept (never on one the site served), and the site
// verified the bundle in full when it took the document.
func TSATime(bundle json.RawMessage) (int64, error) {
	var b struct {
		VerificationMaterial struct {
			TimestampVerificationData struct {
				Timestamps []struct {
					SignedTimestamp []byte `json:"signedTimestamp"`
				} `json:"rfc3161Timestamps"`
			} `json:"timestampVerificationData"`
		} `json:"verificationMaterial"`
	}
	ts := &b.VerificationMaterial.TimestampVerificationData.Timestamps
	if err := json.Unmarshal(bundle, &b); err != nil || len(*ts) != 1 {
		return 0, errors.New("ballot: the bundle has no single RFC 3161 timestamp")
	}
	t, err := genTime((*ts)[0].SignedTimestamp)
	if err != nil {
		return 0, err
	}
	return t, nil
}

var oidTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

var errTimestamp = errors.New("ballot: the RFC 3161 timestamp is unreadable")

func children(b []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, errTimestamp
		}
		out, b = append(out, v), rest
	}
	return out, nil
}

func seq(v asn1.RawValue) ([]asn1.RawValue, error) {
	if v.Class != asn1.ClassUniversal || v.Tag != asn1.TagSequence || !v.IsCompound {
		return nil, errTimestamp
	}
	return children(v.Bytes)
}

// genTime reads genTime from a TimeStampResp, or a TimeStampToken alone
// (a CMS ContentInfo holding SignedData whose content is a TSTInfo).
func genTime(der []byte) (int64, error) {
	var top asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &top); err != nil || len(rest) != 0 {
		return 0, errTimestamp
	}
	el, err := seq(top)
	if err != nil || len(el) < 2 {
		return 0, errTimestamp
	}
	if el[0].Tag == asn1.TagSequence { // TimeStampResp: status, then the token
		if el, err = seq(el[1]); err != nil || len(el) < 2 {
			return 0, errTimestamp
		}
	}
	// ContentInfo: contentType, [0] SignedData.
	if el[1].Class != asn1.ClassContextSpecific || el[1].Tag != 0 {
		return 0, errTimestamp
	}
	in, err := children(el[1].Bytes)
	if err != nil || len(in) != 1 {
		return 0, errTimestamp
	}
	sd, err := seq(in[0]) // version, digestAlgorithms, encapContentInfo, ...
	if err != nil || len(sd) < 3 {
		return 0, errTimestamp
	}
	ec, err := seq(sd[2])
	if err != nil || len(ec) != 2 || ec[1].Class != asn1.ClassContextSpecific || ec[1].Tag != 0 {
		return 0, errTimestamp
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(ec[0].FullBytes, &oid); err != nil || !oid.Equal(oidTSTInfo) {
		return 0, errTimestamp
	}
	oc, err := children(ec[1].Bytes)
	if err != nil || len(oc) != 1 || oc[0].Tag != asn1.TagOctetString {
		return 0, errTimestamp
	}
	var tst asn1.RawValue
	if rest, err := asn1.Unmarshal(oc[0].Bytes, &tst); err != nil || len(rest) != 0 {
		return 0, errTimestamp
	}
	f, err := seq(tst) // version, policy, messageImprint, serialNumber, genTime
	if err != nil || len(f) < 5 || f[4].Tag != asn1.TagGeneralizedTime {
		return 0, errTimestamp
	}
	var t time.Time
	if _, err := asn1.Unmarshal(f[4].FullBytes, &t); err != nil {
		return 0, errTimestamp
	}
	return t.Unix(), nil
}
