// Package ballottest makes Sigstore bundles for tests of the ballot
// manager's callers.
package ballottest

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"time"
)

// Bundle returns a bundle whose RFC 3161 timestamp has genTime tsa and
// whose Rekor entry was integrated at integrated (Unix seconds). The
// timestamp is not signed: it is for the readers of the time only.
func Bundle(tsa, integrated int64) json.RawMessage {
	type imprint struct {
		Alg  pkix.AlgorithmIdentifier
		Hash []byte
	}
	type tstInfo struct {
		Version int
		Policy  asn1.ObjectIdentifier
		Imprint imprint
		Serial  int
		GenTime time.Time `asn1:"generalized"`
	}
	tst, err := asn1.Marshal(tstInfo{1, asn1.ObjectIdentifier{1, 2, 3}, imprint{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}, make([]byte, 32)}, 1, time.Unix(tsa, 0).UTC()})
	if err != nil {
		panic(err)
	}
	octet, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOctetString, Bytes: tst})
	oid, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4})
	encap, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(oid, mustExplicit(octet)...)})
	ver, _ := asn1.Marshal(3)
	algs, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true})
	sd, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(append(ver, algs...), encap...)})
	ctype, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	token, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(ctype, mustExplicit(sd)...)})
	status, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: mustInt(0)})
	resp, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: append(status, token...)})
	b, err := json.Marshal(map[string]any{"verificationMaterial": map[string]any{
		"tlogEntries":               []any{map[string]any{"integratedTime": fmt.Sprint(integrated)}},
		"timestampVerificationData": map[string]any{"rfc3161Timestamps": []any{map[string]any{"signedTimestamp": resp}}},
	}})
	if err != nil {
		panic(err)
	}
	return b
}

func mustExplicit(inner []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	if err != nil {
		panic(err)
	}
	return b
}

func mustInt(n int) []byte {
	b, _ := asn1.Marshal(n)
	return b
}
