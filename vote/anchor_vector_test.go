package vote

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

// anchorVector is testdata/anchor-vector.json: a proposal's anchor bundle
// captured from staging (BALLOT-PROTOCOL §11 item 3, §8.5 "Rekor
// profile"). Its Rekor entry, checkpoint and timestamp verify under its
// trusted_root with Sigstore's verifier (vettid/votes tests it so); this
// test checks the parts the standard library can.
type anchorVector struct {
	ServiceIK    []byte          `json:"service_ik"`
	AnchorKey    []byte          `json:"anchor_key"`
	AnchorCert   []byte          `json:"anchor_cert"`
	Proposal     string          `json:"proposal"`
	ProposalHash string          `json:"proposal_hash"`
	ProposalSig  string          `json:"proposal_sig"`
	Bundle       json.RawMessage `json:"bundle"`
	TrustedRoot  json.RawMessage `json:"trusted_root"`
}

func TestAnchorVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/anchor-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v anchorVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	doc := []byte(v.Proposal)
	p, err := ParseProposal(doc)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if !bytes.Equal(p.Service, v.ServiceIK) || h(sum(doc)) != v.ProposalHash {
		t.Fatal("proposal: another service or hash")
	}
	psig, _ := hex.DecodeString(v.ProposalSig)
	if Verify(v.ServiceIK, LabelProposal, ProposalSigMsg(doc), psig) != nil {
		t.Fatal("proposal_sig")
	}
	// The anchor key's certificate: the service's identity key signs
	// H(SPKI DER) (§3.3).
	spkiHash := sha256.Sum256(v.AnchorKey)
	if Verify(v.ServiceIK, LabelAnchorKey, spkiHash[:], v.AnchorCert) != nil {
		t.Fatal("anchor_cert")
	}
	pub, err := x509.ParsePKIXPublicKey(v.AnchorKey)
	ec, ok := pub.(*ecdsa.PublicKey)
	if err != nil || !ok {
		t.Fatalf("anchor key: %v", err)
	}
	// The bundle names the key by hint, and signs the proposal's bytes.
	var b struct {
		VerificationMaterial struct {
			PublicKey struct {
				Hint string `json:"hint"`
			} `json:"publicKey"`
			TlogEntries []struct {
				KindVersion struct {
					Kind string `json:"kind"`
				} `json:"kindVersion"`
				CanonicalizedBody []byte `json:"canonicalizedBody"`
			} `json:"tlogEntries"`
			TimestampVerificationData struct {
				RFC3161Timestamps []struct {
					SignedTimestamp []byte `json:"signedTimestamp"`
				} `json:"rfc3161Timestamps"`
			} `json:"timestampVerificationData"`
		} `json:"verificationMaterial"`
		MessageSignature struct {
			MessageDigest struct {
				Algorithm string `json:"algorithm"`
				Digest    []byte `json:"digest"`
			} `json:"messageDigest"`
			Signature []byte `json:"signature"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(v.Bundle, &b); err != nil {
		t.Fatal(err)
	}
	vm, ms := b.VerificationMaterial, b.MessageSignature
	if vm.PublicKey.Hint != base64.StdEncoding.EncodeToString(spkiHash[:]) {
		t.Fatal("bundle: another key's hint")
	}
	d := sum(doc)
	if ms.MessageDigest.Algorithm != "SHA2_256" || !bytes.Equal(ms.MessageDigest.Digest, d) || !ecdsa.VerifyASN1(ec, d, ms.Signature) {
		t.Fatal("bundle: the signature over the proposal")
	}
	if len(vm.TlogEntries) != 1 || vm.TlogEntries[0].KindVersion.Kind != "hashedrekord" || len(vm.TimestampVerificationData.RFC3161Timestamps) != 1 {
		t.Fatal("bundle: not one hashedrekord entry and one RFC 3161 timestamp")
	}
	// The Rekor entry is for this digest, signature and key.
	var e struct {
		Spec struct {
			Data struct {
				Hash struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"`
				} `json:"hash"`
			} `json:"data"`
			Signature struct {
				Content   []byte `json:"content"`
				PublicKey struct {
					Content []byte `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(vm.TlogEntries[0].CanonicalizedBody, &e); err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(e.Spec.Signature.PublicKey.Content)
	if e.Spec.Data.Hash.Algorithm != "sha256" || e.Spec.Data.Hash.Value != h(d) ||
		!bytes.Equal(e.Spec.Signature.Content, ms.Signature) || blk == nil || !bytes.Equal(blk.Bytes, v.AnchorKey) {
		t.Fatal("bundle: the Rekor entry is for another digest, signature or key")
	}
	if !bytes.Contains(v.TrustedRoot, []byte(`"application/vnd.dev.sigstore.trustedroot+json;version=0.1"`)) {
		t.Fatal("trusted_root: not a Sigstore trusted root")
	}
}
