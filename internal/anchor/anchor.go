// Package anchor anchors vote documents in Sigstore's Rekor log
// (BALLOT-PROTOCOL §3.3, §8.5 "Rekor profile"): a hashedrekord entry with
// the document's SHA-256 and an ECDSA P-256 signature under the service's
// anchor key, with an RFC 3161 timestamp, packaged as a Sigstore bundle
// (v0.3) that the standard Sigstore tools verify.
//
// It uses only the standard library: one call to Rekor's v1 API and one to
// the timestamp authority. Staging anchors in Sigstore's staging instance
// and production in its public-good one.
package anchor

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
)

// Sigstore instances.
const (
	Staging    = "staging"
	Production = "production"
)

// Endpoints are an instance's Rekor (v1 API) and timestamp authority, as
// its signing configuration names them.
type Endpoints struct {
	Rekor string
	TSA   string
}

// Instances are the pinned endpoints.
var Instances = map[string]Endpoints{
	Production: {Rekor: "https://rekor.sigstore.dev", TSA: "https://timestamp.sigstore.dev/api/v1/timestamp"},
	Staging:    {Rekor: "https://rekor.sigstage.dev", TSA: "https://timestamp.sigstage.dev/api/v1/timestamp"},
}

// Anchorer anchors documents under one key.
type Anchorer struct {
	key    *ecdsa.PrivateKey
	spki   []byte
	ep     Endpoints
	client *http.Client
}

// New returns an Anchorer for key on a Sigstore instance.
func New(instance string, key *ecdsa.PrivateKey) (*Anchorer, error) {
	ep, ok := Instances[instance]
	if !ok {
		return nil, fmt.Errorf("anchor: unknown Sigstore instance %q", instance)
	}
	return NewWith(key, ep, &http.Client{Timeout: 30 * time.Second})
}

// NewWith returns an Anchorer on given endpoints (tests).
func NewWith(key *ecdsa.PrivateKey, ep Endpoints, client *http.Client) (*Anchorer, error) {
	if key.Curve != elliptic.P256() {
		return nil, errors.New("anchor: the key is not P-256")
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Anchorer{key: key, spki: spki, ep: ep, client: client}, nil
}

// PublicKeyDER is the anchor key's SubjectPublicKeyInfo.
func (a *Anchorer) PublicKeyDER() []byte { return a.spki }

// Hint is the key's hint in a bundle: base64 of SHA-256 of its SPKI, as
// sigstore-go names a key.
func Hint(spki []byte) string {
	h := sha256.Sum256(spki)
	return base64.StdEncoding.EncodeToString(h[:])
}

// Anchor signs doc, timestamps the signature, enters it in Rekor, checks
// the entry against what was sent and its inclusion proof, and returns
// the Sigstore bundle as JSON.
func (a *Anchorer) Anchor(ctx context.Context, doc []byte) (json.RawMessage, error) {
	digest := sha256.Sum256(doc)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		return nil, err
	}
	ts, err := a.timestamp(ctx, sig)
	if err != nil {
		return nil, err
	}
	e, err := a.enter(ctx, digest[:], sig)
	if err != nil {
		return nil, err
	}
	b := bundleJSON{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: verificationMaterial{
			PublicKey:                 publicKeyID{Hint: Hint(a.spki)},
			TlogEntries:               []tlogEntry{*e},
			TimestampVerificationData: timestampData{RFC3161Timestamps: []signedTimestamp{{SignedTimestamp: ts}}},
		},
		MessageSignature: messageSignature{MessageDigest: messageDigest{Algorithm: "SHA2_256", Digest: digest[:]}, Signature: sig},
	}
	return json.Marshal(b)
}

// The bundle's JSON form (protobuf-specs dev.sigstore.bundle.v1.Bundle,
// in protojson: camelCase names, bytes as base64, int64 as strings).
type bundleJSON struct {
	MediaType            string               `json:"mediaType"`
	VerificationMaterial verificationMaterial `json:"verificationMaterial"`
	MessageSignature     messageSignature     `json:"messageSignature"`
}

type verificationMaterial struct {
	PublicKey                 publicKeyID   `json:"publicKey"`
	TlogEntries               []tlogEntry   `json:"tlogEntries"`
	TimestampVerificationData timestampData `json:"timestampVerificationData"`
}

type publicKeyID struct {
	Hint string `json:"hint"`
}

type timestampData struct {
	RFC3161Timestamps []signedTimestamp `json:"rfc3161Timestamps"`
}

type signedTimestamp struct {
	SignedTimestamp []byte `json:"signedTimestamp"`
}

type messageSignature struct {
	MessageDigest messageDigest `json:"messageDigest"`
	Signature     []byte        `json:"signature"`
}

type messageDigest struct {
	Algorithm string `json:"algorithm"`
	Digest    []byte `json:"digest"`
}

type tlogEntry struct {
	LogIndex          string           `json:"logIndex"`
	LogID             logID            `json:"logId"`
	KindVersion       kindVersion      `json:"kindVersion"`
	IntegratedTime    string           `json:"integratedTime"`
	InclusionPromise  inclusionPromise `json:"inclusionPromise"`
	InclusionProof    inclusionProof   `json:"inclusionProof"`
	CanonicalizedBody []byte           `json:"canonicalizedBody"`
}

type logID struct {
	KeyID []byte `json:"keyId"`
}

type kindVersion struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
}

type inclusionPromise struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
}

type inclusionProof struct {
	LogIndex   string     `json:"logIndex"`
	RootHash   []byte     `json:"rootHash"`
	TreeSize   string     `json:"treeSize"`
	Hashes     [][]byte   `json:"hashes"`
	Checkpoint checkpoint `json:"checkpoint"`
}

type checkpoint struct {
	Envelope string `json:"envelope"`
}

// hashedrekord is the proposed entry (Rekor's hashedrekord 0.0.1).
type hashedrekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
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

// logEntry is Rekor's answer for one entry.
type logEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof *struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

const maxResponse = 1 << 20

// enter adds the hashedrekord entry, or fetches it if Rekor has it
// already (a retry), and turns Rekor's answer into the bundle's entry.
func (a *Anchorer) enter(ctx context.Context, digest, sig []byte) (*tlogEntry, error) {
	var pe hashedrekord
	pe.APIVersion, pe.Kind = "0.0.1", "hashedrekord"
	pe.Spec.Data.Hash.Algorithm, pe.Spec.Data.Hash.Value = "sha256", hex.EncodeToString(digest)
	pe.Spec.Signature.Content = sig
	pe.Spec.Signature.PublicKey.Content = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: a.spki})
	reqBody, err := json.Marshal(pe)
	if err != nil {
		return nil, err
	}
	status, body, loc, err := a.do(ctx, http.MethodPost, a.ep.Rekor+"/api/v1/log/entries", "application/json", reqBody)
	if err != nil {
		return nil, err
	}
	if status == http.StatusConflict && loc != "" {
		// Already entered (a retry after a lost answer): the same entry.
		u := loc
		if !strings.HasPrefix(u, "https://") {
			u = a.ep.Rekor + loc
		}
		if status, body, _, err = a.do(ctx, http.MethodGet, u, "", nil); err != nil {
			return nil, err
		}
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, fmt.Errorf("anchor: Rekor answered %d", status)
	}
	var entries map[string]logEntry
	if err := json.Unmarshal(body, &entries); err != nil || len(entries) != 1 {
		return nil, errors.New("anchor: Rekor's answer is not one entry")
	}
	var e logEntry
	for _, v := range entries {
		e = v
	}
	return a.check(&e, digest, sig)
}

// check makes sure Rekor entered what was sent, under this key, and that
// the inclusion proof reaches its root (RFC 6962, which Rekor's tree is).
func (a *Anchorer) check(e *logEntry, digest, sig []byte) (*tlogEntry, error) {
	canon, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil, errors.New("anchor: the entry's body isn't base64")
	}
	var got hashedrekord
	if err := json.Unmarshal(canon, &got); err != nil || got.Kind != "hashedrekord" || got.Spec.Data.Hash.Algorithm != "sha256" ||
		got.Spec.Data.Hash.Value != hex.EncodeToString(digest) || !bytes.Equal(got.Spec.Signature.Content, sig) {
		return nil, errors.New("anchor: Rekor entered something else")
	}
	if blk, _ := pem.Decode(got.Spec.Signature.PublicKey.Content); blk == nil || !bytes.Equal(blk.Bytes, a.spki) {
		return nil, errors.New("anchor: Rekor's entry names another key")
	}
	ip := e.Verification.InclusionProof
	if ip == nil || len(e.Verification.SignedEntryTimestamp) == 0 {
		return nil, errors.New("anchor: the entry has no inclusion proof or promise")
	}
	root, err := hex.DecodeString(ip.RootHash)
	if err != nil {
		return nil, errors.New("anchor: bad root hash")
	}
	hashes := make([][]byte, len(ip.Hashes))
	for i, s := range ip.Hashes {
		if hashes[i], err = hex.DecodeString(s); err != nil {
			return nil, errors.New("anchor: bad proof hash")
		}
	}
	if !ballot.VerifyProof(root, canon, int(ip.LogIndex), int(ip.TreeSize), hashes) {
		return nil, errors.New("anchor: the inclusion proof doesn't reach the root")
	}
	id, err := hex.DecodeString(e.LogID)
	if err != nil {
		return nil, errors.New("anchor: bad log id")
	}
	return &tlogEntry{
		LogIndex: strconv.FormatInt(e.LogIndex, 10), LogID: logID{KeyID: id},
		KindVersion:      kindVersion{Kind: "hashedrekord", Version: got.APIVersion},
		IntegratedTime:   strconv.FormatInt(e.IntegratedTime, 10),
		InclusionPromise: inclusionPromise{SignedEntryTimestamp: e.Verification.SignedEntryTimestamp},
		InclusionProof: inclusionProof{LogIndex: strconv.FormatInt(ip.LogIndex, 10), RootHash: root,
			TreeSize: strconv.FormatInt(ip.TreeSize, 10), Hashes: hashes, Checkpoint: checkpoint{Envelope: ip.Checkpoint}},
		CanonicalizedBody: canon,
	}, nil
}

// RFC 3161 (and RFC 5816's id-sha256): a TimeStampReq for SHA-256 of the
// signature, as sigstore-go asks for it.
var oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

type tsReq struct {
	Version        int
	MessageImprint messageImprint
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type tsResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status int
	Rest   asn1.RawValue `asn1:"optional"`
}

// timestamp asks the timestamp authority to stamp the signature and
// returns its TimeStampResp, which the bundle carries as it came.
func (a *Anchorer) timestamp(ctx context.Context, sig []byte) ([]byte, error) {
	h := sha256.Sum256(sig)
	req, err := asn1.Marshal(tsReq{Version: 1, MessageImprint: messageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, HashedMessage: h[:]}})
	if err != nil {
		return nil, err
	}
	status, body, _, err := a.do(ctx, http.MethodPost, a.ep.TSA, "application/timestamp-query", req)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, fmt.Errorf("anchor: the timestamp authority answered %d", status)
	}
	var r tsResp
	rest, err := asn1.Unmarshal(body, &r)
	// Granted (0) or granted with modifications (1), with a token.
	if err != nil || len(rest) != 0 || r.Status.Status > 1 || len(r.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("anchor: the timestamp authority didn't grant a timestamp")
	}
	return body, nil
}

// do makes one request, retrying a 5xx or 429 twice.
func (a *Anchorer) do(ctx context.Context, method, url, ctype string, body []byte) (int, []byte, string, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return 0, nil, "", err
		}
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if url != a.ep.TSA {
			req.Header.Set("Accept", "application/json")
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return 0, nil, "", err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
		resp.Body.Close()
		if err != nil {
			return 0, nil, "", err
		}
		retry := resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests
		if !retry || attempt == 2 {
			return resp.StatusCode, data, resp.Header.Get("Location"), nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, "", ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * time.Second):
		}
	}
}
