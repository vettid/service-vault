package anchor

import (
	"context"
	"crypto"
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
	"github.com/digitorus/timestamp"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/vettid/service-vault/vote"
)

// fakeSigstore is a Rekor that enters whatever it is sent in a one-entry
// tree, and a timestamp authority that grants every request.
type fakeSigstore struct {
	entered  []byte // the canonical body it last entered
	tamper   bool   // enter another digest than the one sent
	conflict bool   // answer 409, as for an entry already there
	// The throwaway TSA: its certificate (a test CA's, with the critical
	// time-stamping usage) and key, and how it answers ("" grants).
	tsaCert  *x509.Certificate
	tsaKey   *ecdsa.PrivateKey
	tsaMode  string
	location string // the 409's Location, when set
	skew     int64  // seconds the entry is integrated after now
}

func (f *fakeSigstore) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	entry := func() []byte {
		leaf := vote.LeafHash(f.entered)
		out, _ := json.Marshal(map[string]any{"24296fb24b8ad77a": map[string]any{
			"body": base64.StdEncoding.EncodeToString(f.entered), "integratedTime": time.Now().Unix() + f.skew, "logID": "c0d23d6ad406973f", "logIndex": 7,
			"verification": map[string]any{"signedEntryTimestamp": []byte("set"),
				"inclusionProof": map[string]any{"checkpoint": "rekor.sigstage.dev - 1\n1\n…\n", "hashes": []string{}, "logIndex": 0,
					"rootHash": hex.EncodeToString(leaf), "treeSize": 1}}}})
		return out
	}
	mux.HandleFunc("POST /api/v1/log/entries", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var pe hashedrekord
		if json.Unmarshal(b, &pe) != nil || pe.Kind != "hashedrekord" {
			http.Error(w, "bad entry", 400)
			return
		}
		if f.tamper {
			pe.Spec.Data.Hash.Value = hex.EncodeToString(make([]byte, 32))
		}
		f.entered, _ = json.Marshal(pe)
		if f.conflict {
			loc := "/api/v1/log/entries/24296fb24b8ad77a"
			if f.location != "" {
				loc = f.location
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(409)
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write(entry())
	})
	mux.HandleFunc("GET /api/v1/log/entries/24296fb24b8ad77a", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(entry()) })
	mux.HandleFunc("POST /api/v1/timestamp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/timestamp-query" {
			http.Error(w, "type", 400)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if req, err := timestamp.ParseRequest(b); err != nil || req.HashAlgorithm != crypto.SHA256 || req.Certificates {
			t.Errorf("timestamp request: %v", err)
		}
		req, _ := timestamp.ParseRequest(b)
		switch f.tsaMode {
		case "refused":
			resp, _ := timestamp.CreateErrorResponse(timestamp.Rejection, timestamp.BadAlgorithm)
			_, _ = w.Write(resp)
		case "notoken":
			// A granted status with no token: SEQUENCE { SEQUENCE { INTEGER 0 } }
			_, _ = w.Write([]byte{0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00})
		case "otherimprint":
			req.HashedMessage = make([]byte, 32)
			fallthrough
		default:
			resp, err := (&timestamp.Timestamp{HashAlgorithm: req.HashAlgorithm, HashedMessage: req.HashedMessage, Time: time.Now(),
				Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, AddTSACertificate: true}).CreateResponseWithOpts(f.tsaCert, f.tsaKey, crypto.SHA256)
			if err != nil {
				t.Errorf("signing the response: %v", err)
			}
			_, _ = w.Write(resp)
		}
	})
	return mux
}

func newFake(t *testing.T) (*Anchorer, *fakeSigstore, *ecdsa.PrivateKey) {
	t.Helper()
	f := &fakeSigstore{}
	f.tsaCert, f.tsaKey = testTSA(t)
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewWith(k, Endpoints{Rekor: srv.URL, TSA: srv.URL + "/api/v1/timestamp"}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return a, f, k
}

func TestAnchor(t *testing.T) {
	a, f, k := newFake(t)
	doc := []byte(`{"proposal_id":"01JBQZ0000000000000000000A","v":1}`)
	raw, err := a.Anchor(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	var b bundleJSON
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(doc)
	ms := b.MessageSignature
	if b.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" || ms.MessageDigest.Algorithm != "SHA2_256" ||
		string(ms.MessageDigest.Digest) != string(d[:]) || !ecdsa.VerifyASN1(&k.PublicKey, d[:], ms.Signature) {
		t.Fatal("the message signature")
	}
	vm := b.VerificationMaterial
	if vm.PublicKey.Hint != Hint(a.PublicKeyDER()) || len(vm.TlogEntries) != 1 || len(vm.TimestampVerificationData.RFC3161Timestamps) != 1 {
		t.Fatalf("verification material %+v", vm)
	}
	e := vm.TlogEntries[0]
	if e.LogIndex != "7" || e.KindVersion.Kind != "hashedrekord" || e.KindVersion.Version != "0.0.1" || string(e.CanonicalizedBody) != string(f.entered) {
		t.Fatalf("entry %+v", e)
	}
	// Int64 fields are strings and bytes are base64, as protojson writes them.
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	te := m["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
	if _, ok := te["integratedTime"].(string); !ok {
		t.Fatal("integratedTime is not a string")
	}
}

func TestAnchorRetryAndTamper(t *testing.T) {
	a, f, _ := newFake(t)
	f.conflict = true
	if _, err := a.Anchor(context.Background(), []byte("doc")); err != nil {
		t.Fatalf("an entry already there: %v", err)
	}
	for _, loc := range []string{"https://elsewhere.example/api/v1/log/entries/x", "//elsewhere.example/x"} {
		f.location = loc
		if _, err := a.Anchor(context.Background(), []byte("doc")); err == nil {
			t.Fatalf("followed a 409 to %s", loc)
		}
	}
	f.location = ""
	f.conflict, f.tamper = false, true
	if _, err := a.Anchor(context.Background(), []byte("doc")); err == nil {
		t.Fatal("accepted an entry of another digest")
	}
}

// A TSA that refuses, grants with no token, or stamps another imprint is
// an error; the signed response of the default fake is accepted.
func TestAnchorTSAResponses(t *testing.T) {
	a, f, _ := newFake(t)
	if _, err := a.Anchor(context.Background(), []byte("doc")); err != nil {
		t.Fatalf("a signed response: %v", err)
	}
	for _, mode := range []string{"refused", "notoken", "otherimprint"} {
		f.tsaMode = mode
		if _, err := a.Anchor(context.Background(), []byte("doc")); err == nil {
			t.Errorf("%s: accepted", mode)
		}
	}
}

// Against Sigstore's staging instance (a public log meant for tests),
// only with SV_LIVE_SIGSTORE=staging. SV_LIVE_BUNDLE_OUT, if set, is
// where the bundle and document are written, to check with Sigstore's
// own verifier.
func TestAnchorStagingLive(t *testing.T) {
	if os.Getenv("SV_LIVE_SIGSTORE") != Staging {
		t.Skip("set SV_LIVE_SIGSTORE=staging to anchor in Sigstore's staging log")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, err := New(Staging, k)
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"test":"service-vault anchor test","v":1}`)
	raw, err := a.Anchor(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("SV_LIVE_BUNDLE_OUT"); out != "" {
		for name, b := range map[string][]byte{"bundle.json": raw, "doc": doc, "key.der": a.PublicKeyDER()} {
			if err := os.WriteFile(out+"/"+name, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// testTSA makes a throwaway CA and a TSA certificate under it, with the
// time-stamping extended key usage marked critical, as RFC 3161 wants.
func testTSA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eku, _ := asn1.Marshal([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}})
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test tsa"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}
