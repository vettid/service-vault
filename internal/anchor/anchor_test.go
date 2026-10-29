package anchor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
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
}

func (f *fakeSigstore) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	entry := func() []byte {
		leaf := vote.LeafHash(f.entered)
		out, _ := json.Marshal(map[string]any{"24296fb24b8ad77a": map[string]any{
			"body": base64.StdEncoding.EncodeToString(f.entered), "integratedTime": 1793520000, "logID": "c0d23d6ad406973f", "logIndex": 7,
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
			w.Header().Set("Location", "/api/v1/log/entries/24296fb24b8ad77a")
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
		var req tsReq
		if _, err := asn1.Unmarshal(b, &req); err != nil || !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
			t.Errorf("timestamp request: %v", err)
		}
		token, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{0x05, 0x00}})
		resp, _ := asn1.Marshal(tsResp{Status: pkiStatusInfo{Status: 0}, TimeStampToken: asn1.RawValue{FullBytes: token}})
		_, _ = w.Write(resp)
	})
	return mux
}

func newFake(t *testing.T) (*Anchorer, *fakeSigstore, *ecdsa.PrivateKey) {
	t.Helper()
	f := &fakeSigstore{}
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
	f.conflict, f.tamper = false, true
	if _, err := a.Anchor(context.Background(), []byte("doc")); err == nil {
		t.Fatal("accepted an entry of another digest")
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
