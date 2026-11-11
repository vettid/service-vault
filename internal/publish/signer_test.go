package publish

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
)

// fakeLambda answers each Invoke with out (or err), and records the call.
type fakeLambda struct {
	out      *lambda.InvokeOutput
	err      error
	in       *lambda.InvokeInput
	deadline time.Duration
}

func (f *fakeLambda) Invoke(ctx context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	f.in = in
	if d, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(d)
	}
	return f.out, f.err
}

func answer(t *testing.T, r SignerResult) *lambda.InvokeOutput {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return &lambda.InvokeOutput{StatusCode: 200, Payload: b}
}

// anchorPriv is the pinned anchor key in these tests; listedKey its SPKI.
var anchorPriv, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var listedKey, _ = x509.MarshalPKIXPublicKey(&anchorPriv.PublicKey)

// signedBundle is a bundle whose message signature is by key over doc.
func signedBundle(t *testing.T, key *ecdsa.PrivateKey, doc []byte, extra string) json.RawMessage {
	t.Helper()
	d := sha256.Sum256(doc)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "extra": extra,
		"messageSignature": map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": d[:]}, "signature": sig}})
	return b
}

// The invoke: synchronous, by the ARN, the request as the signer takes it,
// under the 150 s deadline; a FunctionError or no answer is a failure, and
// an answer that doesn't parse strictly is one too.
func TestLambdaSigner(t *testing.T) {
	ctx := context.Background()
	f := &fakeLambda{out: answer(t, SignerResult{Status: 201, Bundle: json.RawMessage(`{"b":1}`), IndexUpdated: true, AnchorKey: listedKey})}
	ls := &LambdaSigner{Client: f, FunctionARN: "arn:aws:lambda:us-east-1:123456789012:function:s"}
	r, err := ls.Call(ctx, SignerRequest{ProposalID: "p", Name: "proposal", Doc: []byte("d"), Sig: []byte("s")})
	if err != nil || r.Status != 201 || !bytes.Equal(r.AnchorKey, listedKey) {
		t.Fatalf("%+v %v", r, err)
	}
	if aws.ToString(f.in.FunctionName) != ls.FunctionARN || f.in.InvocationType != types.InvocationTypeRequestResponse {
		t.Fatalf("invoke %+v", f.in)
	}
	var sent map[string]any
	if err := json.Unmarshal(f.in.Payload, &sent); err != nil || sent["proposal_id"] != "p" || sent["name"] != "proposal" || sent["doc"] != "ZA==" {
		t.Fatalf("payload %s", f.in.Payload)
	}
	if _, ok := sent["rows"]; ok {
		t.Fatal("rows sent for a proposal")
	}
	if f.deadline <= SignerTimeout-time.Second || f.deadline > SignerTimeout {
		t.Fatalf("deadline %v", f.deadline)
	}
	for name, fl := range map[string]*fakeLambda{
		"function error": {out: &lambda.InvokeOutput{StatusCode: 200, FunctionError: aws.String("NotPublished"), Payload: []byte(`{"errorMessage":"x"}`)}},
		"no answer":      {err: errors.New("dial tcp: timeout")},
		"unknown field":  {out: &lambda.InvokeOutput{StatusCode: 200, Payload: []byte(`{"status":201,"anchor_key":"AA==","extra":1}`)}},
		"trailing data":  {out: &lambda.InvokeOutput{StatusCode: 200, Payload: []byte(`{"status":201} {}`)}},
		"too large":      {out: &lambda.InvokeOutput{StatusCode: 200, Payload: bytes.Repeat([]byte(" "), maxSignerAnswer+1)}},
	} {
		ls := &LambdaSigner{Client: fl, FunctionARN: "arn"}
		if _, err := ls.Call(ctx, SignerRequest{}); !errors.Is(err, ErrSignerFailed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The probe: an empty call, answered 400 with the key, or an error.
func TestLambdaSignerProbe(t *testing.T) {
	ctx := context.Background()
	f := &fakeLambda{out: answer(t, SignerResult{Status: 400, Code: "bad_request", AnchorKey: listedKey})}
	key, err := (&LambdaSigner{Client: f, FunctionARN: "arn"}).Probe(ctx)
	if err != nil || !bytes.Equal(key, listedKey) || string(f.in.Payload) != "{}" {
		t.Fatalf("%q %v %s", key, err, f.in.Payload)
	}
	if f.deadline <= ProbeTimeout-time.Second || f.deadline > ProbeTimeout {
		t.Fatalf("probe deadline %v", f.deadline)
	}
	for name, r := range map[string]SignerResult{
		"no key":       {Status: 400, Code: "bad_request"},
		"accepted":     {Status: 201, AnchorKey: listedKey},
		"another code": {Status: 400, Code: "bad_anchor", AnchorKey: listedKey},
	} {
		if _, err := (&LambdaSigner{Client: &fakeLambda{out: answer(t, r)}, FunctionARN: "arn"}).Probe(ctx); err == nil {
			t.Errorf("%s: probe accepted", name)
		}
	}
}

// fakeSigner answers Call with r (or err) and records the requests.
type fakeSigner struct {
	r    SignerResult
	err  error
	reqs []SignerRequest
}

func (f *fakeSigner) Call(_ context.Context, req SignerRequest) (SignerResult, error) {
	f.reqs = append(f.reqs, req)
	return f.r, f.err
}

// noAnchor fails the test if anything anchors here.
type noAnchor struct{ t *testing.T }

func (n noAnchor) Anchor(context.Context, []byte) (json.RawMessage, error) {
	n.t.Fatal("anchored here with the signer configured")
	return nil, nil
}

func signerPublisher(t *testing.T, f *fakeSigner, log *bytes.Buffer) *Publisher {
	return &Publisher{URL: "https://votes.example", Signer: f, AnchorKey: listedKey, Anchor: noAnchor{t},
		Records: peer.NewMemStore(), Log: slog.New(slog.NewJSONHandler(log, nil))}
}

// Through the signer: the document goes to it, nothing anchors here, and
// the site's bundle it answers with is kept as this document's.
func TestPublishViaSigner(t *testing.T) {
	ctx := context.Background()
	var log bytes.Buffer
	site := signedBundle(t, anchorPriv, []byte("doc"), "site")
	f := &fakeSigner{r: SignerResult{Status: 201, Bundle: site, IndexUpdated: false, AnchorKey: listedKey}}
	p := signerPublisher(t, f, &log)
	// A bundle this service anchored itself before the signer, never
	// uploaded, is replaced by the site's.
	if err := p.keep(ctx, []byte("doc"), json.RawMessage(`{"old":1}`)); err != nil {
		t.Fatal(err)
	}
	b, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig"))
	if err != nil || !bytes.Equal(b, site) {
		t.Fatalf("%s %v", b, err)
	}
	if len(f.reqs) != 1 || f.reqs[0].ProposalID != "p1" || f.reqs[0].Name != "proposal" || string(f.reqs[0].Sig) != "sig" {
		t.Fatalf("%+v", f.reqs)
	}
	if kept, _ := p.StoredBundle(ctx, []byte("doc")); !bytes.Equal(kept, site) {
		t.Fatalf("kept %s", kept)
	}
	p2 := &Publisher{Records: p.Records} // a restart reads it from Records
	if kept, _ := p2.StoredBundle(ctx, []byte("doc")); !bytes.Equal(kept, site) {
		t.Fatalf("kept after a restart %s", kept)
	}
	f.r.Bundle = signedBundle(t, anchorPriv, []byte("ext"), "")
	rc, err := p.PublishExtension(ctx, "p1", 2, []byte("ext"), []byte("s2"))
	if err != nil || !rc.IndexStale || f.reqs[1].Name != "extension-2" {
		t.Fatalf("%+v %v %+v", rc, err, f.reqs[1])
	}
}

// The call outlives the API request that started it (its 30 s write
// timeout): a canceled request context doesn't cancel it.
func TestPublishViaSignerOutlivesTheRequest(t *testing.T) {
	var log bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := &ctxSigner{r: SignerResult{Status: 201, Bundle: signedBundle(t, anchorPriv, []byte("doc"), ""), IndexUpdated: true, AnchorKey: listedKey}}
	p := signerPublisher(t, nil, &log)
	p.Signer = f
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err != nil || f.canceled {
		t.Fatalf("%v, canceled %v", err, f.canceled)
	}
}

// ctxSigner records whether the call's context was already canceled.
type ctxSigner struct {
	r        SignerResult
	canceled bool
}

func (c *ctxSigner) Call(ctx context.Context, _ SignerRequest) (SignerResult, error) {
	c.canceled = ctx.Err() != nil
	return c.r, nil
}

// Failures: the signer failing is "not published" (retried), but the
// document is marked as sent; another key, a missing bundle, 5xx and 429
// are errors to retry; other statuses are the site's refusals.
func TestPublishViaSignerFailures(t *testing.T) {
	ctx := context.Background()
	var log bytes.Buffer
	f := &fakeSigner{err: ErrSignerFailed}
	p := signerPublisher(t, f, &log)
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); !errors.Is(err, ErrSignerFailed) {
		t.Fatalf("%v", err)
	}
	if ok, _ := p.Attempted(ctx, []byte("doc")); !ok {
		t.Fatal("a document sent to the signer isn't marked as attempted")
	}
	if ok, _ := (&Publisher{Records: p.Records}).Attempted(ctx, []byte("doc")); !ok {
		t.Fatal("the mark doesn't outlive a restart")
	}
	if ok, _ := p.Attempted(ctx, []byte("never sent")); ok {
		t.Fatal("a document never sent is attempted")
	}
	f.err = nil
	f.r = SignerResult{Status: 201, Bundle: signedBundle(t, anchorPriv, []byte("doc"), ""), AnchorKey: []byte("another key")}
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil || !strings.Contains(log.String(), "anchor_key_changed") {
		t.Fatalf("another key: %v", err)
	}
	if kept, _ := p.StoredBundle(ctx, []byte("doc")); kept != nil {
		t.Fatal("a bundle under another key was kept")
	}
	f.r = SignerResult{Status: 201, AnchorKey: listedKey}
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil {
		t.Fatal("201 without a bundle")
	}
	// The bundle itself is checked: the right key field is not enough.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, b := range map[string]json.RawMessage{
		"another key's signature": signedBundle(t, other, []byte("doc"), ""),
		"another document":        signedBundle(t, anchorPriv, []byte("other doc"), ""),
		"no signature":            json.RawMessage(`{"messageSignature":{}}`),
		"not JSON":                json.RawMessage(`{`),
	} {
		log.Reset()
		f.r = SignerResult{Status: 201, Bundle: b, AnchorKey: listedKey}
		if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil || !strings.Contains(log.String(), "signer_bundle_unverified") {
			t.Fatalf("%s: %v", name, err)
		}
		if kept, _ := p.StoredBundle(ctx, []byte("doc")); kept != nil {
			t.Fatalf("%s: kept", name)
		}
	}
	// No status, or one no answer carries: retried, not a refusal.
	for _, st := range []int{0, 100, 204, 302} {
		f.r = SignerResult{Status: st, AnchorKey: listedKey}
		if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); !errors.Is(err, ErrSignerFailed) {
			t.Fatalf("status %d: %v", st, err)
		}
	}
	var ref *ErrRefused
	for _, st := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		f.r = SignerResult{Status: st, AnchorKey: listedKey}
		if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil || errors.As(err, &ref) {
			t.Fatalf("%d: %v", st, err)
		}
	}
	f.r = SignerResult{Status: 422, Code: "too_late", AnchorKey: listedKey}
	if _, err := p.PublishExtension(ctx, "p1", 1, []byte("ext"), []byte("s")); !errors.As(err, &ref) || ref.Code != "too_late" || ref.Status != 422 {
		t.Fatalf("too_late: %v", err)
	}
	f.r = SignerResult{Status: 409, Code: "claim_conflict", AnchorKey: listedKey}
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); !errors.As(err, &ref) || ref.Code != "claim_conflict" {
		t.Fatalf("claim conflict: %v", err)
	}
	if (&Publisher{Signer: f, Records: peer.NewMemStore()}).viaSignerNoKey(ctx) == nil {
		t.Fatal("published with no listed key to check against")
	}
}

// viaSignerNoKey publishes with no listed key (the test above).
func (p *Publisher) viaSignerNoKey(ctx context.Context) error {
	_, err := p.PublishProposal(ctx, "p", []byte("d"), []byte("s"))
	return err
}

// Results through the signer: published, and checked after. Early or
// unverifiable results the site took are an alarm, not a retry: the site
// holds them. Results again (a stale index) go through the signer too.
func TestPublishResultsViaSigner(t *testing.T) {
	ctx := context.Background()
	const closes = int64(1_800_000_000)
	for name, c := range map[string]struct {
		stamp int64
		bad   bool
		alarm string
	}{
		"after the close": {closes + 5, false, ""},
		"early":           {closes - 5, false, "results_stamped_early"},
		"unverifiable":    {0, true, "results_bundle_unverified"},
	} {
		var log bytes.Buffer
		bundle := signedBundle(t, anchorPriv, []byte("res"), name)
		f := &fakeSigner{r: SignerResult{Status: 201, Bundle: bundle, IndexUpdated: true, AnchorKey: listedKey}}
		p := signerPublisher(t, f, &log)
		p.Timestamp = func(b json.RawMessage, _ []byte) (int64, error) {
			if c.bad {
				return 0, errors.New("doesn't verify")
			}
			return c.stamp, nil
		}
		rc, err := p.PublishResults(ctx, "p1", []byte("res"), []byte("sig"), []byte("rows"), closes)
		if err != nil || !bytes.Equal(rc.Bundle, bundle) {
			t.Fatalf("%s: %v", name, err)
		}
		if string(f.reqs[0].Rows) != "rows" || f.reqs[0].Name != "results" {
			t.Fatalf("%s: %+v", name, f.reqs[0])
		}
		if (c.alarm == "") != !strings.Contains(log.String(), `"alarm"`) || (c.alarm != "" && !strings.Contains(log.String(), c.alarm)) {
			t.Fatalf("%s: log %s", name, log.String())
		}
		if _, err := p.RepublishResults(ctx, "p1", []byte("res"), []byte("sig"), []byte("rows"), bundle, closes); err != nil || len(f.reqs) != 2 {
			t.Fatalf("%s: again %v", name, err)
		}
	}
}

var _ ballot.AttemptSource = (*Publisher)(nil)

// The bundle's fields, each checked on its own: a valid signature over
// the document doesn't save a wrong digest field or algorithm, and names
// that appear twice (also as a case variant) are refused, so no reader
// sees another value.
func TestVerifyBundleSignatureFields(t *testing.T) {
	doc := []byte("doc")
	d := sha256.Sum256(doc)
	sig, _ := ecdsa.SignASN1(rand.Reader, anchorPriv, d[:])
	other := sha256.Sum256([]byte("other"))
	b64 := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	mk := func(alg, digest string) json.RawMessage {
		return json.RawMessage(`{"messageSignature":{"messageDigest":{"algorithm":"` + alg + `","digest":"` + digest + `"},"signature":"` + b64(sig) + `"}}`)
	}
	if err := VerifyBundleSignature(&anchorPriv.PublicKey, doc, mk("SHA2_256", b64(d[:]))); err != nil {
		t.Fatalf("the good one: %v", err)
	}
	ms := `"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + b64(d[:]) + `"},"signature":"` + b64(sig) + `"}`
	for name, b := range map[string]json.RawMessage{
		"another digest field":  mk("SHA2_256", b64(other[:])),
		"another algorithm":     mk("SHA2_384", b64(d[:])),
		"a duplicate member":    json.RawMessage(`{` + ms + `,` + ms + `}`),
		"a case variant":        json.RawMessage(`{` + ms + `,"MessageSignature":{}}`),
		"a nested case variant": json.RawMessage(`{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"` + b64(d[:]) + `","Digest":"` + b64(other[:]) + `"},"signature":"` + b64(sig) + `"}}`),
		"data after the object": json.RawMessage(`{` + ms + `} {}`),
		"not an object":         json.RawMessage(`[]`),
		"no message signature":  json.RawMessage(`{}`),
	} {
		if err := VerifyBundleSignature(&anchorPriv.PublicKey, doc, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An error status without a key is judged by its status, with no false
// key alarm; a success without the key is the alarm.
func TestPublishViaSignerErrorWithoutKey(t *testing.T) {
	ctx := context.Background()
	var log bytes.Buffer
	f := &fakeSigner{r: SignerResult{Status: 503}}
	p := signerPublisher(t, f, &log)
	var ref *ErrRefused
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil || errors.As(err, &ref) || strings.Contains(log.String(), "anchor_key_changed") {
		t.Fatalf("503: %v %s", err, log.String())
	}
	f.r = SignerResult{Status: 422, Code: "too_late"}
	if _, err := p.PublishExtension(ctx, "p1", 1, []byte("e"), []byte("s")); !errors.As(err, &ref) || strings.Contains(log.String(), "anchor_key_changed") {
		t.Fatalf("422: %v %s", err, log.String())
	}
	f.r = SignerResult{Status: 201, Bundle: signedBundle(t, anchorPriv, []byte("doc"), "")}
	if _, err := p.PublishProposal(ctx, "p1", []byte("doc"), []byte("sig")); err == nil || !strings.Contains(log.String(), "anchor_key_changed") {
		t.Fatalf("a success without the key: %v", err)
	}
}
