package publish

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
)

// The AnchorSigner (key protection, phase 1, GC #7406 §1 as amended for
// #7648): a function in the signer's own account that holds the anchor
// key in KMS and publishes each document itself (checks, claim, sign,
// timestamp, transparency log, upload). With Publisher.Signer set, the
// service never holds the anchor key: it sends the document and its IK
// signature, and gets back the site's answer and the bundle.

// SignerTimeout is the client's deadline for one call: the function's own
// timeout is 120 s, and the task waits a little longer so that a slow
// call ends on the function's side first (GC #7406 §1, "Timeouts").
const SignerTimeout = 150 * time.Second

// SignerRequest is one call (votes signer.Request).
type SignerRequest struct {
	ProposalID string `json:"proposal_id"`
	Name       string `json:"name"`
	Doc        []byte `json:"doc"`
	Sig        []byte `json:"sig"`
	Rows       []byte `json:"rows,omitempty"`
}

// SignerResult is a call's answer (votes signer.Result): the site's answer
// to the upload, or the signer's own refusal, and the anchor key's
// SubjectPublicKeyInfo, which every answer carries.
type SignerResult struct {
	Status       int             `json:"status"`
	Code         string          `json:"code,omitempty"`
	Bundle       json.RawMessage `json:"bundle,omitempty"`
	IndexUpdated bool            `json:"index_updated"`
	AnchorKey    []byte          `json:"anchor_key"`
}

// Signer calls the AnchorSigner. An error is a failure: nothing is known
// to be published, and the caller retries later, which the signer's
// claim turns into a resume.
type Signer interface {
	Call(ctx context.Context, req SignerRequest) (SignerResult, error)
}

// ErrSignerFailed is the function failing (a FunctionError, or no answer).
var ErrSignerFailed = errors.New("publish: the anchor signer failed: not published")

// LambdaAPI is the part of the Lambda client the signer uses.
type LambdaAPI interface {
	Invoke(ctx context.Context, in *lambda.InvokeInput, opts ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

// LambdaSigner invokes the signer synchronously by its unqualified ARN.
type LambdaSigner struct {
	Client      LambdaAPI
	FunctionARN string
}

// maxSignerAnswer bounds the answer read: a bundle and a few fields.
const maxSignerAnswer = 256 << 10

// Call implements Signer.
func (l *LambdaSigner) Call(ctx context.Context, req SignerRequest) (SignerResult, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return SignerResult{}, err
	}
	return l.invoke(ctx, payload, SignerTimeout)
}

// recordTimeout bounds each record write around a signer call (the mark,
// the bundle), which run detached from the request.
const recordTimeout = 10 * time.Second

// ProbeTimeout is the probe's deadline: it asks for nothing but the key.
const ProbeTimeout = 15 * time.Second

// Probe asks the signer for the anchor key alone: an empty call, which it
// refuses as malformed (bad_request) before any work (no claim, no sign),
// answering with its anchor key.
func (l *LambdaSigner) Probe(ctx context.Context) ([]byte, error) {
	r, err := l.invoke(ctx, []byte(`{}`), ProbeTimeout)
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusBadRequest || r.Code != "bad_request" || len(r.AnchorKey) == 0 {
		return nil, fmt.Errorf("publish: the anchor signer's probe answered %d %q without the anchor key", r.Status, r.Code)
	}
	return r.AnchorKey, nil
}

func (l *LambdaSigner) invoke(ctx context.Context, payload []byte, timeout time.Duration) (SignerResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := l.Client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   aws.String(l.FunctionARN),
		InvocationType: types.InvocationTypeRequestResponse,
		LogType:        types.LogTypeNone,
		Payload:        payload,
	})
	if err != nil {
		return SignerResult{}, fmt.Errorf("%w: %v", ErrSignerFailed, err)
	}
	if out.FunctionError != nil {
		// The function's error type only: its message may echo input.
		return SignerResult{}, fmt.Errorf("%w: %s", ErrSignerFailed, aws.ToString(out.FunctionError))
	}
	if len(out.Payload) > maxSignerAnswer {
		return SignerResult{}, fmt.Errorf("%w: an answer over %d bytes", ErrSignerFailed, maxSignerAnswer)
	}
	var r SignerResult
	dec := json.NewDecoder(bytes.NewReader(out.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || dec.More() {
		return SignerResult{}, fmt.Errorf("%w: the answer doesn't parse", ErrSignerFailed)
	}
	return r, nil
}

// KindSignerCall marks a document sent to the signer, by its SHA-256
// (hex), before the call: the signer may have signed it even if this
// service never learned the bundle (a crash, a lost answer), so the
// document is not judged never anchored (Attempted).
const KindSignerCall = "vote_signer_call"

// Attempted implements ballot.AttemptSource: whether doc was ever sent to
// the signer (or anchored here, StoredBundle).
func (p *Publisher) Attempted(ctx context.Context, doc []byte) (bool, error) {
	if b, err := p.StoredBundle(ctx, doc); err != nil || b != nil {
		return b != nil, err
	}
	key := sha256.Sum256(doc)
	if p.Records == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.called[key], nil
	}
	_, ok, err := p.Records.Get(ctx, KindSignerCall, hex.EncodeToString(key[:]))
	return ok, err
}

func (p *Publisher) markCalled(ctx context.Context, doc []byte) error {
	key := sha256.Sum256(doc)
	if p.Records == nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.called == nil {
			p.called = map[[32]byte]bool{}
		}
		p.called[key] = true
		return nil
	}
	err := p.Records.Apply(ctx, []peer.Change{{Kind: KindSignerCall, ID: hex.EncodeToString(key[:]), Data: []byte(`{}`), IfAbsent: true}})
	if errors.Is(err, peer.ErrConflict) {
		return nil // marked before
	}
	return err
}

// keep stores b as doc's bundle: the bundle the site holds, which the
// signer returned. One kept before (an anchor of this service's own, from
// before the signer, never uploaded) is replaced, so that StoredBundle
// answers what the site holds.
func (p *Publisher) keep(ctx context.Context, doc []byte, b json.RawMessage) error {
	key := sha256.Sum256(doc)
	if p.Records != nil {
		id := hex.EncodeToString(key[:])
		old, ok, err := p.Records.Get(ctx, KindBundle, id)
		if err != nil {
			return err
		}
		if !ok || !bytes.Equal(old, b) {
			if err := p.Records.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: id, Data: b}}); err != nil {
				return err
			}
		}
	}
	p.mu.Lock()
	if p.bundles == nil {
		p.bundles = map[[32]byte]json.RawMessage{}
	}
	p.bundles[key] = b
	p.mu.Unlock()
	return nil
}

// viaSigner publishes doc through the signer. The signer checks, claims,
// signs, stamps, logs and uploads; this service keeps the bundle the site
// holds. Results are checked after: the site refuses results anchored
// before collection ended (VOTES-SITE §4), so one it took that this check
// refuses is an alarm, not a retry (the site holds it).
func (p *Publisher) viaSigner(ctx context.Context, id, name string, doc, sig, rows []byte, notBefore int64) (ballot.Receipt, error) {
	pub, err := pinnedKey(p.AnchorKey)
	if err != nil {
		return ballot.Receipt{}, fmt.Errorf("publish: the pinned anchor key: %w", err)
	}
	// The call outlives the API request that started it (its 30 s write
	// timeout): a signer's answer that arrives is kept, so the next try
	// finds the bundle. SignerTimeout still bounds it.
	ctx = context.WithoutCancel(ctx)
	mctx, cancel := context.WithTimeout(ctx, recordTimeout)
	err = p.markCalled(mctx, doc)
	cancel()
	if err != nil {
		return ballot.Receipt{}, err
	}
	r, err := p.Signer.Call(ctx, SignerRequest{ProposalID: id, Name: name, Doc: doc, Sig: sig, Rows: rows})
	if err != nil {
		p.log().Warn("publish: the anchor signer failed; retried later", "proposal_id", id, "name", name, "err", err.Error())
		return ballot.Receipt{}, err
	}
	// Every answer of the signer carries its key (refusals included); an
	// error status without one is judged by its status alone, but a
	// success needs the pinned key.
	success := r.Status == http.StatusCreated || r.Status == http.StatusOK
	if (success || len(r.AnchorKey) > 0) && !bytes.Equal(r.AnchorKey, p.AnchorKey) {
		p.log().Error("the anchor signer answered under another anchor key than the one pinned", "alarm", "anchor_key_changed",
			"proposal_id", id, "name", name)
		return ballot.Receipt{}, errors.New("publish: the anchor signer's key is not the pinned anchor key")
	}
	switch {
	case r.Status == http.StatusCreated || r.Status == http.StatusOK:
		if len(r.Bundle) == 0 {
			return ballot.Receipt{}, fmt.Errorf("publish: the anchor signer answered %d without a bundle", r.Status)
		}
		// The bundle is checked, not the answer's word: its signature
		// must be the pinned key's over this document.
		if err := VerifyBundleSignature(pub, doc, r.Bundle); err != nil {
			p.log().Error("the anchor signer returned a bundle not signed by the pinned key over this document", "alarm", "signer_bundle_unverified",
				"proposal_id", id, "name", name, "err", err.Error())
			return ballot.Receipt{}, fmt.Errorf("publish: the signer's bundle: %w", err)
		}
		kctx, cancel := context.WithTimeout(ctx, recordTimeout)
		err := p.keep(kctx, doc, r.Bundle)
		cancel()
		if err != nil {
			return ballot.Receipt{}, err
		}
		if notBefore > 0 {
			p.checkPublishedResults(id, doc, r.Bundle, notBefore)
		}
		if !r.IndexUpdated {
			p.log().Warn("publish: the site's index is not updated", "proposal_id", id, "name", name)
		}
		return ballot.Receipt{Bundle: r.Bundle, IndexStale: !r.IndexUpdated}, nil
	case r.Status >= 500 && r.Status <= 599 || r.Status == http.StatusTooManyRequests:
		return ballot.Receipt{}, fmt.Errorf("publish: votes.vettid.org answered %d %s (through the anchor signer)", r.Status, r.Code)
	case r.Status >= 400 && r.Status <= 499:
		return ballot.Receipt{}, &ErrRefused{Status: r.Status, Code: r.Code}
	}
	// No status, or one no answer should carry: not a refusal to act on.
	return ballot.Receipt{}, fmt.Errorf("%w: an answer with status %d", ErrSignerFailed, r.Status)
}

// pinnedKey parses the pinned anchor key (an SPKI) as P-256.
func pinnedKey(spki []byte) (*ecdsa.PublicKey, error) {
	if len(spki) == 0 {
		return nil, errors.New("none")
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return pub, nil
}

// VerifyBundleSignature checks a Sigstore bundle's message signature: a
// SHA-256 digest that is the document's, and an ECDSA signature by pub
// over it. The bundle's other parts (the timestamp, the log entry) are
// checked where they are used (anchor.TimestampTime).
func VerifyBundleSignature(pub *ecdsa.PublicKey, doc []byte, bundle json.RawMessage) error {
	// Parsed strictly along the path read: each object's names unique,
	// also ignoring case (encoding/json would take a case variant, and
	// the last of duplicates), so no other reader can see another value.
	top, err := strictObject(bundle)
	if err != nil {
		return fmt.Errorf("the bundle: %w", err)
	}
	ms, err := strictObject(top["messageSignature"])
	if err != nil {
		return fmt.Errorf("the bundle's messageSignature: %w", err)
	}
	md, err := strictObject(ms["messageDigest"])
	if err != nil {
		return fmt.Errorf("the bundle's messageDigest: %w", err)
	}
	var alg string
	var digest, sig []byte
	if json.Unmarshal(md["algorithm"], &alg) != nil || json.Unmarshal(md["digest"], &digest) != nil || json.Unmarshal(ms["signature"], &sig) != nil {
		return errors.New("the bundle's message signature doesn't parse")
	}
	want := sha256.Sum256(doc)
	if alg != "SHA2_256" {
		return fmt.Errorf("the bundle's digest algorithm is %q, not SHA2_256", alg)
	}
	if !bytes.Equal(digest, want[:]) {
		return errors.New("the bundle's digest is not this document's")
	}
	if !ecdsa.VerifyASN1(pub, want[:], sig) {
		return errors.New("the bundle's signature doesn't verify under the pinned anchor key")
	}
	return nil
}

// strictObject reads a JSON object's members, refusing anything but an
// object, and a name that appears twice, also as a case variant.
func strictObject(data json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, _ := t.(string)
		folded := strings.ToLower(name)
		if seen[folded] {
			return nil, fmt.Errorf("the name %q appears twice", name)
		}
		seen[folded] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[name] = v
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, errors.New("not an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	return out, nil
}

// checkPublishedResults alarms on published results whose bundle doesn't
// verify, or is timestamped before the close: they are on the site, so
// nothing is retried, but someone must look.
func (p *Publisher) checkPublishedResults(id string, doc []byte, bundle json.RawMessage, notBefore int64) {
	if p.Timestamp == nil {
		p.log().Error("the published results' timestamp can't be checked", "alarm", "results_bundle_unverified", "proposal_id", id)
		return
	}
	t, err := p.Timestamp(bundle, doc)
	if err != nil {
		p.log().Error("the published results' bundle doesn't verify", "alarm", "results_bundle_unverified", "proposal_id", id, "err", err.Error())
		return
	}
	if t < notBefore {
		p.log().Error("the published results were timestamped before the close", "alarm", "results_stamped_early", "proposal_id", id, "timestamp", t, "closes_at", notBefore)
	}
}
