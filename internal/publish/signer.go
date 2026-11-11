package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	return l.invoke(ctx, payload)
}

// Probe asks the signer for the anchor key alone: an empty call, which it
// refuses as malformed before any work (no claim, no sign), answering with
// its anchor key.
func (l *LambdaSigner) Probe(ctx context.Context) ([]byte, error) {
	r, err := l.invoke(ctx, []byte(`{}`))
	if err != nil {
		return nil, err
	}
	if r.Status != http.StatusBadRequest || len(r.AnchorKey) == 0 {
		return nil, fmt.Errorf("publish: the anchor signer's probe answered %d %q without the anchor key", r.Status, r.Code)
	}
	return r.AnchorKey, nil
}

func (l *LambdaSigner) invoke(ctx context.Context, payload []byte) (SignerResult, error) {
	ctx, cancel := context.WithTimeout(ctx, SignerTimeout)
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
	if len(p.AnchorKey) == 0 {
		return ballot.Receipt{}, errors.New("publish: no listed anchor key to check the signer's answers against")
	}
	if err := p.markCalled(ctx, doc); err != nil {
		return ballot.Receipt{}, err
	}
	r, err := p.Signer.Call(ctx, SignerRequest{ProposalID: id, Name: name, Doc: doc, Sig: sig, Rows: rows})
	if err != nil {
		p.log().Warn("publish: the anchor signer failed; retried later", "proposal_id", id, "name", name, "err", err.Error())
		return ballot.Receipt{}, err
	}
	if !bytes.Equal(r.AnchorKey, p.AnchorKey) {
		p.log().Error("the anchor signer answered under another anchor key than the one listed", "alarm", "anchor_key_changed",
			"proposal_id", id, "name", name)
		return ballot.Receipt{}, errors.New("publish: the anchor signer's key is not the listed anchor key")
	}
	switch r.Status {
	case http.StatusCreated, http.StatusOK:
		if len(r.Bundle) == 0 {
			return ballot.Receipt{}, fmt.Errorf("publish: the anchor signer answered %d without a bundle", r.Status)
		}
		if err := p.keep(ctx, doc, r.Bundle); err != nil {
			return ballot.Receipt{}, err
		}
		if notBefore > 0 {
			p.checkPublishedResults(id, doc, r.Bundle, notBefore)
		}
		if !r.IndexUpdated {
			p.log().Warn("publish: the site's index is not updated", "proposal_id", id, "name", name)
		}
		return ballot.Receipt{Bundle: r.Bundle, IndexStale: !r.IndexUpdated}, nil
	}
	if r.Status >= 500 || r.Status == http.StatusTooManyRequests {
		return ballot.Receipt{}, fmt.Errorf("publish: votes.vettid.org answered %d %s (through the anchor signer)", r.Status, r.Code)
	}
	return ballot.Receipt{}, &ErrRefused{Status: r.Status, Code: r.Code}
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
