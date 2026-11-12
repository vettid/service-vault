package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/publish"
)

// Where the anchor key is used (key protection, phase 1, GC #7406 §7 step
// 1 as amended for #7648):
//
//   - With SV_ANCHOR_SIGNER, the AnchorSigner in the signer's own account
//     signs and publishes. The key is pinned (SV_ANCHOR_KEY, its SPKI, set
//     by the owner): only the pinned key is certified and listed, every
//     answer must carry it, and every bundle must verify under it. The
//     signer is probed in the background, never on the start's path. This
//     service never reads the anchor-key blob, and holds no KMS grant on
//     the key.
//   - Without it, the anchor-key blob is opened here, the way it was
//     before the signer, until the SSM marker says the key moved. Once the
//     marker exists (or can't be read), the daemon refuses to start
//     without the signer. Release builds never create an anchor key
//     (createAnchorKey); only a devsigner build does.

// anchorSetup is how documents are anchored.
type anchorSetup struct {
	spki []byte // the anchor key's SubjectPublicKeyInfo
	// anc anchors here (no signer), or only asks the timestamp authority
	// for the time (with the signer: it can't sign).
	anc    *anchor.Anchorer
	signer publish.Signer // nil: anc anchors
}

// ssmGetter is the part of the SSM client the marker check uses.
type ssmGetter interface {
	GetParameter(ctx context.Context, in *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// keyProber is the signer as the setup uses it: the key, then calls.
type keyProber interface {
	publish.Signer
	Probe(ctx context.Context) ([]byte, error)
}

// errAnchorKeyMoved: the marker says the anchor key lives in the signer.
var errAnchorKeyMoved = errors.New("the anchor key has moved to the signer (SSM marker): SV_ANCHOR_SIGNER is required")

// errAnchorKeyNotPinned: the key opened here isn't the pinned one.
var errAnchorKeyNotPinned = errors.New("the stored anchor key is not the pinned one (SV_ANCHOR_KEY)")

// setupAnchor decides how documents are anchored. An error stops the
// daemon; the signer is not called here (watchSigner probes it).
func setupAnchor(ctx context.Context, cfg *Config, signer keyProber, sc ssmGetter, kc keystore.KMS, blobs keystore.Blobs) (*anchorSetup, error) {
	if cfg.AnchorSigner != "" {
		pub, err := p256(cfg.AnchorKey)
		if err != nil {
			return nil, fmt.Errorf("SV_ANCHOR_KEY: %w", err)
		}
		anc, err := anchor.NewSigner(cfg.Sigstore, timeOnly{pub})
		if err != nil {
			return nil, err
		}
		return &anchorSetup{spki: cfg.AnchorKey, anc: anc, signer: signer}, nil
	}
	moved, err := anchorMoved(ctx, sc, cfg.AnchorMovedParam)
	if err != nil {
		return nil, fmt.Errorf("the anchor key marker can't be read, so the key is taken as moved: %w", err)
	}
	if moved {
		return nil, errAnchorKeyMoved
	}
	ak, err := keystore.LoadOrCreate(ctx, kc, cfg.KMSKeyID, blobs, keystore.AnchorKeyName, createAnchorKey)
	if err != nil {
		return nil, fmt.Errorf("anchor key: %w", err)
	}
	priv, err := ak.Private()
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(cfg.AnchorKey) > 0 && !bytes.Equal(spki, cfg.AnchorKey) {
		return nil, errAnchorKeyNotPinned
	}
	anc, err := anchor.New(cfg.Sigstore, priv)
	if err != nil {
		return nil, err
	}
	return &anchorSetup{spki: spki, anc: anc}, nil
}

// Probing the signer (watchSigner): its first try right after the start,
// then with backoff until it answers.
var (
	probeFirst = 5 * time.Second
	probeMax   = 15 * time.Minute
)

// watchSigner probes the signer in the background until it answers once:
// an unreachable signer, or one under another key than the pinned one,
// is an alarm. Publishing is configured all the while: a call to a signer
// that is down fails and is retried, and every answer is checked against
// the pinned key anyway. It never falls back to a key held here.
func watchSigner(ctx context.Context, p keyProber, pinned []byte, log *slog.Logger) {
	wait := probeFirst
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		spki, err := p.Probe(ctx)
		switch {
		case ctx.Err() != nil:
			return // shutting down: not the signer's failure
		case err != nil:
			wait = min(2*wait, probeMax)
			log.Error("the anchor signer doesn't answer: votes can't be published until it does", "alarm", "anchor_signer_unavailable",
				"err", err.Error(), "next_probe", wait.String())
			continue
		case !bytes.Equal(spki, pinned):
			log.Error("the anchor signer's key is not the pinned anchor key: nothing it answers is used", "alarm", "anchor_key_changed")
		default:
			log.Info("the anchor signer answers under the pinned key")
		}
		return
	}
}

// anchorMoved reports whether the marker parameter exists. Its value is
// not read: it exists or it doesn't. Only "not found" is "not moved".
func anchorMoved(ctx context.Context, sc ssmGetter, name string) (bool, error) {
	if name == "" {
		return false, errors.New("no SV_ANCHOR_MOVED_PARAM")
	}
	_, err := sc.GetParameter(ctx, &ssm.GetParameterInput{Name: aws.String(name)})
	var nf *ssmtypes.ParameterNotFound
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &nf):
		return false, nil
	}
	return false, err
}

// p256 parses an SPKI as a P-256 public key.
func p256(spki []byte) (*ecdsa.PublicKey, error) {
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

// timeOnly is an anchor.DigestSigner that can't sign: with the signer, the
// service's own Anchorer only asks the timestamp authority for the time
// (anchor.AuthorityTime).
type timeOnly struct{ pub *ecdsa.PublicKey }

func (t timeOnly) Public() *ecdsa.PublicKey { return t.pub }

func (timeOnly) SignDigest(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("anchor: this service holds no anchor key (the signer signs)")
}
