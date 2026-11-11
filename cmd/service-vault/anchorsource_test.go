package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/publish"
)

// fakeSigner is the anchor signer: a probe answer and a call count.
type fakeSigner struct {
	spki     []byte
	probeErr error
	calls    atomic.Int32
}

func (f *fakeSigner) Probe(context.Context) ([]byte, error) { return f.spki, f.probeErr }

func (f *fakeSigner) Call(context.Context, publish.SignerRequest) (publish.SignerResult, error) {
	f.calls.Add(1)
	return publish.SignerResult{Status: 201, AnchorKey: f.spki}, nil
}

// fakeSSM answers the marker: present, absent, or an error.
type fakeSSM struct {
	present bool
	err     error
	asked   []string
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	f.asked = append(f.asked, *in.Name)
	switch {
	case f.err != nil:
		return nil, f.err
	case f.present:
		return &ssm.GetParameterOutput{}, nil
	}
	return nil, &ssmtypes.ParameterNotFound{}
}

// countingBlobs records every read and write of the anchor-key blob.
type countingBlobs struct {
	memBlobs
	anchorReads, anchorCreates int
}

func (b *countingBlobs) Get(ctx context.Context, name string) ([]byte, error) {
	if name == keystore.AnchorKeyName {
		b.anchorReads++
	}
	return b.memBlobs.Get(ctx, name)
}

func (b *countingBlobs) Create(ctx context.Context, name string, data []byte) error {
	if name == keystore.AnchorKeyName {
		b.anchorCreates++
	}
	return b.memBlobs.Create(ctx, name, data)
}

func newCountingBlobs() *countingBlobs {
	return &countingBlobs{memBlobs: memBlobs{m: map[string][]byte{}}}
}

// p256SPKI is a fresh P-256 key's SPKI.
func p256SPKI(t *testing.T) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// sealAnchorKey stores an existing anchor key, the way a deployment from
// before the signer has one, without NewAnchorKey (devsigner only).
func sealAnchorKey(t *testing.T, b *countingBlobs) *ecdsa.PrivateKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pt, _ := json.Marshal(keystore.AnchorKey{PKCS8: der})
	s, err := keystore.Seal(context.Background(), plainKMS{}, "k", keystore.AnchorKeyName, pt)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(s)
	b.m[keystore.AnchorKeyName] = raw // stored before the test: not counted
	return k
}

func anchorCfg(signer string) *Config {
	return &Config{Sigstore: "staging", KMSKeyID: "k", AnchorSigner: signer, AnchorMovedParam: "/sv/staging/anchor_key_moved"}
}

const testSignerARN = "arn:aws:lambda:us-east-1:123456789012:function:vettid-anchor-signer-staging"

// With the signer, the key comes from its probe; the blob and the marker
// are never read, and nothing here can sign.
func TestSetupAnchorWithSigner(t *testing.T) {
	ctx := context.Background()
	sg := &fakeSigner{spki: p256SPKI(t)}
	sc, blobs := &fakeSSM{}, newCountingBlobs()
	sealAnchorKey(t, blobs) // an old key, still there: never read
	as, err := setupAnchor(ctx, anchorCfg(testSignerARN), sg, sc, plainKMS{}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(as.spki, sg.spki) || as.signer == nil || as.anc == nil {
		t.Fatalf("%+v", as)
	}
	if blobs.anchorReads != 0 || blobs.anchorCreates != 0 || len(sc.asked) != 0 {
		t.Fatalf("blob reads %d, creates %d, marker reads %v", blobs.anchorReads, blobs.anchorCreates, sc.asked)
	}
	if _, err := as.anc.Anchor(ctx, []byte(`{}`)); err == nil {
		t.Fatal("the service's own anchorer signed with the signer configured")
	}
}

// A signer that doesn't answer the probe turns publishing off, without
// falling back to the blob; one that answers with another kind of key
// stops the daemon.
func TestSetupAnchorSignerFails(t *testing.T) {
	ctx := context.Background()
	blobs := newCountingBlobs()
	sealAnchorKey(t, blobs)
	_, err := setupAnchor(ctx, anchorCfg(testSignerARN), &fakeSigner{probeErr: errors.New("timeout")}, &fakeSSM{}, plainKMS{}, blobs)
	if !errors.Is(err, errSignerUnavailable) {
		t.Fatalf("unreachable signer: %v", err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	edSPKI, _ := x509.MarshalPKIXPublicKey(pub)
	if _, err := setupAnchor(ctx, anchorCfg(testSignerARN), &fakeSigner{spki: edSPKI}, &fakeSSM{}, plainKMS{}, blobs); err == nil || errors.Is(err, errSignerUnavailable) {
		t.Fatalf("an Ed25519 anchor key: %v", err)
	}
	if blobs.anchorReads != 0 {
		t.Fatal("the blob was read as a fallback")
	}
}

// Without the signer: the marker decides first. Present, or unreadable,
// the daemon refuses to start and never reads the blob.
func TestSetupAnchorMarker(t *testing.T) {
	ctx := context.Background()
	for name, sc := range map[string]*fakeSSM{"present": {present: true}, "unreadable": {err: errors.New("AccessDenied")}} {
		blobs := newCountingBlobs()
		sealAnchorKey(t, blobs)
		_, err := setupAnchor(ctx, anchorCfg(""), nil, sc, plainKMS{}, blobs)
		if err == nil || errors.Is(err, errSignerUnavailable) {
			t.Fatalf("%s: started: %v", name, err)
		}
		if name == "present" && !errors.Is(err, errAnchorKeyMoved) {
			t.Fatalf("present: %v", err)
		}
		if blobs.anchorReads != 0 || len(sc.asked) != 1 || sc.asked[0] != "/sv/staging/anchor_key_moved" {
			t.Fatalf("%s: blob reads %d, marker reads %v", name, blobs.anchorReads, sc.asked)
		}
	}
	if _, err := anchorMoved(ctx, &fakeSSM{}, ""); err == nil {
		t.Fatal("no marker name was taken as not moved")
	}
}

// Without the signer or the marker, an existing key is opened, as before
// the signer.
func TestSetupAnchorExistingKey(t *testing.T) {
	ctx := context.Background()
	blobs := newCountingBlobs()
	k := sealAnchorKey(t, blobs)
	as, err := setupAnchor(ctx, anchorCfg(""), nil, &fakeSSM{}, plainKMS{}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if !bytes.Equal(as.spki, want) || as.signer != nil || blobs.anchorCreates != 0 {
		t.Fatalf("%+v creates %d", as, blobs.anchorCreates)
	}
}

// A release build makes no anchor key: with none stored, the start
// fails and nothing is written.
func TestSetupAnchorNoKeyRelease(t *testing.T) {
	if devSigner {
		t.Skip("devsigner build")
	}
	blobs := newCountingBlobs()
	if _, err := setupAnchor(context.Background(), anchorCfg(""), nil, &fakeSSM{}, plainKMS{}, blobs); err == nil || !strings.Contains(err.Error(), "SV_ANCHOR_SIGNER") {
		t.Fatalf("started without a key: %v", err)
	}
	if blobs.anchorCreates != 0 {
		t.Fatal("a release build created an anchor key")
	}
}

// The release binary has no way to make an anchor key: built without the
// devsigner tag, it doesn't contain keystore.NewAnchorKey at all.
func TestReleaseBinaryHasNoAnchorKeyMaker(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the daemon")
	}
	if devSigner {
		t.Skip("devsigner build")
	}
	bin := filepath.Join(t.TempDir(), "service-vault")
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	nm, err := exec.Command("go", "tool", "nm", bin).Output()
	if err != nil {
		t.Fatalf("nm: %v", err)
	}
	if !bytes.Contains(nm, []byte("main.setupAnchor")) {
		t.Fatal("nm shows no main.setupAnchor: the check would prove nothing")
	}
	for _, sym := range []string{"keystore.NewAnchorKey"} {
		if bytes.Contains(nm, []byte(sym)) {
			t.Fatalf("the release binary contains %s", sym)
		}
	}
}
