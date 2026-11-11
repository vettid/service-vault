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
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/vettid/service-vault/internal/keystore"
	"github.com/vettid/service-vault/internal/publish"
)

// fakeSigner is the anchor signer: a probe answer and a call count.
type fakeSigner struct {
	spki       []byte
	probeErr   error
	failProbes int32 // probes that fail with probeErr before one answers (0: every one does)
	calls      atomic.Int32
	probes     atomic.Int32
}

func (f *fakeSigner) Probe(context.Context) ([]byte, error) {
	n := f.probes.Add(1)
	if f.probeErr != nil && (f.failProbes == 0 || n <= f.failProbes) {
		return nil, f.probeErr
	}
	return f.spki, nil
}

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

// With the signer, the key is the pinned one: the signer isn't called at
// the start, the blob and the marker are never read, and nothing here
// can sign.
func TestSetupAnchorWithSigner(t *testing.T) {
	ctx := context.Background()
	pinned := p256SPKI(t)
	sg := &fakeSigner{spki: p256SPKI(t)} // even a signer under another key
	sc, blobs := &fakeSSM{}, newCountingBlobs()
	sealAnchorKey(t, blobs) // an old key, still there: never read
	cfg := anchorCfg(testSignerARN)
	cfg.AnchorKey = pinned
	as, err := setupAnchor(ctx, cfg, sg, sc, plainKMS{}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(as.spki, pinned) || as.signer == nil || as.anc == nil {
		t.Fatalf("%+v", as)
	}
	if sg.probes.Load() != 0 || sg.calls.Load() != 0 {
		t.Fatal("the signer was called at the start")
	}
	if blobs.anchorReads != 0 || blobs.anchorCreates != 0 || len(sc.asked) != 0 {
		t.Fatalf("blob reads %d, creates %d, marker reads %v", blobs.anchorReads, blobs.anchorCreates, sc.asked)
	}
	if _, err := as.anc.Anchor(ctx, []byte(`{}`)); err == nil {
		t.Fatal("the service's own anchorer signed with the signer configured")
	}
	// A pinned key that isn't P-256 stops the start.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	cfg.AnchorKey, _ = x509.MarshalPKIXPublicKey(pub)
	if _, err := setupAnchor(ctx, cfg, sg, sc, plainKMS{}, blobs); err == nil {
		t.Fatal("an Ed25519 pin")
	}
}

// The background probe: an unreachable signer alarms and is retried with
// backoff; one under another key than the pinned one alarms; the pinned
// key ends the watch quietly.
func TestWatchSigner(t *testing.T) {
	first, max := probeFirst, probeMax
	probeFirst, probeMax = time.Millisecond, 4*time.Millisecond
	defer func() { probeFirst, probeMax = first, max }()
	pinned := p256SPKI(t)
	run := func(sg *fakeSigner) string {
		var buf bytes.Buffer
		watchSigner(context.Background(), sg, pinned, slog.New(slog.NewJSONHandler(&buf, nil)))
		return buf.String()
	}
	sg := &fakeSigner{spki: pinned, probeErr: errors.New("timeout"), failProbes: 3}
	if log := run(sg); strings.Count(log, "anchor_signer_unavailable") != 3 || strings.Contains(log, "anchor_key_changed") || sg.probes.Load() != 4 {
		t.Fatalf("probes %d, log %s", sg.probes.Load(), log)
	}
	if log := run(&fakeSigner{spki: p256SPKI(t)}); !strings.Contains(log, "anchor_key_changed") {
		t.Fatalf("another key: %s", log)
	}
	if log := run(&fakeSigner{spki: pinned}); strings.Contains(log, `"alarm"`) {
		t.Fatalf("the pinned key: %s", log)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	watchSigner(ctx, &fakeSigner{probeErr: errors.New("x"), failProbes: 1 << 30}, pinned, slog.Default()) // returns
	// A probe that fails because the service is shutting down raises no
	// alarm.
	var buf bytes.Buffer
	ctx2, cancel2 := context.WithCancel(context.Background())
	sd := &shutdownProber{cancel: cancel2}
	watchSigner(ctx2, sd, pinned, slog.New(slog.NewJSONHandler(&buf, nil)))
	if strings.Contains(buf.String(), "alarm") {
		t.Fatalf("an alarm at shutdown: %s", buf.String())
	}
	// The next probe logged is never past the cap.
	probeFirst, probeMax = time.Millisecond, 2*time.Millisecond
	buf.Reset()
	watchSigner(context.Background(), &fakeSigner{spki: pinned, probeErr: errors.New("t"), failProbes: 4}, pinned, slog.New(slog.NewJSONHandler(&buf, nil)))
	if !strings.Contains(buf.String(), `"next_probe":"2ms"`) || strings.Contains(buf.String(), `"next_probe":"4ms"`) {
		t.Fatalf("next_probe past the cap: %s", buf.String())
	}
}

// shutdownProber fails its probe because the service is stopping.
type shutdownProber struct{ cancel context.CancelFunc }

func (s *shutdownProber) Probe(context.Context) ([]byte, error) {
	s.cancel()
	return nil, context.Canceled
}

func (s *shutdownProber) Call(context.Context, publish.SignerRequest) (publish.SignerResult, error) {
	return publish.SignerResult{}, nil
}

// Without the signer: the marker decides first. Present, or unreadable,
// the daemon refuses to start and never reads the blob.
func TestSetupAnchorMarker(t *testing.T) {
	ctx := context.Background()
	for name, sc := range map[string]*fakeSSM{"present": {present: true}, "unreadable": {err: errors.New("AccessDenied")}} {
		blobs := newCountingBlobs()
		sealAnchorKey(t, blobs)
		_, err := setupAnchor(ctx, anchorCfg(""), nil, sc, plainKMS{}, blobs)
		if err == nil {
			t.Fatalf("%s: started", name)
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
// the signer; with a pin, it must be the pinned key.
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
	cfg := anchorCfg("")
	cfg.AnchorKey = want
	if _, err := setupAnchor(ctx, cfg, nil, &fakeSSM{}, plainKMS{}, blobs); err != nil {
		t.Fatalf("the pinned key: %v", err)
	}
	cfg.AnchorKey = p256SPKI(t)
	if _, err := setupAnchor(ctx, cfg, nil, &fakeSSM{}, plainKMS{}, blobs); !errors.Is(err, errAnchorKeyNotPinned) {
		t.Fatalf("another key than the pinned one: %v", err)
	}
}

// A release build makes no anchor key: with none stored, the start
// fails and nothing is written. This is the guard; the nm test below only
// adds that the maker isn't linked in.
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

// The anchor-key item is loaded in one place only (setupAnchor), and only
// with createAnchorKey, which refuses in a release build.
func TestOneAnchorKeyLoadSite(t *testing.T) {
	var sites []string
	err := filepath.WalkDir("../..", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git" || d.Name() == "cdk") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "keystore.AnchorKeyName") && strings.Contains(line, "LoadOrCreate") {
				sites = append(sites, path+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || !strings.Contains(sites[0], "anchorsource.go") || !strings.Contains(sites[0], "createAnchorKey)") {
		t.Fatalf("anchor-key load sites: %q", sites)
	}
}

// The release binary doesn't link keystore.NewAnchorKey (built only with
// the devsigner tag, so this can hardly fail; TestSetupAnchorNoKeyRelease
// and TestOneAnchorKeyLoadSite are the guards).
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
