package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/store"
	"github.com/vettid/service-vault/internal/tlsid"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func goodEnv() map[string]string {
	return map[string]string{
		"SV_RELAY_URL": "https://relay.vettid.org/", "SV_TABLE": "t", "SV_KMS_KEY_ID": "arn:k", "SV_LISTEN": ":8080",
		"SV_WEBHOOK_URL": "https://member.example/webhooks", "SV_SERVICE_NAME": "VettID Member Service",
		"SV_TLS_NAME": "service-vault.prod.vettid.internal", "SV_TLS_PIN_PARAM": "/p",
		"SV_API_KEY_HASHES": strings.Repeat("ab", 32) + "," + strings.Repeat("cd", 32),
		"SV_WEBHOOK_SECRET": strings.Repeat("s", 40),
	}
}

func TestConfigFromEnv(t *testing.T) {
	c, err := configFromEnv(env(goodEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if c.RelayURL != "https://relay.vettid.org" || len(c.APIKeyHashes) != 2 ||
		c.Profile.FirstName != "VettID" || c.Profile.LastName != "Member Service" ||
		len(c.EmailLimits) != 2 || c.EmailLimits[0].String() != "5/15m" || c.EmailLimits[1].String() != "20/24h" ||
		len(c.SourceLimits) != 1 || c.SourceLimits[0].String() != "20/15m" ||
		len(c.ApprovalLimits) != 2 || c.ApprovalLimits[0].String() != "2/1h" || c.ApprovalLimits[1].String() != "4/24h" {
		t.Fatalf("%+v", c)
	}
	e := goodEnv()
	e["SV_SIGNIN_LIMITS_EMAIL"], e["SV_SIGNIN_LIMITS_SOURCE"] = "3/10m", "none"
	e["SV_APPROVAL_LIMITS"] = "1/24h"
	if c, err := configFromEnv(env(e)); err != nil || len(c.EmailLimits) != 1 || c.EmailLimits[0].Max != 3 || c.SourceLimits != nil ||
		len(c.ApprovalLimits) != 1 || c.ApprovalLimits[0].String() != "1/24h" {
		t.Fatalf("limits %+v %v", c, err)
	}
	if c.AdminBootstrapEmail != "" || c.AdminThreshold != 1 || c.ApprovalTTL != 24*time.Hour || c.RecordKeyVersion != 1 {
		t.Fatalf("defaults %+v", c)
	}
	e = goodEnv()
	e["SV_BALLOTS_TABLE"] = "t-ballots"
	if _, err := configFromEnv(env(e)); err == nil {
		t.Fatal("ballots without SV_SIGSTORE")
	}
	e["SV_SIGSTORE"] = "staging"
	if _, err := configFromEnv(env(e)); err == nil || !strings.Contains(err.Error(), "SV_ANCHOR_MOVED_PARAM") {
		t.Fatalf("ballots without the anchor marker's name or the signer: %v", err)
	}
	e["SV_ANCHOR_MOVED_PARAM"] = "/vettid/service-vault/staging/anchor_key_moved"
	if c, err := configFromEnv(env(e)); err != nil || c.Sigstore != "staging" || c.BallotsTable != "t-ballots" ||
		c.AnchorMovedParam != "/vettid/service-vault/staging/anchor_key_moved" || c.AnchorSigner != "" {
		t.Fatalf("ballots %+v %v", c, err)
	}
	e["SV_VOTES_URL"] = "https://votes.vettid.org/"
	if c, err := configFromEnv(env(e)); err != nil || c.VotesURL != "https://votes.vettid.org" {
		t.Fatalf("votes URL %+v %v", c, err)
	}
	// The signer: an unqualified function ARN, with the votes URL; then the
	// marker's name isn't needed.
	signer := "arn:aws:lambda:us-east-1:123456789012:function:vettid-anchor-signer-staging"
	for _, bad := range []string{"arn:aws:lambda:us-east-1:123456789012:function:f:live", "vettid-anchor-signer", "arn:aws:iam::123456789012:role/x"} {
		e["SV_ANCHOR_SIGNER"] = bad
		if _, err := configFromEnv(env(e)); err == nil {
			t.Fatalf("SV_ANCHOR_SIGNER %q", bad)
		}
	}
	e["SV_ANCHOR_SIGNER"] = signer
	delete(e, "SV_ANCHOR_MOVED_PARAM")
	if _, err := configFromEnv(env(e)); err == nil || !strings.Contains(err.Error(), "SV_ANCHOR_KEY") {
		t.Fatalf("a signer without the pinned key: %v", err)
	}
	for _, bad := range []string{"not base64!", base64.StdEncoding.EncodeToString([]byte("not a key"))} {
		e["SV_ANCHOR_KEY"] = bad
		if _, err := configFromEnv(env(e)); err == nil {
			t.Fatalf("SV_ANCHOR_KEY %q", bad)
		}
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	e["SV_ANCHOR_KEY"] = base64.StdEncoding.EncodeToString(spki)
	if c, err := configFromEnv(env(e)); err != nil || c.AnchorSigner != signer || !bytes.Equal(c.AnchorKey, spki) {
		t.Fatalf("signer %+v %v", c, err)
	}
	delete(e, "SV_VOTES_URL")
	if _, err := configFromEnv(env(e)); err == nil {
		t.Fatal("a signer without the votes URL")
	}
	e["SV_VOTES_URL"] = "https://votes.vettid.org"
	delete(e, "SV_ANCHOR_SIGNER")
	e["SV_ANCHOR_MOVED_PARAM"] = "/p/moved"
	e["SV_VOTES_URL"] = "http://votes.vettid.org"
	if _, err := configFromEnv(env(e)); err == nil {
		t.Fatal("an http votes URL")
	}
	delete(e, "SV_VOTES_URL")
	e["SV_SIGSTORE"] = "public"
	if _, err := configFromEnv(env(e)); err == nil {
		t.Fatal("an unknown Sigstore instance")
	}
	e = goodEnv()
	e["SV_RECORD_KEY_VERSION"] = "3"
	if c, err := configFromEnv(env(e)); err != nil || c.RecordKeyVersion != 3 {
		t.Fatalf("record key version %+v %v", c, err)
	}
	e = goodEnv()
	e["SV_ADMIN_BOOTSTRAP_EMAIL"], e["SV_ADMIN_THRESHOLD"], e["SV_APPROVAL_TTL"] = " Admin@Example.org ", "2", "48h"
	if c, err := configFromEnv(env(e)); err != nil || c.AdminBootstrapEmail != "admin@example.org" || c.AdminThreshold != 2 ||
		c.ApprovalTTL != 48*time.Hour {
		t.Fatalf("approvals %+v %v", c, err)
	}
	// SV_CHANNEL: production by default; on staging the approval TTL
	// defaults to and is at most 1 hour.
	e = goodEnv()
	if c, err := configFromEnv(env(e)); err != nil || c.Channel != ChannelProduction || c.ApprovalTTL != 24*time.Hour {
		t.Fatalf("channel default %+v %v", c, err)
	}
	e["SV_CHANNEL"] = "production"
	if c, err := configFromEnv(env(e)); err != nil || c.Channel != ChannelProduction {
		t.Fatalf("production %+v %v", c, err)
	}
	e["SV_CHANNEL"], e["SV_APPROVAL_TTL"] = "staging", "36h"
	if _, err := configFromEnv(env(e)); err == nil {
		t.Error("a staging approval TTL over 1h accepted")
	}
	e["SV_CHANNEL"], e["SV_APPROVAL_TTL"] = "staging", "1h"
	if c, err := configFromEnv(env(e)); err != nil || c.Channel != ChannelStaging || c.ApprovalTTL != time.Hour {
		t.Fatalf("staging 1h %+v %v", c, err)
	}
	e["SV_APPROVAL_TTL"] = "1h1m"
	if _, err := configFromEnv(env(e)); err == nil {
		t.Error("a staging approval TTL of 1h1m accepted")
	}
	delete(e, "SV_APPROVAL_TTL")
	if c, err := configFromEnv(env(e)); err != nil || c.ApprovalTTL != time.Hour {
		t.Fatalf("staging default %+v %v", c, err)
	}
	for _, v := range []string{"Staging", "prod", " x "} {
		e["SV_CHANNEL"] = v
		if _, err := configFromEnv(env(e)); err == nil {
			t.Errorf("SV_CHANNEL=%q accepted", v)
		}
	}
	e = goodEnv()
	if c, err := configFromEnv(env(e)); err != nil || c.LongChallenges {
		t.Fatalf("long challenges default %+v %v", c, err)
	}
	e["SV_LONG_APPROVAL_CHALLENGES"] = "true"
	if c, err := configFromEnv(env(e)); err != nil || !c.LongChallenges {
		t.Fatalf("long challenges on %+v %v", c, err)
	}
	e["SV_LONG_APPROVAL_CHALLENGES"] = "false"
	if c, err := configFromEnv(env(e)); err != nil || c.LongChallenges {
		t.Fatalf("long challenges off %+v %v", c, err)
	}
	for _, v := range []string{"yes", "1", "True"} {
		e["SV_LONG_APPROVAL_CHALLENGES"] = v
		if _, err := configFromEnv(env(e)); err == nil {
			t.Errorf("SV_LONG_APPROVAL_CHALLENGES=%q accepted", v)
		}
	}
	e = goodEnv()
	if c, err := configFromEnv(env(e)); err != nil || c.TestSignIns {
		t.Fatalf("test sign-ins default %+v %v", c, err)
	}
	for v, want := range map[string]bool{"true": true, "false": false, " true ": true} {
		e["SV_TEST_SIGNINS"] = v
		if c, err := configFromEnv(env(e)); err != nil || c.TestSignIns != want {
			t.Fatalf("SV_TEST_SIGNINS=%q: %+v %v", v, c, err)
		}
	}
	e = goodEnv()
	e["SV_SERVICE_NAME"] = "VettID " + strings.Repeat("x", 250)
	if _, err := configFromEnv(env(e)); err == nil {
		t.Error("a service name too long for an approval context accepted")
	}
	for k, v := range map[string]string{
		"SV_ADMIN_BOOTSTRAP_EMAIL": "nope", "SV_ADMIN_THRESHOLD": "0", "SV_APPROVAL_TTL": "1m",
		"SV_TABLE": "", "SV_WEBHOOK_URL": "http://member.example/", "SV_WEBHOOK_SECRET": "short",
		"SV_API_KEY_HASHES": "zz", "SV_SERVICE_NAME": "VettID",
		"SV_SIGNIN_LIMITS_EMAIL": "5", "SV_SIGNIN_LIMITS_SOURCE": "0/1m", "SV_APPROVAL_LIMITS": "x/1h",
		"SV_RECORD_KEY_VERSION": "0", "SV_TEST_SIGNINS": "yes",
	} {
		e := goodEnv()
		e[k] = v
		if _, err := configFromEnv(env(e)); err == nil {
			t.Errorf("%s=%q accepted", k, v)
		}
	}
}

func TestHealthcheck(t *testing.T) {
	key, err := tlsid.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := tlsid.Certificate(key, []string{"localhost"}, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var down atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || down.Load() {
			w.WriteHeader(503)
		}
	}))
	srv.TLS = tlsid.ServerConfig(cert)
	srv.StartTLS()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if err := healthcheck(":" + port); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	down.Store(true)
	if err := healthcheck(":" + port); err == nil {
		t.Fatal("unhealthy server passed")
	}
	srv.Close()
	if err := healthcheck(":" + port); err == nil {
		t.Fatal("closed server passed")
	}
}

// The daemon stops once no heartbeat write has succeeded for
// heartbeatStopAfter, counting from the last good one, and each write has
// heartbeatWriteTimeout to finish.
func TestHeartbeatStopsInTime(t *testing.T) {
	start := time.Unix(1_000_000, 0)
	tick := make(chan time.Time)
	fail := errors.New("throttled")
	results := []error{nil, fail, nil, fail, fail, fail, fail}
	var writes int
	write := func(ctx context.Context, _ time.Time) error {
		dl, ok := ctx.Deadline()
		if !ok || time.Until(dl) > heartbeatWriteTimeout {
			t.Errorf("write %d: deadline %v, %v", writes, dl, ok)
		}
		err := results[writes]
		writes++
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- heartbeat(context.Background(), write, start, tick, slog.New(slog.DiscardHandler))
	}()
	// Ticks 30 s apart: ok at 30 s, a failure at 60 s, ok at 90 s, then
	// failures. The stop comes at the first failure heartbeatStopAfter
	// (60 s) after the last good write: at 150 s.
	var last time.Time
	for i := 1; ; i++ {
		at := start.Add(time.Duration(i) * store.HeartbeatInterval)
		select {
		case tick <- at:
			last = at
			continue
		case err := <-done:
			if err == nil || !errors.Is(err, fail) {
				t.Fatalf("err %v", err)
			}
			got := last.Sub(start)
			if got != 150*time.Second {
				t.Fatalf("stopped at %v, want 150s", got)
			}
			if since := got - 90*time.Second; since >= store.HeartbeatStale {
				t.Fatalf("stopped %v after the last good write", since)
			}
			return
		}
	}
}

func TestHeartbeatEndsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan error, 1)
	go func() {
		done <- heartbeat(ctx, func(context.Context, time.Time) error { return nil }, time.Now(), tick, slog.New(slog.DiscardHandler))
	}()
	tick <- time.Now()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The first heartbeat: bounded like the others, and the stop clock starts
// at the time it carries.
func TestFirstHeartbeat(t *testing.T) {
	at := time.Unix(1_000_000, 0)
	var stamped time.Time
	start, err := firstHeartbeat(context.Background(), func(ctx context.Context, now time.Time) error {
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > heartbeatWriteTimeout {
			t.Errorf("deadline %v, %v", dl, ok)
		}
		stamped = now
		return nil
	}, at)
	if err != nil || !start.Equal(at) || !stamped.Equal(at) {
		t.Fatalf("start %v, stamped %v, err %v", start, stamped, err)
	}
	if _, err := firstHeartbeat(context.Background(), func(context.Context, time.Time) error { return errors.New("down") }, at); err == nil {
		t.Fatal("a failed first write")
	}
}

type fakeMarkers struct{ rebuild bool }

func (f *fakeMarkers) MarkBallotsRebuild(context.Context, time.Time) error {
	f.rebuild = true
	return nil
}

func (f *fakeMarkers) BallotsRebuild(context.Context) (bool, error) { return f.rebuild, nil }

// A restore while ballots are off keeps the rebuild for the first start
// with ballots on, though the restore marker goes with the reconnects.
func TestBallotsRebuildAfterRestoreWithBallotsOff(t *testing.T) {
	ctx, now := context.Background(), time.Now()
	m := &fakeMarkers{}
	if r, err := ballotsRebuild(ctx, m, true, false, now); err != nil || r {
		t.Fatalf("ballots off: rebuild %v, %v", r, err)
	}
	if !m.rebuild {
		t.Fatal("the rebuild wasn't kept for later")
	}
	// The next start: restore marker gone, ballots on again.
	if r, err := ballotsRebuild(ctx, m, false, true, now); err != nil || !r {
		t.Fatalf("ballots back on: rebuild %v, %v", r, err)
	}
	if r, _ := ballotsRebuild(ctx, &fakeMarkers{}, false, true, now); r {
		t.Fatal("a rebuild without a restore")
	}
	if r, _ := ballotsRebuild(ctx, &fakeMarkers{}, true, true, now); !r {
		t.Fatal("no rebuild right after a restore")
	}
}

// A test-only setting that is on is named at start; off, nothing is said.
func TestWarnTestMode(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	warnTestMode(log, &Config{})
	if buf.Len() != 0 {
		t.Fatalf("off: %q", buf.String())
	}
	warnTestMode(log, &Config{TestSignIns: true})
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, `msg="unsigned sign-ins enabled: test deployments only"`) ||
		strings.Count(out, "=") != 3 { // time, level, msg: no other attributes
		t.Fatalf("on: %q", out)
	}
}
