package main

import (
	"context"
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
		len(c.SourceLimits) != 1 || c.SourceLimits[0].String() != "20/15m" {
		t.Fatalf("%+v", c)
	}
	e := goodEnv()
	e["SV_SIGNIN_LIMITS_EMAIL"], e["SV_SIGNIN_LIMITS_SOURCE"] = "3/10m", "none"
	if c, err := configFromEnv(env(e)); err != nil || len(c.EmailLimits) != 1 || c.EmailLimits[0].Max != 3 || c.SourceLimits != nil {
		t.Fatalf("limits %+v %v", c, err)
	}
	if c.AdminBootstrapEmail != "" || c.AdminThreshold != 1 || c.ApprovalTTL != 24*time.Hour || c.RecordKeyVersion != 1 {
		t.Fatalf("defaults %+v", c)
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
	e = goodEnv()
	e["SV_SERVICE_NAME"] = "VettID " + strings.Repeat("x", 250)
	if _, err := configFromEnv(env(e)); err == nil {
		t.Error("a service name too long for an approval context accepted")
	}
	for k, v := range map[string]string{
		"SV_ADMIN_BOOTSTRAP_EMAIL": "nope", "SV_ADMIN_THRESHOLD": "0", "SV_APPROVAL_TTL": "1m",
		"SV_TABLE": "", "SV_WEBHOOK_URL": "http://member.example/", "SV_WEBHOOK_SECRET": "short",
		"SV_API_KEY_HASHES": "zz", "SV_SERVICE_NAME": "VettID",
		"SV_SIGNIN_LIMITS_EMAIL": "5", "SV_SIGNIN_LIMITS_SOURCE": "0/1m",
		"SV_RECORD_KEY_VERSION": "0",
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
