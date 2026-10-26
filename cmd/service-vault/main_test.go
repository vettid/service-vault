package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	for k, v := range map[string]string{
		"SV_TABLE": "", "SV_WEBHOOK_URL": "http://member.example/", "SV_WEBHOOK_SECRET": "short",
		"SV_API_KEY_HASHES": "zz", "SV_SERVICE_NAME": "VettID",
		"SV_SIGNIN_LIMITS_EMAIL": "5", "SV_SIGNIN_LIMITS_SOURCE": "0/1m",
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
