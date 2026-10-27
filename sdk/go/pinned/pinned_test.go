package pinned

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func pinOf(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	return "sha256/" + base64.RawURLEncoding.EncodeToString(sum[:])
}

func tls13(h http.Handler) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	return srv
}

// The pinned key is accepted, any other refused, and a redirect is not
// followed (it would carry the API key elsewhere).
func TestClient(t *testing.T) {
	var redirected bool
	srv := tls13(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/away" {
			redirected = true
		}
		if r.URL.Path == "/r" {
			http.Redirect(w, r, "/away", http.StatusFound)
		}
	}))
	defer srv.Close()

	c, err := Client(pinOf(srv), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(srv.URL + "/r")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound || redirected {
		t.Fatalf("redirect: %d, followed %v", res.StatusCode, redirected)
	}
	wrong, err := Client("sha256/"+base64.RawURLEncoding.EncodeToString(make([]byte, 32)), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Get(srv.URL); !errors.Is(err, ErrPin) {
		t.Fatalf("another key: %v", err)
	}
	if _, err := Client("sha256/short", time.Second); err == nil {
		t.Fatal("a malformed pin")
	}
}
