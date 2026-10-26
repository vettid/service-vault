package tlsid

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/sdk/go/pinned"
)

func server(t *testing.T, keyDER []byte) (*httptest.Server, string) {
	t.Helper()
	cert, pin, err := Certificate(keyDER, []string{"service-vault.test.vettid.internal"}, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	srv.TLS = ServerConfig(cert)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, pin
}

func TestPinnedClient(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	srv, pin := server(t, key)
	if !strings.HasPrefix(pin, "sha256/") {
		t.Fatalf("pin %q", pin)
	}

	// The pin depends on the key only: a certificate made again from the
	// same key has the same pin.
	_, pin2, _ := Certificate(key, nil, time.Now().Add(time.Hour), time.Hour)
	if pin2 != pin {
		t.Fatal("pin changed with the certificate")
	}

	c, err := pinned.Client(pin, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("pinned GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}

	other, _ := GenerateKey()
	_, otherPin, _ := Certificate(other, nil, time.Now(), time.Hour)
	bad, _ := pinned.Client(otherPin, 5*time.Second)
	if _, err := bad.Get(srv.URL); err == nil || !errors.Is(err, pinned.ErrPin) && !strings.Contains(err.Error(), pinned.ErrPin.Error()) {
		t.Fatalf("other pin: %v", err)
	}

	// The default client, which trusts only CAs, refuses it too.
	if _, err := http.Get(srv.URL); err == nil {
		t.Fatal("unpinned client accepted the self-signed server")
	}
}

func TestParsePin(t *testing.T) {
	for _, p := range []string{"", "sha256/", "sha1/abc", "sha256/!!", "sha256/" + strings.Repeat("A", 42)} {
		if _, err := pinned.ParsePin(p); err == nil {
			t.Errorf("pin %q accepted", p)
		}
	}
}

func TestCertificateRejectsOtherKeys(t *testing.T) {
	if _, _, err := Certificate([]byte("not a key"), nil, time.Now(), time.Hour); err == nil {
		t.Fatal("garbage key accepted")
	}
}
