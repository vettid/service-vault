package publish

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The extension files are read to the first 404; a document without its
// signature is an error; the index count is read from the index.
func TestSiteReader(t *testing.T) {
	files := map[string]string{
		"/v1/p/X/extension-1.json":          `{"n":1}`,
		"/v1/p/X/extension-1.sig":           "sig",
		"/v1/p/X/extension-1.sigstore.json": `{}`,
		"/v1/p/X/extension-2.json":          `{"n":2}`,
		"/v1/index.json":                    `[{"proposal_id":"Y","extended":0},{"proposal_id":"X","extended":1}]`,
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path]; ok {
			w.Write([]byte(b))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	p := &Publisher{URL: srv.URL, Client: srv.Client()}
	ctx := context.Background()
	if x, err := p.Extension(ctx, "X", 1); err != nil || x == nil || string(x.Sig) != "sig" {
		t.Fatalf("extension 1: %v %v", x, err)
	}
	if _, err := p.Extension(ctx, "X", 2); err == nil {
		t.Fatal("a document without its signature is an extension")
	}
	if x, err := p.Extension(ctx, "X", 3); err != nil || x != nil {
		t.Fatalf("extension 3: %v %v", x, err)
	}
	if n, found, err := p.ExtensionCount(ctx, "X"); err != nil || !found || n != 1 {
		t.Fatalf("index: %d %v %v", n, found, err)
	}
}
