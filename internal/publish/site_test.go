package publish

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// siteFiles is what the votes site's write() stores for an extension
// (vettid/votes site.go: <base>.json.sig and <base>.json.sigstore.json,
// beside <base>.json); a reader built on other names would find nothing.
func siteFiles(id string, n string) map[string]string {
	base := "/v1/p/" + id + "/extension-" + n
	return map[string]string{
		base + ".json":               `{"n":` + n + `}`,
		base + ".json.sig":           "sig",
		base + ".json.sigstore.json": `{}`,
	}
}

// The extension files are read under the site's names, to the first 404;
// a document without its signature is an error, not a missing extension.
func TestSiteReader(t *testing.T) {
	files := siteFiles("X", "1")
	files["/v1/p/X/extension-2.json"] = `{"n":2}` // no signature or bundle
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
	if x, err := p.Extension(ctx, "X", 1); err != nil || x == nil || string(x.Sig) != "sig" || string(x.Doc) != `{"n":1}` {
		t.Fatalf("extension 1: %v %v", x, err)
	}
	if _, err := p.Extension(ctx, "X", 2); err == nil {
		t.Fatal("a document without its signature is an extension")
	}
	if x, err := p.Extension(ctx, "X", 3); err != nil || x != nil {
		t.Fatalf("extension 3: %v %v", x, err)
	}
}

// index_updated false is stale; true or absent (an older site) is not.
func TestIndexUpdated(t *testing.T) {
	for body, stale := range map[string]bool{`{"published":"x","index_updated":false}`: true, `{"published":"x","index_updated":true}`: false, `{"published":"x"}`: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(201)
			w.Write([]byte(body))
		}))
		p := &Publisher{URL: srv.URL, Anchor: &fakeAnchor{}, Client: srv.Client()}
		rc, err := p.PublishExtension(context.Background(), "X", 1, []byte("d"), []byte("s"))
		srv.Close()
		if err != nil || rc.IndexStale != stale {
			t.Errorf("%s: stale %v, %v", body, rc.IndexStale, err)
		}
		if b, _ := p.StoredBundle(context.Background(), []byte("d")); b == nil {
			t.Error("the bundle is not kept")
		}
		if b, _ := p.StoredBundle(context.Background(), []byte("other")); b != nil {
			t.Error("a bundle for a document never anchored")
		}
	}
}
