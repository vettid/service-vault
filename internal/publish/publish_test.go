package publish

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vettid/service-vault/anchor"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/ballot/ballottest"
	"github.com/vettid/service-vault/internal/peer"
)

type fakeAnchor struct{ n int }

func (a *fakeAnchor) Anchor(_ context.Context, doc []byte) (json.RawMessage, error) {
	a.n++
	return json.RawMessage(`{"n":` + string(rune('0'+a.n)) + `}`), nil
}

type upload struct {
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle"`
	Rows   []byte          `json:"rows"`
}

func TestPublish(t *testing.T) {
	var got []upload
	var paths []string
	status := 201
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var u upload
		_ = json.Unmarshal(b, &u)
		got, paths = append(got, u), append(paths, r.URL.Path)
		w.WriteHeader(status)
		if status >= 400 {
			_, _ = w.Write([]byte(`{"error":"too_late"}`))
		}
	}))
	defer srv.Close()
	a := &fakeAnchor{}
	p := &Publisher{URL: srv.URL + "/", Anchor: a, Client: srv.Client()}
	ctx := context.Background()
	const id = "01JBQZ0000000000000000000A"

	b1, err := p.PublishProposal(ctx, id, []byte("doc"), []byte("sig"))
	if err != nil || string(b1) != `{"n":1}` {
		t.Fatalf("proposal: %s %v", b1, err)
	}
	if paths[0] != "/api/v1/p/"+id+"/proposal" || string(got[0].Doc) != "doc" || string(got[0].Sig) != "sig" || got[0].Rows != nil {
		t.Fatalf("upload %s %+v", paths[0], got[0])
	}
	// A retry of the same document sends the same bundle: the site keeps
	// only the first anchor of a document's path.
	status = 503
	if _, err := p.PublishProposal(ctx, id, []byte("doc2"), []byte("sig")); err == nil {
		t.Fatal("a 503 was taken for success")
	}
	status = 200
	b2, err := p.PublishProposal(ctx, id, []byte("doc2"), []byte("sig"))
	if err != nil || a.n != 2 || string(b2) != `{"n":2}` {
		t.Fatalf("retry anchored again (%d anchors), %v", a.n, err)
	}
	if _, err := p.PublishExtension(ctx, id, 3, []byte("ext"), []byte("s")); err != nil || paths[len(paths)-1] != "/api/v1/p/"+id+"/extension-3" {
		t.Fatalf("extension: %v %s", err, paths[len(paths)-1])
	}
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows"), 0); err != nil || string(got[len(got)-1].Rows) != "rows" {
		t.Fatalf("results: %v", err)
	}
	status = 422
	var ref *ErrRefused
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows"), 0); !errors.As(err, &ref) || ref.Code != "too_late" {
		t.Fatalf("a refusal: %v", err)
	}
}

// A bundle is kept before its upload, so a retry after a restart sends
// the same one: the site took the document with it, and refuses another.
func TestPublishKeepsBundles(t *testing.T) {
	status := 503
	var bundles []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u upload
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &u)
		bundles = append(bundles, string(u.Bundle))
		w.WriteHeader(status)
	}))
	defer srv.Close()
	store := peer.NewMemStore()
	a := &fakeAnchor{}
	ctx := context.Background()
	const id = "01JBQZ0000000000000000000A"
	p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store}
	if _, err := p.PublishProposal(ctx, id, []byte("doc"), []byte("sig")); err == nil {
		t.Fatal("a 503 was taken for success")
	}
	status = 201
	restarted := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store}
	b, err := restarted.PublishProposal(ctx, id, []byte("doc"), []byte("sig"))
	if err != nil || a.n != 1 || string(b) != `{"n":1}` || bundles[0] != bundles[1] {
		t.Fatalf("after a restart: %d anchors, bundles %v, %v", a.n, bundles, err)
	}
}

// The publisher's client follows no redirect: a 3xx is the site's answer.
func TestPublishNoRedirect(t *testing.T) {
	other := 0
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other++ }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	p := &Publisher{URL: srv.URL, Anchor: &fakeAnchor{}, Client: anchor.Client(5 * time.Second)}
	var ref *ErrRefused
	if _, err := p.PublishProposal(context.Background(), "01JBQZ0000000000000000000A", []byte("d"), []byte("s")); !errors.As(err, &ref) || ref.Status != 307 || other != 0 {
		t.Fatalf("redirect: %v, %d requests elsewhere", err, other)
	}
}

// stampAnchor anchors with the test timestamps in times, in turn, each
// bundle with its own anchor signature (or the same one, with sameSig).
type stampAnchor struct {
	times   []int64
	n       int
	sameSig bool
}

func (a *stampAnchor) Anchor(_ context.Context, _ []byte) (json.RawMessage, error) {
	t := a.times[a.n]
	a.n++
	sig := []byte{byte(a.n)}
	if a.sameSig {
		sig = []byte{1}
	}
	var b map[string]any
	_ = json.Unmarshal(ballottest.Bundle(t, t+1), &b)
	b["messageSignature"] = map[string]any{"signature": sig}
	return json.Marshal(b)
}

// stampSite records the uploads' bundles.
func stampSite(t *testing.T) (*httptest.Server, *[]json.RawMessage) {
	var bundles []json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var u upload
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &u)
		bundles = append(bundles, u.Bundle)
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	return srv, &bundles
}

// Results are uploaded only with a timestamp at or after the close in
// force (BALLOT-PROTOCOL §8.3 step 2): an earlier bundle is never
// uploaded and never kept, and the results are anchored again: at once
// for a bundle kept before, at the next call for one this call anchored.
func TestPublishResultsStamp(t *testing.T) {
	const id, closes = "01JBQZ0000000000000000000A", int64(1_800_000_000)
	ctx := context.Background()
	stamp := func(b json.RawMessage) int64 { v, _ := ballottest.Time(b, nil); return v }
	res := []byte("res")
	stored := func(store peer.Store) json.RawMessage {
		b, _ := (&Publisher{Records: store}).StoredBundle(ctx, res)
		return b
	}

	t.Run("at the close", func(t *testing.T) {
		srv, up := stampSite(t)
		a := &stampAnchor{times: []int64{closes}}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: peer.NewMemStore(), Timestamp: ballottest.Time}
		rc, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes)
		if err != nil || a.n != 1 || len(*up) != 1 || stamp(rc.Bundle) != closes {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*up), err)
		}
	})

	t.Run("early, then on time", func(t *testing.T) {
		srv, up := stampSite(t)
		store := peer.NewMemStore()
		a := &stampAnchor{times: []int64{closes - 1, closes + 3}}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store, Timestamp: ballottest.Time}
		// The call that anchored early doesn't anchor again at once.
		if _, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || len(*up) != 0 {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*up), err)
		}
		if b := stored(store); b != nil {
			t.Fatalf("an early bundle was kept: %s", b)
		}
		rc, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes)
		if err != nil || a.n != 2 || len(*up) != 1 || stamp((*up)[0]) != closes+3 || stamp(rc.Bundle) != closes+3 {
			t.Fatalf("retry: %d anchors, %d uploads, %v", a.n, len(*up), err)
		}
		if kept, _ := p.StoredBundle(ctx, res); stamp(kept) != closes+3 || stamp(stored(store)) != closes+3 {
			t.Fatal("the bundle kept is not the one uploaded")
		}
	})

	t.Run("early twice", func(t *testing.T) {
		srv, up := stampSite(t)
		store := peer.NewMemStore()
		a := &stampAnchor{times: []int64{closes - 120, closes - 100, closes + 1}}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store, Timestamp: ballottest.Time}
		for i := 1; i <= 2; i++ {
			if _, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); !errors.Is(err, ballot.ErrStampedEarly) || len(*up) != 0 || a.n != i || stored(store) != nil {
				t.Fatalf("try %d: %d anchors, %d uploads, %v", i, a.n, len(*up), err)
			}
		}
		rc, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes)
		if err != nil || a.n != 3 || len(*up) != 1 || stamp(rc.Bundle) != closes+1 {
			t.Fatalf("retry: %d anchors, %d uploads, %v", a.n, len(*up), err)
		}
	})

	// A bundle kept by an earlier run is checked too, not handed back: it
	// is dropped and the results anchored again at once.
	t.Run("early bundle kept before a restart", func(t *testing.T) {
		srv, up := stampSite(t)
		store := peer.NewMemStore()
		old := &Publisher{URL: "https://unused.invalid", Anchor: &stampAnchor{times: []int64{closes - 5}}, Records: store}
		if _, err := old.bundle(ctx, res); err != nil {
			t.Fatal(err)
		}
		a := &stampAnchor{times: []int64{0, closes}, n: 1} // a new signature, {2}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store, Timestamp: ballottest.Time}
		rc, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes)
		if err != nil || a.n != 2 || len(*up) != 1 || stamp(rc.Bundle) != closes {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*up), err)
		}
	})

	// Anchoring again must give a new anchor signature: the same one would
	// only fetch the log's existing entry.
	t.Run("same anchor signature again", func(t *testing.T) {
		srv, up := stampSite(t)
		store := peer.NewMemStore()
		old := &Publisher{URL: "https://unused.invalid", Anchor: &stampAnchor{times: []int64{closes - 5}, sameSig: true}, Records: store}
		if _, err := old.bundle(ctx, res); err != nil {
			t.Fatal(err)
		}
		a := &stampAnchor{times: []int64{closes}, sameSig: true}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store, Timestamp: ballottest.Time}
		if _, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); err == nil || len(*up) != 0 {
			t.Fatalf("published under the same anchor signature: %v", err)
		}
	})

	// A kept bundle that doesn't verify is never uploaded, and kept.
	t.Run("unverifiable bundle", func(t *testing.T) {
		srv, up := stampSite(t)
		store := peer.NewMemStore()
		a := &stampAnchor{times: []int64{closes}}
		bad := func(json.RawMessage, []byte) (int64, error) { return 0, errors.New("untrusted") }
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: store, Timestamp: bad}
		if _, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); err == nil || errors.Is(err, ballot.ErrStampedEarly) || len(*up) != 0 || stored(store) == nil {
			t.Fatalf("%d uploads, %v", len(*up), err)
		}
	})

	t.Run("no timestamp check", func(t *testing.T) {
		srv, up := stampSite(t)
		a := &stampAnchor{times: []int64{closes}}
		p := &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client()}
		if _, err := p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); err == nil || len(*up) != 0 {
			t.Fatalf("published without a timestamp check: %v", err)
		}
	})
}
