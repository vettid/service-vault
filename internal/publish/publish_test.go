package publish

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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
	p := &Publisher{URL: srv.URL + "/", Anchor: a, Client: srv.Client(),
		Timestamp: func(json.RawMessage, []byte) (int64, error) { return 1, nil }} // results stamped at the close
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
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows"), 1); err != nil || string(got[len(got)-1].Rows) != "rows" {
		t.Fatalf("results: %v", err)
	}
	status = 422
	var ref *ErrRefused
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows"), 1); !errors.As(err, &ref) || ref.Code != "too_late" {
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
// bundle with its own anchor signature, or sigs[i] when given.
type stampAnchor struct {
	times []int64
	sigs  [][]byte
	n     int
}

func (a *stampAnchor) Anchor(_ context.Context, _ []byte) (json.RawMessage, error) {
	t := a.times[a.n]
	sig := []byte{byte(a.n + 1)}
	if a.n < len(a.sigs) && a.sigs[a.n] != nil {
		sig = a.sigs[a.n]
	}
	a.n++
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
// force (BALLOT-PROTOCOL §8.3 step 2). An earlier bundle is never uploaded
// and never kept; anchors are rationed: at most one per call, and none
// until the authority's time, judged from the early stamp, can have
// reached the close.
func TestPublishResultsStamp(t *testing.T) {
	const id, closes = "01JBQZ0000000000000000000A", int64(1_800_000_000)
	ctx := context.Background()
	stamp := func(b json.RawMessage) int64 { v, _ := ballottest.Time(b, nil); return v }
	res := []byte("res")
	stored := func(store peer.Store) json.RawMessage {
		b, _ := (&Publisher{Records: store}).StoredBundle(ctx, res)
		return b
	}
	type env struct {
		up    *[]json.RawMessage
		store *peer.MemStore
		clock time.Time
		p     *Publisher
	}
	newEnv := func(t *testing.T, a Anchorer) *env {
		srv, up := stampSite(t)
		e := &env{up: up, store: peer.NewMemStore(), clock: time.Unix(closes+60, 0)}
		e.p = &Publisher{URL: srv.URL, Anchor: a, Client: srv.Client(), Records: e.store, Timestamp: ballottest.Time, Now: func() time.Time { return e.clock }}
		return e
	}
	publish := func(e *env) (ballot.Receipt, error) {
		return e.p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes)
	}

	t.Run("at the close", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes}}
		e := newEnv(t, a)
		rc, err := publish(e)
		if err != nil || a.n != 1 || len(*e.up) != 1 || stamp(rc.Bundle) != closes {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	t.Run("early, then on time", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 5, closes + 1}}
		e := newEnv(t, a)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || len(*e.up) != 0 || stored(e.store) != nil {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
		// The authority is 5 s short of the close: no anchor until then,
		// also after a restart.
		e.clock = e.clock.Add(4 * time.Second)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 {
			t.Fatalf("anchored too soon: %d anchors, %v", a.n, err)
		}
		restarted := &Publisher{URL: e.p.URL, Anchor: a, Client: e.p.Client, Records: e.store, Timestamp: ballottest.Time, Now: e.p.Now}
		if _, err := restarted.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), closes); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 {
			t.Fatalf("anchored too soon after a restart: %d anchors, %v", a.n, err)
		}
		e.clock = e.clock.Add(time.Second)
		rc, err := publish(e)
		if err != nil || a.n != 2 || len(*e.up) != 1 || stamp((*e.up)[0]) != closes+1 || stamp(rc.Bundle) != closes+1 {
			t.Fatalf("on time: %d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
		if kept, _ := e.p.StoredBundle(ctx, res); stamp(kept) != closes+1 || stamp(stored(e.store)) != closes+1 {
			t.Fatal("the bundle kept is not the one uploaded")
		}
	})

	// A bundle kept by an earlier run is checked, not handed back: dropped,
	// and, as the authority is short of the close, not anchored again yet.
	t.Run("early bundle kept before a restart", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 5, closes}}
		e := newEnv(t, a)
		if _, err := (&Publisher{Anchor: a, Records: e.store}).bundle(ctx, res); err != nil {
			t.Fatal(err)
		}
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || len(*e.up) != 0 || stored(e.store) != nil {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
		e.clock = e.clock.Add(5 * time.Second)
		if rc, err := publish(e); err != nil || a.n != 2 || len(*e.up) != 1 || stamp(rc.Bundle) != closes {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	// While the wait holds, a bundle kept meanwhile (another process's,
	// on time) is still checked and uploaded: the wait only stops anchors.
	t.Run("kept bundle during the wait", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 30, closes + 2}}
		e := newEnv(t, a)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 {
			t.Fatal(err)
		}
		if _, err := (&Publisher{Anchor: a, Records: e.store}).bundle(ctx, res); err != nil { // on time
			t.Fatal(err)
		}
		rc, err := publish(e)
		if err != nil || a.n != 2 || len(*e.up) != 1 || stamp(rc.Bundle) != closes+2 {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	// A crash between the wait's save and the drop leaves a kept bundle
	// whose signature is already dropped: judged as dropped (stamped_early,
	// nothing kept), not as an error.
	t.Run("crash between the wait and the drop", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 5, closes}}
		e := newEnv(t, a)
		if _, err := (&Publisher{Anchor: a, Records: e.store}).bundle(ctx, res); err != nil { // signature {1}
			t.Fatal(err)
		}
		if err := e.p.saveWait(ctx, res, &stampWait{TSA: closes - 5, Seen: e.clock.Unix(), Dropped: [][]byte{{1}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || len(*e.up) != 0 || stored(e.store) != nil {
			t.Fatalf("%d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
		e.clock = e.clock.Add(5 * time.Second)
		if _, err := publish(e); err != nil || a.n != 2 || len(*e.up) != 1 {
			t.Fatalf("then: %d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	// With AuthorityTime, a fresh probe (no log entry) decides when to
	// anchor again after an early stamp, so a clock corrected meanwhile
	// can't starve the results; the wait goes once they are published.
	t.Run("a fresh probe after an early stamp", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 3600, closes}}
		e := newEnv(t, a)
		authority, probes := closes-10, 0
		e.p.AuthorityTime = func(context.Context) (int64, error) { probes++; return authority, nil }
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || probes != 0 {
			t.Fatalf("%d anchors, %d probes, %v", a.n, probes, err)
		}
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 || probes != 1 {
			t.Fatalf("the probe says early: %d anchors, %d probes, %v", a.n, probes, err)
		}
		authority = closes // the estimate (an hour off) would still wait
		if _, err := publish(e); err != nil || a.n != 2 || probes != 2 || len(*e.up) != 1 {
			t.Fatalf("the probe says on time: %d anchors, %d probes, %d uploads, %v", a.n, probes, len(*e.up), err)
		}
		if w, _ := e.p.loadWait(ctx, res); w != nil {
			t.Fatalf("the wait was kept after publishing: %+v", w)
		}
	})

	// Without a probe, the estimate's wait is void if the clock went back,
	// and never lasts over ballot.ProbeMaxWait.
	t.Run("the estimate's limits", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes - 3600, closes - 3600, closes}}
		e := newEnv(t, a)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 1 {
			t.Fatal(err)
		}
		e.clock = e.clock.Add(-time.Second) // went back
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 2 {
			t.Fatalf("after the clock went back: %d anchors, %v", a.n, err)
		}
		e.clock = e.clock.Add(ballot.ProbeMaxWait - time.Second)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) || a.n != 2 {
			t.Fatalf("within the cap: %d anchors, %v", a.n, err)
		}
		e.clock = e.clock.Add(time.Second)
		if _, err := publish(e); err != nil || a.n != 3 {
			t.Fatalf("at the cap: %d anchors, %v", a.n, err)
		}
	})

	// The identical upload again (a stale site index) sends the bundle
	// uploaded first; one that is early or doesn't verify is kept, alarmed,
	// and not uploaded (the site holds it).
	t.Run("results again", func(t *testing.T) {
		e := newEnv(t, &stampAnchor{})
		onTime, _ := (&stampAnchor{times: []int64{closes}}).Anchor(ctx, res)
		if _, err := e.p.RepublishResults(ctx, id, res, []byte("s"), []byte("rows"), onTime, closes); err != nil || len(*e.up) != 1 || string((*e.up)[0]) != string(onTime) {
			t.Fatalf("%d uploads, %v", len(*e.up), err)
		}
		early, _ := (&stampAnchor{times: []int64{closes - 1}}).Anchor(ctx, res)
		key := sha256.Sum256(res)
		if err := e.store.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: hex.EncodeToString(key[:]), Data: early}}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.p.RepublishResults(ctx, id, res, []byte("s"), []byte("rows"), early, closes); !errors.Is(err, ballot.ErrStampedEarly) || len(*e.up) != 1 || stored(e.store) == nil {
			t.Fatalf("an early bundle again: %d uploads, kept %v, %v", len(*e.up), stored(e.store) != nil, err)
		}
		if _, err := e.p.RepublishResults(ctx, id, res, []byte("s"), []byte("rows"), onTime, 0); err == nil {
			t.Fatal("results again without a close")
		}
	})

	// An anchor signature dropped once is never taken again, across calls.
	t.Run("same anchor signature again", func(t *testing.T) {
		one := []byte{9}
		a := &stampAnchor{times: []int64{closes - 1, closes, closes}, sigs: [][]byte{one, one}}
		e := newEnv(t, a)
		if _, err := publish(e); !errors.Is(err, ballot.ErrStampedEarly) {
			t.Fatal(err)
		}
		e.clock = e.clock.Add(time.Second)
		if _, err := publish(e); err == nil || errors.Is(err, ballot.ErrStampedEarly) || len(*e.up) != 0 || stored(e.store) != nil {
			t.Fatalf("published or kept under a dropped anchor signature: %v", err)
		}
		if _, err := publish(e); err != nil || a.n != 3 || len(*e.up) != 1 {
			t.Fatalf("next call: %d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	// A bundle that doesn't verify is never uploaded. One kept from before
	// stays kept (the site may hold it); one this call anchored is dropped.
	t.Run("unverifiable bundle", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes, closes}}
		e := newEnv(t, a)
		e.p.Timestamp = func(json.RawMessage, []byte) (int64, error) { return 0, errors.New("untrusted") }
		if _, err := publish(e); err == nil || errors.Is(err, ballot.ErrStampedEarly) || len(*e.up) != 0 || stored(e.store) != nil {
			t.Fatalf("anchored now: %d uploads, %v", len(*e.up), err)
		}
		if _, err := (&Publisher{Anchor: a, Records: e.store}).bundle(ctx, res); err != nil {
			t.Fatal(err)
		}
		if _, err := publish(e); err == nil || len(*e.up) != 0 || stored(e.store) == nil || a.n != 2 {
			t.Fatalf("kept: %d anchors, %d uploads, %v", a.n, len(*e.up), err)
		}
	})

	t.Run("no timestamp check", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes}}
		e := newEnv(t, a)
		e.p.Timestamp = nil
		if _, err := publish(e); err == nil || len(*e.up) != 0 {
			t.Fatalf("published without a timestamp check: %v", err)
		}
	})

	t.Run("results without a close", func(t *testing.T) {
		a := &stampAnchor{times: []int64{closes}}
		e := newEnv(t, a)
		if _, err := e.p.PublishResults(ctx, id, res, []byte("s"), []byte("rows"), 0); err == nil || a.n != 0 || len(*e.up) != 0 {
			t.Fatalf("results published unchecked: %v", err)
		}
	})

	// Both alarms are logged as alarms.
	t.Run("alarms", func(t *testing.T) {
		var logs bytes.Buffer
		a := &stampAnchor{times: []int64{closes - 1, closes}}
		e := newEnv(t, a)
		e.p.Log = slog.New(slog.NewJSONHandler(&logs, nil))
		_, _ = publish(e)
		e.clock = e.clock.Add(time.Second)
		e.p.Timestamp = func(json.RawMessage, []byte) (int64, error) { return 0, errors.New("untrusted") }
		_, _ = publish(e)
		for _, name := range []string{"results_stamped_early", "results_bundle_unverified"} {
			if !strings.Contains(logs.String(), `"alarm":"`+name+`"`) {
				t.Errorf("no %s alarm in %s", name, logs.String())
			}
		}
	})
}

// forget drops only the bundle it was given: one another process kept
// meanwhile stays.
func TestForgetIsConditional(t *testing.T) {
	ctx := context.Background()
	store := peer.NewMemStore()
	doc := []byte("res")
	key := sha256.Sum256(doc)
	theirs := json.RawMessage(`{"theirs":1}`)
	if err := store.Apply(ctx, []peer.Change{{Kind: KindBundle, ID: hex.EncodeToString(key[:]), Data: theirs}}); err != nil {
		t.Fatal(err)
	}
	p := &Publisher{Records: store}
	if err := p.forget(ctx, doc, json.RawMessage(`{"mine":1}`)); err != nil {
		t.Fatal(err)
	}
	if b, _ := p.StoredBundle(ctx, doc); string(b) != string(theirs) {
		t.Fatalf("another's bundle was dropped: %s", b)
	}
	if err := p.forget(ctx, doc, theirs); err != nil {
		t.Fatal(err)
	}
	if b, _ := p.StoredBundle(ctx, doc); b != nil {
		t.Fatalf("not dropped: %s", b)
	}
}
