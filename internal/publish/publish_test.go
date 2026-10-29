package publish

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
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
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows")); err != nil || string(got[len(got)-1].Rows) != "rows" {
		t.Fatalf("results: %v", err)
	}
	status = 422
	var ref *ErrRefused
	if _, err := p.PublishResults(ctx, id, []byte("res"), []byte("s"), []byte("rows")); !errors.As(err, &ref) || ref.Code != "too_late" {
		t.Fatalf("a refusal: %v", err)
	}
}
