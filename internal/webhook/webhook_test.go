package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/service-vault/sdk/go/webhook"
)

var secret = bytes.Repeat([]byte{0x42}, 32)

func TestDeliverSigned(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		id := r.Header.Get(webhook.HeaderEventID)
		if err := webhook.Verify(secret, r.Header.Get(webhook.HeaderSignature), id, body, time.Now(), webhook.DefaultTolerance); err != nil {
			t.Errorf("Verify: %v", err)
		}
		var e Event
		if err := json.Unmarshal(body, &e); err != nil || e.ID != id || e.Type != "signin.approved" {
			t.Errorf("body %s: %v", body, err)
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	e, err := NewEvent("signin.approved", "c1", map[string]string{"request_id": "r1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{URL: srv.URL, Secret: secret}
	var se *StatusError
	if err := d.Deliver(context.Background(), e); !errors.As(err, &se) || se.Code != http.StatusServiceUnavailable {
		t.Fatalf("first: %v", err)
	}
	if err := d.Deliver(context.Background(), e); err != nil || calls.Load() != 2 {
		t.Fatalf("second: %v, %d calls", err, calls.Load())
	}
}

func TestDeliverRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	e, _ := NewEvent("connection.added", "c1", nil, time.Now())
	d := &Dispatcher{URL: srv.URL, Secret: secret}
	if err := d.Deliver(context.Background(), e); !errors.Is(err, ErrRejected) {
		t.Fatalf("err %v", err)
	}
}

func TestDeliverShortSecret(t *testing.T) {
	e, _ := NewEvent("connection.added", "c1", nil, time.Now())
	d := &Dispatcher{URL: "http://127.0.0.1:1", Secret: secret[:8]}
	if err := d.Deliver(context.Background(), e); !errors.Is(err, webhook.ErrSecret) {
		t.Fatalf("err %v", err)
	}
}
