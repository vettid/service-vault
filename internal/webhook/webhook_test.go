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

func TestDeliverSignedAndRetried(t *testing.T) {
	var calls atomic.Int32
	var ids []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		id := r.Header.Get(webhook.HeaderEventID)
		ids = append(ids, id)
		if err := webhook.Verify(secret, r.Header.Get(webhook.HeaderSignature), id, body, time.Now(), webhook.DefaultTolerance); err != nil {
			t.Errorf("Verify: %v", err)
		}
		var e Event
		if err := json.Unmarshal(body, &e); err != nil || e.ID != id || e.Type != "signin.approved" {
			t.Errorf("body %s: %v", body, err)
		}
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	e, err := NewEvent("signin.approved", "c1", map[string]string{"request_id": "r1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{URL: srv.URL, Secret: secret, Backoff: time.Millisecond}
	if err := d.Deliver(context.Background(), e); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if calls.Load() != 3 || ids[0] != ids[2] {
		t.Fatalf("calls %d ids %v", calls.Load(), ids)
	}
}

func TestDeliverRejectedNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	e, _ := NewEvent("connection.added", "c1", nil, time.Now())
	d := &Dispatcher{URL: srv.URL, Secret: secret, Backoff: time.Millisecond}
	if err := d.Deliver(context.Background(), e); !errors.Is(err, ErrRejected) || calls.Load() != 1 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
}

func TestDeliverGivesUp(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	e, _ := NewEvent("connection.added", "c1", nil, time.Now())
	d := &Dispatcher{URL: srv.URL, Secret: secret, Backoff: time.Millisecond, MaxAttempts: 4}
	if err := d.Deliver(context.Background(), e); err == nil || calls.Load() != 4 {
		t.Fatalf("err %v calls %d", err, calls.Load())
	}
}

func TestDeliverShortSecret(t *testing.T) {
	e, _ := NewEvent("connection.added", "c1", nil, time.Now())
	d := &Dispatcher{URL: "http://127.0.0.1:1", Secret: secret[:8]}
	if err := d.Deliver(context.Background(), e); !errors.Is(err, webhook.ErrSecret) {
		t.Fatalf("err %v", err)
	}
}
