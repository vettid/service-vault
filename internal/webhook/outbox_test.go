package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// endpoint answers each event id with its entry in fail (nil: 2xx).
type endpoint struct {
	mu   sync.Mutex
	fail map[string]error
	got  []string
}

func (p *endpoint) Deliver(_ context.Context, e *Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.fail[e.ID]; err != nil {
		return err
	}
	p.got = append(p.got, e.ID)
	return nil
}

func (p *endpoint) delivered() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.got...)
}

func (p *endpoint) set(id string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail[id] = err
}

func event(id string, at time.Time) *Event {
	return &Event{ID: id, Type: "connection.added", ConnectionID: "c1", CreatedAt: at}
}

// Events go out in id order; one the endpoint cannot take stops the
// rest and stays first; a rejected one is dropped; adding an event again
// (a redelivered peer event) queues it once.
func TestOutboxOrder(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	ep := &endpoint{fail: map[string]error{"02": &StatusError{Code: 503}, "03": fmt.Errorf("%w: status 400", ErrRejected)}}
	o := &Outbox{Store: peer.NewMemStore(), Kind: "hook", Sender: ep, Now: func() time.Time { return now }}
	for _, id := range []string{"04", "02", "01", "03", "01"} {
		if err := o.Add(ctx, id, event(id, now)); err != nil {
			t.Fatal(err)
		}
	}
	var se *StatusError
	if err := o.Flush(ctx); !errors.As(err, &se) {
		t.Fatalf("flush: %v", err)
	}
	if got := ep.delivered(); fmt.Sprint(got) != "[01]" {
		t.Fatalf("delivered %v", got)
	}
	ep.set("02", nil)
	if err := o.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := ep.delivered(); fmt.Sprint(got) != "[01 02 04]" {
		t.Fatalf("delivered %v", got)
	}
	if recs, _ := o.Store.Load(ctx, "hook"); len(recs) != 0 {
		t.Fatalf("%d left", len(recs))
	}
}

// An event that still fails at MaxAge is dropped, so the events behind
// it go out.
func TestOutboxMaxAge(t *testing.T) {
	ctx := context.Background()
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	now := start
	ep := &endpoint{fail: map[string]error{"01": &StatusError{Code: http.StatusInternalServerError}}}
	o := &Outbox{Store: peer.NewMemStore(), Kind: "hook", Sender: ep, Now: func() time.Time { return now }}
	_ = o.Add(ctx, "01", event("01", start))
	_ = o.Add(ctx, "02", event("02", start.Add(time.Hour)))
	now = start.Add(DefaultMaxAge - time.Second)
	if err := o.Flush(ctx); err == nil || len(ep.delivered()) != 0 {
		t.Fatalf("before MaxAge: %v %v", err, ep.delivered())
	}
	now = start.Add(DefaultMaxAge)
	if err := o.Flush(ctx); err != nil || fmt.Sprint(ep.delivered()) != "[02]" {
		t.Fatalf("at MaxAge: %v %v", err, ep.delivered())
	}
}

// Run delivers what is added without waiting for its poll, and after a
// failure tries again once the backoff has passed.
func TestOutboxRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ep := &endpoint{fail: map[string]error{"01": &StatusError{Code: 503}}}
	o := &Outbox{Store: peer.NewMemStore(), Kind: "hook", Sender: ep, Backoff: 10 * time.Millisecond, Poll: time.Hour}
	done := make(chan struct{})
	go func() { o.Run(ctx); close(done) }()
	if err := o.Add(ctx, "01", event("01", time.Now())); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	ep.set("01", nil)
	deadline := time.Now().Add(5 * time.Second)
	for len(ep.delivered()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if fmt.Sprint(ep.delivered()) != "[01]" {
		t.Fatalf("delivered %v", ep.delivered())
	}
	cancel()
	<-done
}
