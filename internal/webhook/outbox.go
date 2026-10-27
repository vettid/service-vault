package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// DefaultMaxAge is how long an event that cannot be delivered is tried.
const DefaultMaxAge = 24 * time.Hour

// Sender delivers one event, once (Dispatcher).
type Sender interface {
	Deliver(ctx context.Context, e *Event) error
}

// Outbox holds webhook events in the store until they are delivered, and
// delivers them in id order from its own loop (Run). The work that
// produces an event records it and goes on, so an endpoint that is slow
// or down delays only the webhooks queued behind it, never connections,
// sign-ins or approvals. Delivery is at least once: an event is deleted
// after the endpoint answers 2xx, or rejects it (4xx other than 408 and
// 429: logged and dropped); anything else is tried again, with backoff,
// until the event is MaxAge old, when it is logged and dropped so that
// the events behind it go out. What a dropped event said, the
// application can still read from the API (an invite's, a sign-in's or
// an approval's status).
type Outbox struct {
	Store  peer.Store
	Kind   string // the record kind; one Outbox per kind
	Sender Sender
	Log    *slog.Logger
	// Backoff is the delay after a failed delivery, doubled after each
	// further failure up to MaxBackoff (defaults 1 s and 5 min).
	Backoff, MaxBackoff time.Duration
	// Poll is how often Run looks for events when nothing wakes it
	// (default 30 s).
	Poll time.Duration
	// MaxAge is how long a failing event is tried, from its CreatedAt
	// (default DefaultMaxAge).
	MaxAge time.Duration
	Now    func() time.Time

	mu   sync.Mutex // serializes Flush
	once sync.Once
	kick chan struct{}
}

// Change is the record that queues e under key, for a caller's own
// Store.Apply. Events go out in key order, so a key sorts as the events
// were made. It fails that Apply with peer.ErrConflict if key is queued
// already.
func (o *Outbox) Change(key string, e *Event) (peer.Change, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return peer.Change{}, err
	}
	return peer.Change{Kind: o.Kind, ID: key, Data: data, IfAbsent: true}, nil
}

// Add queues e under key and wakes Run. An event already queued under
// key (a redelivered event) is left as it is.
func (o *Outbox) Add(ctx context.Context, key string, e *Event) error {
	c, err := o.Change(key, e)
	if err != nil {
		return err
	}
	if err := o.Store.Apply(ctx, []peer.Change{c}); err != nil && !errors.Is(err, peer.ErrConflict) {
		return err
	}
	o.Wake()
	return nil
}

// Wake makes Run flush soon; call it after applying a Change.
func (o *Outbox) Wake() {
	o.init()
	select {
	case o.kick <- struct{}{}:
	default:
	}
}

func (o *Outbox) init() { o.once.Do(func() { o.kick = make(chan struct{}, 1) }) }

func (o *Outbox) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *Outbox) maxAge() time.Duration {
	if o.MaxAge > 0 {
		return o.MaxAge
	}
	return DefaultMaxAge
}

func (o *Outbox) log() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.Default()
}

// Flush delivers the queued events in id order, deleting each once it is
// delivered, rejected or MaxAge old. It stops at the first other event
// that could not be delivered and returns its error; that event is first
// again next time.
func (o *Outbox) Flush(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	recs, err := o.Store.Load(ctx, o.Kind)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		e := &Event{}
		if err := json.Unmarshal(rec.Data, e); err != nil {
			return err
		}
		err := o.Sender.Deliver(ctx, e)
		switch {
		case err == nil:
		case errors.Is(err, ErrRejected):
			// The application's own answer (README "Delivery"), not a fault here.
			o.log().Warn("webhook rejected", "event_id", e.ID, "type", e.Type)
		case ctx.Err() == nil && o.now().Sub(e.CreatedAt) >= o.maxAge():
			o.log().Error("webhook dropped: undeliverable", "event_id", e.ID, "type", e.Type, "err", errCode(ctx, err))
		default:
			o.log().Warn("webhook delivery", "event_id", e.ID, "type", e.Type, "err", errCode(ctx, err))
			return err
		}
		if err := o.Store.Apply(ctx, []peer.Change{{Kind: o.Kind, ID: rec.ID}}); err != nil {
			return err
		}
	}
	return nil
}

// Run flushes until ctx ends: at once, when woken, every Poll, and after
// a failure once its backoff has passed (a wake does not cut that short).
func (o *Outbox) Run(ctx context.Context) {
	o.init()
	first, most, poll := o.Backoff, o.MaxBackoff, o.Poll
	if first <= 0 {
		first = time.Second
	}
	if most <= 0 {
		most = 5 * time.Minute
	}
	if poll <= 0 {
		poll = 30 * time.Second
	}
	var delay time.Duration
	for {
		if err := o.Flush(ctx); err != nil && ctx.Err() == nil {
			delay = min(max(2*delay, first), most)
		} else {
			delay = 0
		}
		wait, kick := poll, o.kick
		if delay > 0 {
			wait, kick = delay, nil
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-kick:
			t.Stop()
		}
	}
}

// errCode names a delivery error for the log, without the endpoint's URL
// or answer.
func errCode(ctx context.Context, err error) string {
	var se *StatusError
	switch {
	case errors.As(err, &se):
		return "status_" + strconv.Itoa(se.Code)
	case ctx.Err() != nil:
		return "canceled"
	case errors.As(err, new(*url.Error)):
		return "unreachable"
	default:
		return "error"
	}
}
