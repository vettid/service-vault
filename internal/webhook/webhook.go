// Package webhook delivers the service vault's events to the application:
// a signed POST per event (sdk/go/webhook), retried with backoff until the
// application answers 2xx or the attempts run out.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vettid/service-vault/sdk/go/webhook"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Event is one webhook: a type, the connection it concerns and a
// type-specific payload.
type Event struct {
	ID           string          `json:"id"` // ULID; also the VettID-Event-Id header
	Type         string          `json:"type"`
	ConnectionID string          `json:"connection_id,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	Data         json.RawMessage `json:"data,omitempty"`
}

// NewEvent makes an event with a fresh id.
func NewEvent(typ, connectionID string, data any, now time.Time) (*Event, error) {
	id, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	e := &Event{ID: id, Type: typ, ConnectionID: connectionID, CreatedAt: now.UTC().Truncate(time.Second)}
	if data != nil {
		if e.Data, err = json.Marshal(data); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Dispatcher posts events to one endpoint.
type Dispatcher struct {
	URL         string
	Secret      []byte // at least webhook.MinSecretLen bytes
	Client      *http.Client
	MaxAttempts int           // default 8
	Backoff     time.Duration // first retry delay, doubled each time; default 1 s, capped at 5 min
	Now         func() time.Time
}

// ErrRejected is returned when the endpoint answers 4xx (other than 408
// and 429): the event is not retried.
var ErrRejected = errors.New("webhook: rejected by endpoint")

// Deliver posts e, retrying network errors, 408, 429 and 5xx. The body and
// event id stay the same across attempts; each attempt is signed afresh.
func (d *Dispatcher) Deliver(ctx context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	attempts, delay := d.MaxAttempts, d.Backoff
	if attempts <= 0 {
		attempts = 8
	}
	if delay <= 0 {
		delay = time.Second
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	var last error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
			delay = min(2*delay, 5*time.Minute)
		}
		retry, err := d.post(ctx, e.ID, body, now())
		if err == nil {
			return nil
		}
		if !retry {
			return err
		}
		last = err
	}
	return fmt.Errorf("webhook: %d attempts: %w", attempts, last)
}

func (d *Dispatcher) post(ctx context.Context, id string, body []byte, now time.Time) (retry bool, err error) {
	sig, err := webhook.Sign(d.Secret, now, id, body)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.HeaderEventID, id)
	req.Header.Set(webhook.HeaderSignature, sig)
	c := d.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return ctx.Err() == nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return true, fmt.Errorf("webhook: status %d", resp.StatusCode)
	default:
		return false, fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
}
