// Package webhook delivers the service vault's events to the application:
// a signed POST per event (sdk/go/webhook). Events wait in an Outbox in
// the store and are delivered from its own loop, retried with backoff
// until the application answers 2xx or rejects them.
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

// Dispatcher posts events to one endpoint, one attempt per Deliver; the
// Outbox retries.
type Dispatcher struct {
	URL    string
	Secret []byte // at least webhook.MinSecretLen bytes
	Client *http.Client
	Now    func() time.Time
}

// ErrRejected is returned when the endpoint answers 4xx (other than 408
// and 429): the event is not retried.
var ErrRejected = errors.New("webhook: rejected by endpoint")

// StatusError is an answer worth retrying: 408, 429 or 5xx.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("webhook: status %d", e.Code) }

// defaultClient follows no redirect (a 3xx is an answer, not a place to
// send a signed event) and ignores proxy settings in the environment.
var defaultClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Timeout: 15 * time.Second, Transport: t,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

// Deliver posts e once. The body and event id are the same on every
// attempt; each is signed afresh. It returns nil on 2xx, ErrRejected
// (wrapped) on a 4xx other than 408 and 429, and another error when the
// event should be tried again.
func (d *Dispatcher) Deliver(ctx context.Context, e *Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	return d.post(ctx, e.ID, body, now())
}

func (d *Dispatcher) post(ctx context.Context, id string, body []byte, now time.Time) error {
	sig, err := webhook.Sign(d.Secret, now, id, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.HeaderEventID, id)
	req.Header.Set(webhook.HeaderSignature, sig)
	c := d.Client
	if c == nil {
		c = defaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return &StatusError{Code: resp.StatusCode}
	default:
		return fmt.Errorf("%w: status %d", ErrRejected, resp.StatusCode)
	}
}
