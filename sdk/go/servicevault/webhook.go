package servicevault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/service-vault/sdk/go/webhook"
)

// Webhook event types.
const (
	TypeConnectionPending  = "connection.pending"
	TypeConnectionAdded    = "connection.added"
	TypeConnectionDeclined = "connection.declined"
	TypeConnectionExpired  = "connection.expired"
	TypeConnectionRemoved  = "connection.removed"
	TypeSignInApproved     = "signin.approved"
	TypeSignInDenied       = "signin.denied"
	TypeSignInExpired      = "signin.expired"
)

// Header is what every webhook event carries.
type Header struct {
	ID           string    `json:"-"` // ULID; also the VettID-Event-Id header, stable across redeliveries
	Type         string    `json:"-"` // one of the Type constants
	ConnectionID string    `json:"-"` // the connection the event concerns
	CreatedAt    time.Time `json:"-"` // when the service vault recorded it
}

// EventHeader returns h; it makes every event type an Event.
func (h Header) EventHeader() Header { return h }

// Event is a verified webhook event: one of *ConnectionPending,
// *ConnectionAdded, *ConnectionDeclined, *ConnectionExpired,
// *ConnectionRemoved, *SignInApproved, *SignInDenied, *SignInExpired, or
// *UnknownEvent for a type this package does not know yet.
type Event interface {
	EventHeader() Header
}

// ConnectionPending: the member's vault completed the handshake; the site
// shows SAS, which the member compares on the phone before approving.
type ConnectionPending struct {
	Header
	InviteID string `json:"invite_id"`
	SAS      string `json:"sas"`
	Name     string `json:"name"` // the member's account name, as their vault presents it
}

// ConnectionAdded: both sides approved; the connection is active.
type ConnectionAdded struct {
	Header
	InviteID string `json:"invite_id"`
	Name     string `json:"name"`
	// EmailBound says whether the email entered for the invitation now
	// names this connection; nil when the service vault does not report it.
	EmailBound *bool `json:"email_bound,omitempty"`
}

// ConnectionDeclined: the member declined the invitation.
type ConnectionDeclined struct {
	Header
	InviteID string `json:"invite_id"`
}

// ConnectionExpired: the invitation ended without both approvals.
type ConnectionExpired struct {
	Header
	InviteID string `json:"invite_id"`
}

// Removal directions (ConnectionRemoved.Direction).
const (
	DirectionIn  = "in"  // the member removed it
	DirectionOut = "out" // the service removed it
)

// ConnectionRemoved: the connection ended, by either side.
type ConnectionRemoved struct {
	Header
	Direction string `json:"direction"`
}

// SignInApproved: the member approved the sign-in on the phone.
type SignInApproved struct {
	Header
	SignInID string `json:"signin_id"`
	// KeyChanged: the member's signing key differs from the one pinned
	// for the connection.
	KeyChanged bool `json:"key_changed"`
}

// SignInDenied: the member denied the sign-in, or its signature did not
// check out.
type SignInDenied struct {
	Header
	SignInID string `json:"signin_id"`
	Reason   string `json:"reason"` // denied | bad_signature
}

// SignInExpired: no answer before the sign-in expired.
type SignInExpired struct {
	Header
	SignInID string `json:"signin_id"`
}

// UnknownEvent is an event of a type this package does not know. A
// receiver should acknowledge it so the service vault does not retry it.
type UnknownEvent struct {
	Header
	Data json.RawMessage
}

// DefaultMaxWebhookBody is the default limit on a webhook body.
const DefaultMaxWebhookBody = 64 << 10

// Errors returned by Receiver.Parse and ParseWebhook. Signature failures
// wrap ErrSignature and the sdk/go/webhook error (ErrStale, ErrMismatch,
// ErrMalformed, ErrSecret).
var (
	ErrSignature    = errors.New("servicevault: webhook signature not accepted")
	ErrBodyTooLarge = errors.New("servicevault: webhook body too large")
	ErrBadEvent     = errors.New("servicevault: malformed webhook event")
	ErrReplay       = errors.New("servicevault: webhook event already received")
)

// ReplayCache remembers webhook event ids for the tolerance window, so a
// captured request replayed inside it is refused. An implementation
// shared by several receivers (a database, a cache) makes the check hold
// across them.
type ReplayCache interface {
	// Add records id until the given time. It reports false, without
	// error, if id is already recorded and not yet expired at now.
	Add(ctx context.Context, id string, now, until time.Time) (bool, error)
	// Remove forgets id, so a redelivery of an event the application
	// failed to handle is accepted.
	Remove(ctx context.Context, id string) error
}

// MemoryReplayCache is an in-process ReplayCache. The zero value is ready
// to use.
type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	adds int
}

// Add implements ReplayCache.
func (m *MemoryReplayCache) Add(_ context.Context, id string, now, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]time.Time{}
	}
	if m.adds++; m.adds >= 1024 {
		m.adds = 0
		for k, exp := range m.seen {
			if !now.Before(exp) {
				delete(m.seen, k)
			}
		}
	}
	if exp, ok := m.seen[id]; ok && now.Before(exp) {
		return false, nil
	}
	m.seen[id] = until
	return true, nil
}

// Remove implements ReplayCache.
func (m *MemoryReplayCache) Remove(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seen, id)
	return nil
}

// Receiver verifies and decodes the service vault's webhooks.
type Receiver struct {
	// Secret is the webhook signing secret (at least 32 bytes).
	Secret []byte
	// Tolerance is how far a signature's timestamp may be from Now;
	// default webhook.DefaultTolerance.
	Tolerance time.Duration
	// MaxBody limits the body; default DefaultMaxWebhookBody.
	MaxBody int64
	// Replay, if set, refuses an event id already received within the
	// tolerance window.
	Replay ReplayCache
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// ParseWebhook verifies r's signature at now with the default tolerance
// and decodes its event. It keeps no replay cache; use a Receiver with
// Replay set for that.
func ParseWebhook(r *http.Request, secret []byte, now time.Time) (Event, error) {
	return (&Receiver{Secret: secret}).parse(r, now)
}

// Parse verifies r and decodes its event. With Replay set, an event id
// already received in the window gives ErrReplay; the id stays recorded,
// so a caller that then fails to handle the event should Remove it.
func (rc *Receiver) Parse(r *http.Request) (Event, error) {
	now := rc.now()
	ev, err := rc.parse(r, now)
	if err != nil || rc.Replay == nil {
		return ev, err
	}
	fresh, err := rc.Replay.Add(r.Context(), ev.EventHeader().ID, now, now.Add(2*rc.tolerance()))
	if err != nil {
		return nil, fmt.Errorf("servicevault: replay cache: %w", err)
	}
	if !fresh {
		return nil, ErrReplay
	}
	return ev, nil
}

// Handler returns an http.Handler for the webhook endpoint. It answers:
// 2xx after handle returns nil, and for a replayed event id (already
// handled; handle is not called again); 401 for a signature that is not
// accepted; 400 for a malformed event; 413 for a body over MaxBody; 405
// for a method other than POST; and 500 when handle or the replay cache
// fails, so the service vault delivers the event again.
func (rc *Receiver) Handler(handle func(ctx context.Context, e Event) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ev, err := rc.Parse(r)
		switch {
		case err == nil:
		case errors.Is(err, ErrReplay):
			w.WriteHeader(http.StatusOK)
			return
		case errors.Is(err, ErrSignature):
			w.WriteHeader(http.StatusUnauthorized)
			return
		case errors.Is(err, ErrBodyTooLarge):
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		case errors.Is(err, ErrBadEvent):
			w.WriteHeader(http.StatusBadRequest)
			return
		default:
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if err := handle(r.Context(), ev); err != nil {
			if rc.Replay != nil {
				_ = rc.Replay.Remove(context.WithoutCancel(r.Context()), ev.EventHeader().ID)
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (rc *Receiver) now() time.Time {
	if rc.Now != nil {
		return rc.Now()
	}
	return time.Now()
}

func (rc *Receiver) tolerance() time.Duration {
	if rc.Tolerance > 0 {
		return rc.Tolerance
	}
	return webhook.DefaultTolerance
}

// envelope is the webhook body.
type envelope struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	ConnectionID string          `json:"connection_id"`
	CreatedAt    time.Time       `json:"created_at"`
	Data         json.RawMessage `json:"data"`
}

func (rc *Receiver) parse(r *http.Request, now time.Time) (Event, error) {
	max := rc.MaxBody
	if max <= 0 {
		max = DefaultMaxWebhookBody
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, fmt.Errorf("servicevault: reading webhook: %w", err)
	}
	if int64(len(body)) > max {
		return nil, ErrBodyTooLarge
	}
	id := r.Header.Get(webhook.HeaderEventID)
	if err := webhook.Verify(rc.Secret, r.Header.Get(webhook.HeaderSignature), id, body, now, rc.tolerance()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSignature, err)
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadEvent, err)
	}
	if env.ID != id || env.Type == "" {
		return nil, fmt.Errorf("%w: id or type", ErrBadEvent)
	}
	return decodeEvent(Header{ID: env.ID, Type: env.Type, ConnectionID: env.ConnectionID, CreatedAt: env.CreatedAt}, env.Data)
}

func decodeEvent(h Header, data json.RawMessage) (Event, error) {
	var ev Event
	switch h.Type {
	case TypeConnectionPending:
		ev = &ConnectionPending{Header: h}
	case TypeConnectionAdded:
		ev = &ConnectionAdded{Header: h}
	case TypeConnectionDeclined:
		ev = &ConnectionDeclined{Header: h}
	case TypeConnectionExpired:
		ev = &ConnectionExpired{Header: h}
	case TypeConnectionRemoved:
		ev = &ConnectionRemoved{Header: h}
	case TypeSignInApproved:
		ev = &SignInApproved{Header: h}
	case TypeSignInDenied:
		ev = &SignInDenied{Header: h}
	case TypeSignInExpired:
		ev = &SignInExpired{Header: h}
	default:
		return &UnknownEvent{Header: h, Data: data}, nil
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, ev); err != nil {
			return nil, fmt.Errorf("%w: %s data: %w", ErrBadEvent, h.Type, err)
		}
	}
	return ev, nil
}
