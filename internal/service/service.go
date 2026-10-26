// Package service joins the peer to the application (MEMBER-SERVICE-PLAN
// §4.1, §4.2): it makes invitations for the private API, binds the email
// a visitor entered to the connection that results, starts and reports
// email sign-ins, and turns the peer's events into signed webhooks.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Record kinds the service keeps in the peer's store.
const (
	kindEmail     = "email"      // email index key -> connection id
	kindSignIn    = "signin"     // a sign-in
	kindSignInReq = "signin_req" // challenge request id -> sign-in id
)

// signInRetention keeps a finished sign-in readable (chosen; not in the
// spec).
const signInRetention = 24 * time.Hour

// Peer is the part of peer.Peer the service uses.
type Peer interface {
	CreateInvite(ctx context.Context, tag string) (*peer.InviteRecord, error)
	Invite(id string) (peer.InviteRecord, bool)
	Connection(id string) (peer.ConnectionInfo, bool)
	Authenticate(ctx context.Context, connID, ctxt string, ttl time.Duration) (string, error)
}

// Webhooks delivers webhook events (webhook.Dispatcher).
type Webhooks interface {
	Deliver(ctx context.Context, e *webhook.Event) error
}

// Service implements peer.Events; Invites and SignIns return its
// api.Invites and api.SignIns.
type Service struct {
	Peer        Peer
	Store       peer.Store
	ServiceName string // in the sign-in challenge's context
	Webhooks    Webhooks
	Now         func() time.Time
	Log         *slog.Logger
}

var _ peer.Events = (*Service)(nil)

// Invites returns the service's api.Invites.
func (s *Service) Invites() api.Invites { return invites{s} }

// SignIns returns the service's api.SignIns.
func (s *Service) SignIns() api.SignIns { return signIns{s} }

type invites struct{ s *Service }

func (i invites) Create(ctx context.Context, emailKey string) (*api.Invitation, error) {
	return i.s.CreateInvite(ctx, emailKey)
}

func (i invites) Status(ctx context.Context, id string) (*api.InviteStatus, error) {
	return i.s.InviteStatus(ctx, id)
}

type signIns struct{ s *Service }

func (x signIns) Start(ctx context.Context, emailKey, code string) (string, error) {
	return x.s.StartSignIn(ctx, emailKey, code)
}

func (x signIns) Status(ctx context.Context, id string) (string, string, error) {
	return x.s.SignInStatus(ctx, id)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// CreateInvite makes an in-person invitation tagged with the
// email index key of the address the visitor entered.
func (s *Service) CreateInvite(ctx context.Context, emailKey string) (*api.Invitation, error) {
	inv, err := s.Peer.CreateInvite(ctx, emailKey)
	if err != nil {
		return nil, err
	}
	return &api.Invitation{ID: inv.ID, URL: inv.URL, Exp: inv.Exp}, nil
}

// InviteStatus reports what became of an invitation.
func (s *Service) InviteStatus(_ context.Context, id string) (*api.InviteStatus, error) {
	inv, ok := s.Peer.Invite(id)
	if !ok {
		return nil, api.ErrNotFound
	}
	st := &api.InviteStatus{ID: inv.ID, Status: inv.Status}
	switch inv.Status {
	case peer.InviteSAS:
		st.SAS, st.ConnectionID = inv.SAS, inv.ConnID
	case peer.InviteConnected:
		st.ConnectionID = inv.ConnID
	}
	return st, nil
}

// Sign-in statuses (api.SignIns).
const (
	signInPending  = "pending"
	signInApproved = "approved"
	signInDenied   = "denied"
	signInExpired  = "expired"
)

type signInRecord struct {
	ID        string    `json:"id"`
	ConnID    string    `json:"connection_id,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Status    string    `json:"status"`
	Exp       time.Time `json:"exp"`
}

// StartSignIn begins an email sign-in (MEMBER-SERVICE-PLAN §4.2): with a
// connection bound to the email, a challenge whose context carries the
// match code goes to the member's vault; without one, the sign-in only
// expires. Either way it returns a fresh id and nothing else.
func (s *Service) StartSignIn(ctx context.Context, emailKey, code string) (string, error) {
	now := s.now()
	id, err := envelope.NewULID(now)
	if err != nil {
		return "", err
	}
	rec := &signInRecord{ID: id, Status: signInPending, Exp: now.Add(signin.ChallengeTTL)}
	if b, ok, err := s.Store.Get(ctx, kindEmail, emailKey); err != nil {
		return "", err
	} else if ok {
		connID := string(b)
		if c, ok := s.Peer.Connection(connID); ok && c.State == peer.StateActive {
			ctxt, err := signin.Context(s.ServiceName, code)
			if err != nil {
				return "", err
			}
			reqID, err := s.Peer.Authenticate(ctx, connID, ctxt, signin.ChallengeTTL)
			if err != nil {
				// Answered as any other sign-in: it stays pending and expires.
				s.log().Warn("signin challenge", "signin_id", id, "err", errName(err))
			} else {
				rec.ConnID, rec.RequestID = connID, reqID
			}
		}
	}
	changes := []peer.Change{s.signInChange(rec)}
	if rec.RequestID != "" {
		changes = append(changes, peer.Change{Kind: kindSignInReq, ID: rec.RequestID, Data: []byte(id),
			Expires: rec.Exp.Add(signInRetention), IfAbsent: true})
	}
	if err := s.Store.Apply(ctx, changes); err != nil {
		return "", err
	}
	return id, nil
}

func errName(err error) string {
	switch {
	case errors.Is(err, peer.ErrLimit):
		return "limit"
	case errors.Is(err, peer.ErrNotFound):
		return "not_found"
	}
	return "error"
}

func (s *Service) signInChange(rec *signInRecord) peer.Change {
	b, _ := json.Marshal(rec)
	return peer.Change{Kind: kindSignIn, ID: rec.ID, Data: b, Expires: rec.Exp.Add(signInRetention)}
}

func (s *Service) signIn(ctx context.Context, id string) (*signInRecord, error) {
	b, ok, err := s.Store.Get(ctx, kindSignIn, id)
	if err != nil || !ok {
		return nil, err
	}
	rec := &signInRecord{}
	if err := json.Unmarshal(b, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// SignInStatus reports a sign-in: pending, approved (with the
// connection), denied or expired.
func (s *Service) SignInStatus(ctx context.Context, id string) (status, connectionID string, err error) {
	rec, err := s.signIn(ctx, id)
	if err != nil {
		return "", "", err
	}
	if rec == nil {
		return "", "", api.ErrNotFound
	}
	if rec.Status == signInPending && !s.now().Before(rec.Exp) {
		return signInExpired, "", nil
	}
	if rec.Status == signInApproved {
		return rec.Status, rec.ConnID, nil
	}
	return rec.Status, "", nil
}

// Deliver implements peer.Events: the email binding follows the
// connection, sign-ins get their outcome, and the application gets a
// signed webhook. A webhook the endpoint rejects (4xx) is dropped after
// logging; one it could not take is retried by the peer.
func (s *Service) Deliver(ctx context.Context, e *peer.Event) error {
	switch e.Type {
	case peer.EventConnectionAdded:
		if e.Tag != "" {
			// The email the visitor entered now names this connection
			// (MEMBER-SERVICE-PLAN §4.1 step 4); a later connection with
			// the same email takes it over.
			if err := s.Store.Apply(ctx, []peer.Change{{Kind: kindEmail, ID: e.Tag, Data: []byte(e.ConnectionID)}}); err != nil {
				return err
			}
		}
	case peer.EventConnectionRemoved:
		if e.Tag != "" {
			b, ok, err := s.Store.Get(ctx, kindEmail, e.Tag)
			if err != nil {
				return err
			}
			if ok && string(b) == e.ConnectionID {
				if err := s.Store.Apply(ctx, []peer.Change{{Kind: kindEmail, ID: e.Tag}}); err != nil {
					return err
				}
			}
		}
	case peer.EventSignInApproved, peer.EventSignInDenied, peer.EventSignInExpired:
		sid, err := s.finishSignIn(ctx, e)
		if err != nil {
			return err
		}
		if sid == "" {
			return nil // not a sign-in (an approval challenge, later)
		}
		data := map[string]any{"signin_id": sid}
		switch e.Type {
		case peer.EventSignInApproved:
			data["key_changed"] = e.KeyChanged
		case peer.EventSignInDenied:
			data["reason"] = e.Reason
		}
		return s.webhook(ctx, e, data)
	}
	var data any
	switch e.Type {
	case peer.EventConnectionPending:
		data = map[string]string{"invite_id": e.InviteID, "sas": e.SAS, "name": e.Name}
	case peer.EventConnectionAdded:
		data = map[string]string{"invite_id": e.InviteID, "name": e.Name}
	case peer.EventConnectionDeclined, peer.EventConnectionExpired:
		data = map[string]string{"invite_id": e.InviteID}
	case peer.EventConnectionRemoved:
		data = map[string]string{"direction": e.Direction}
	}
	return s.webhook(ctx, e, data)
}

// finishSignIn records a sign-in's outcome; it returns the sign-in id.
func (s *Service) finishSignIn(ctx context.Context, e *peer.Event) (string, error) {
	b, ok, err := s.Store.Get(ctx, kindSignInReq, e.RequestID)
	if err != nil || !ok {
		return "", err
	}
	rec, err := s.signIn(ctx, string(b))
	if err != nil || rec == nil {
		return "", err
	}
	if rec.Status == signInPending {
		switch e.Type {
		case peer.EventSignInApproved:
			rec.Status = signInApproved
		case peer.EventSignInDenied:
			rec.Status = signInDenied
		default:
			rec.Status = signInExpired
		}
		if err := s.Store.Apply(ctx, []peer.Change{s.signInChange(rec)}); err != nil {
			return "", err
		}
	}
	return rec.ID, nil
}

func (s *Service) webhook(ctx context.Context, e *peer.Event, data any) error {
	if s.Webhooks == nil {
		return nil
	}
	w := &webhook.Event{ID: e.ID, Type: e.Type, ConnectionID: e.ConnectionID, CreatedAt: e.At.UTC().Truncate(time.Second)}
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		w.Data = b
	}
	err := s.Webhooks.Deliver(ctx, w)
	if errors.Is(err, webhook.ErrRejected) {
		s.log().Error("webhook rejected", "event_id", e.ID, "type", e.Type)
		return nil
	}
	return err
}
