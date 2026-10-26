// Package service joins the peer to the application (MEMBER-SERVICE-PLAN
// §4.1, §4.2): it makes invitations for the private API, binds the email
// a visitor entered to the connection that results, starts and reports
// email sign-ins, and turns the peer's events into signed webhooks.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Record kinds the service keeps in the peer's store.
const (
	kindEmail     = "email"      // email index key -> the one connection bound to it
	kindSignIn    = "signin"     // a sign-in
	kindSignInReq = "signin_req" // challenge request id -> sign-in id
	kindSignInCur = "signin_cur" // email index key -> its latest sign-in id
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
	CancelChallenge(ctx context.Context, requestID string) (bool, error)
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
	// Limiter applies the per-email and per-source sign-in limits
	// (MEMBER-SERVICE-PLAN §4.2); nil applies none.
	Limiter *signin.Limiter
	// Approvals runs admin approvals (MEMBER-SERVICE-PLAN §4.5); nil runs
	// none. Its challenges' outcomes, the bootstrap admin and the removal
	// of an admin's connection reach it from Deliver.
	Approvals *approval.Manager
	Now       func() time.Time
	Log       *slog.Logger

	limited atomic.Uint64 // sign-ins started over a limit
	locks   [64]sync.Mutex
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

func (x signIns) Start(ctx context.Context, req api.SignInRequest) (string, error) {
	return x.s.StartSignIn(ctx, req)
}

func (x signIns) Status(ctx context.Context, id string) (*api.SignInStatus, error) {
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
// email index key of the address the visitor entered. It answers the
// same whether or not the email is bound already: binding is decided
// when the connection is added.
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

type signInRecord struct {
	ID         string    `json:"id"`
	ConnID     string    `json:"connection_id,omitempty"`
	RequestID  string    `json:"request_id,omitempty"`
	Status     string    `json:"status"`
	KeyChanged bool      `json:"key_changed,omitempty"`
	Exp        time.Time `json:"exp"`
}

// lock serializes sign-ins for one email key in this process (one task
// runs the service vault), so that "one pending sign-in per email" holds
// under concurrent starts.
func (s *Service) lock(emailKey string) *sync.Mutex {
	h := fnv.New32a()
	h.Write([]byte(emailKey))
	return &s.locks[h.Sum32()%uint32(len(s.locks))]
}

// LimitedSignIns is the number of sign-ins started over a rate limit
// since the process started.
func (s *Service) LimitedSignIns() uint64 { return s.limited.Load() }

// StartSignIn begins an email sign-in (MEMBER-SERVICE-PLAN §4.2). It is
// counted against the per-email and per-source limits; it supersedes the
// email's pending sign-in, if any (one pending sign-in per member: the
// older one reads expired and its challenge is cancelled); and with a
// connection bound to the email, and within the limits, a challenge
// whose context carries the match code goes to the member's vault.
// Otherwise the sign-in only expires. Either way it returns a fresh id
// and nothing else.
func (s *Service) StartSignIn(ctx context.Context, req api.SignInRequest) (string, error) {
	mu := s.lock(req.EmailKey)
	mu.Lock()
	defer mu.Unlock()
	now := s.now()
	over, err := s.Limiter.Count(ctx, req.EmailKey, req.SourceKey, now)
	if err != nil {
		return "", err
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return "", err
	}
	if over != "" {
		// Neither the email nor the source is logged.
		s.log().Info("signin rate limited", "signin_id", id, "limit", over, "limited_total", s.limited.Add(1))
	}
	if err := s.supersede(ctx, req.EmailKey); err != nil {
		return "", err
	}
	rec := &signInRecord{ID: id, Status: api.SignInPending, Exp: now.Add(signin.ChallengeTTL)}
	if over == "" {
		if err := s.challenge(ctx, req, rec); err != nil {
			return "", err
		}
	}
	changes := []peer.Change{s.signInChange(rec),
		{Kind: kindSignInCur, ID: req.EmailKey, Data: []byte(id), Expires: rec.Exp}}
	if rec.RequestID != "" {
		changes = append(changes, peer.Change{Kind: kindSignInReq, ID: rec.RequestID, Data: []byte(id),
			Expires: rec.Exp.Add(signInRetention), IfAbsent: true})
	}
	if err := s.Store.Apply(ctx, changes); err != nil {
		return "", err
	}
	return id, nil
}

// challenge sends the challenge when a connection is bound to the email
// and active.
func (s *Service) challenge(ctx context.Context, req api.SignInRequest, rec *signInRecord) error {
	b, ok, err := s.Store.Get(ctx, kindEmail, req.EmailKey)
	if err != nil || !ok {
		return err
	}
	connID := string(b)
	if c, ok := s.Peer.Connection(connID); !ok || c.State != peer.StateActive {
		return nil
	}
	ctxt, err := signin.Context(s.ServiceName, req.MatchCode)
	if err != nil {
		return err
	}
	reqID, err := s.Peer.Authenticate(ctx, connID, ctxt, signin.ChallengeTTL)
	if err != nil {
		// Answered as any other sign-in: it stays pending and expires.
		s.log().Warn("signin challenge", "signin_id", rec.ID, "err", errName(err))
		return nil
	}
	rec.ConnID, rec.RequestID = connID, reqID
	return nil
}

// supersede ends the email's pending sign-in, if any: its challenge is
// cancelled on the service's side and it reads expired. It does so for
// every email, bound or not, so that superseding reveals nothing.
func (s *Service) supersede(ctx context.Context, emailKey string) error {
	b, ok, err := s.Store.Get(ctx, kindSignInCur, emailKey)
	if err != nil || !ok {
		return err
	}
	old, err := s.signIn(ctx, string(b))
	if err != nil || old == nil || old.Status != api.SignInPending {
		return err
	}
	if old.RequestID != "" {
		// Cancelled first, so no outcome is emitted for it afterwards; an
		// outcome emitted already finds the sign-in expired and is dropped.
		if _, err := s.Peer.CancelChallenge(ctx, old.RequestID); err != nil {
			return err
		}
	}
	old.Status = api.SignInExpired
	return s.Store.Apply(ctx, []peer.Change{s.signInChange(old)})
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

// SignInStatus reports a sign-in: pending, approved (with the connection
// and key_changed), denied or expired.
func (s *Service) SignInStatus(ctx context.Context, id string) (*api.SignInStatus, error) {
	rec, err := s.signIn(ctx, id)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, api.ErrNotFound
	}
	st := &api.SignInStatus{ID: rec.ID, Status: rec.Status}
	switch {
	case rec.Status == api.SignInPending && !s.now().Before(rec.Exp):
		st.Status = api.SignInExpired
	case rec.Status == api.SignInApproved:
		kc := rec.KeyChanged
		st.ConnectionID, st.KeyChanged = rec.ConnID, &kc
	}
	return st, nil
}

// BoundConnection returns the connection bound to an email index key
// (approval.Manager.BoundConnection).
func (s *Service) BoundConnection(ctx context.Context, emailKey string) (string, bool, error) {
	b, ok, err := s.Store.Get(ctx, kindEmail, emailKey)
	return string(b), ok, err
}

// bindEmail binds the email key of a new connection's invitation to it
// unless another connection holds it (the first active connection keeps
// it; the binding is freed when that connection is removed). The write is
// conditional, so two connections added at once cannot both bind. It
// reports whether this connection holds the binding (also on a
// redelivered event).
func (s *Service) bindEmail(ctx context.Context, emailKey, connID string) (bool, error) {
	err := s.Store.Apply(ctx, []peer.Change{{Kind: kindEmail, ID: emailKey, Data: []byte(connID), IfAbsent: true}})
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, peer.ErrConflict) {
		return false, err
	}
	b, ok, err := s.Store.Get(ctx, kindEmail, emailKey)
	if err != nil {
		return false, err
	}
	return ok && string(b) == connID, nil
}

// Deliver implements peer.Events: the email binding follows the
// connection, sign-ins get their outcome, and the application gets a
// signed webhook. A webhook the endpoint rejects (4xx) is dropped after
// logging; one it could not take is retried by the peer.
func (s *Service) Deliver(ctx context.Context, e *peer.Event) error {
	switch e.Type {
	case peer.EventConnectionAdded:
		// The email the visitor entered names this connection
		// (MEMBER-SERVICE-PLAN §4.1 step 4) unless an active connection
		// holds it already.
		bound := false
		if e.Tag != "" {
			var err error
			if bound, err = s.bindEmail(ctx, e.Tag, e.ConnectionID); err != nil {
				return err
			}
		}
		if s.Approvals != nil {
			if err := s.Approvals.ConnectionAdded(ctx, e.ConnectionID, e.Tag, bound); err != nil {
				return err
			}
		}
		return s.webhook(ctx, e, map[string]any{"invite_id": e.InviteID, "name": e.Name, "email_bound": bound})
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
		// After the binding is freed, so the bootstrap cannot pick the
		// removed connection again.
		if s.Approvals != nil {
			if err := s.Approvals.ConnectionRemoved(ctx, e.ConnectionID); err != nil {
				return err
			}
		}
	case peer.EventSignInApproved, peer.EventSignInDenied, peer.EventSignInExpired:
		if s.Approvals != nil {
			// An admin's answer to an approval challenge.
			if ok, err := s.Approvals.Answer(ctx, e); err != nil || ok {
				return err
			}
		}
		sid, err := s.finishSignIn(ctx, e)
		if err != nil {
			return err
		}
		if sid == "" {
			return nil // not a sign-in, or superseded
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
	case peer.EventConnectionDeclined, peer.EventConnectionExpired:
		data = map[string]string{"invite_id": e.InviteID}
	case peer.EventConnectionRemoved:
		data = map[string]string{"direction": e.Direction}
	}
	return s.webhook(ctx, e, data)
}

// finishSignIn records a sign-in's outcome; it returns the sign-in id,
// or "" when the event is not for a sign-in or the sign-in ended
// otherwise (superseded), in which case no webhook is sent.
func (s *Service) finishSignIn(ctx context.Context, e *peer.Event) (string, error) {
	b, ok, err := s.Store.Get(ctx, kindSignInReq, e.RequestID)
	if err != nil || !ok {
		return "", err
	}
	rec, err := s.signIn(ctx, string(b))
	if err != nil || rec == nil {
		return "", err
	}
	status := api.SignInExpired
	switch e.Type {
	case peer.EventSignInApproved:
		status = api.SignInApproved
	case peer.EventSignInDenied:
		status = api.SignInDenied
	}
	switch rec.Status {
	case api.SignInPending:
		rec.Status = status
		rec.KeyChanged = status == api.SignInApproved && e.KeyChanged
		if err := s.Store.Apply(ctx, []peer.Change{s.signInChange(rec)}); err != nil {
			return "", err
		}
	case status: // a redelivered event
	default:
		return "", nil
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
