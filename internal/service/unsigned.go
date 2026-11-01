package service

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/vettid/service-vault/internal/api"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/signin"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Sign-in challenges to an unsigned connection stay within what the
// member vault accepts per connection (VAULT-MESSAGING §10.4.1): at most
// 2 pending (this sends one only when none is pending) and 10 in 24 h,
// and none for 1 h after the member declined one.
const (
	kindSignInConn = "signin_conn" // connection id -> its challenge history

	maxChallengesPerDay = 10
	challengeDay        = 24 * time.Hour
	declineCooldown     = time.Hour
)

// connHistory is the sign-in challenges sent to one connection in the
// last day, and when the member last declined one.
type connHistory struct {
	Sent       []time.Time `json:"sent,omitempty"`
	DeclinedAt time.Time   `json:"declined_at,omitempty"`
}

func (s *Service) history(ctx context.Context, connID string) (*connHistory, error) {
	h := &connHistory{}
	b, ok, err := s.Store.Get(ctx, kindSignInConn, connID)
	if err != nil || !ok {
		return h, err
	}
	return h, json.Unmarshal(b, h)
}

// saveHistory writes h, dropping what is older than the day.
func (s *Service) saveHistory(ctx context.Context, connID string, h *connHistory, now time.Time) error {
	h.Sent = slices.DeleteFunc(h.Sent, func(t time.Time) bool { return now.Sub(t) >= challengeDay })
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return s.Store.Apply(ctx, []peer.Change{{Kind: kindSignInConn, ID: connID, Data: b, Expires: now.Add(challengeDay)}})
}

// noteChallenge records a sign-in challenge sent to connID. Best effort:
// the history only keeps the sender inside the member vault's limits.
func (s *Service) noteChallenge(ctx context.Context, connID string, now time.Time) {
	mu := s.lock("conn:" + connID)
	mu.Lock()
	defer mu.Unlock()
	h, err := s.history(ctx, connID)
	if err == nil {
		h.Sent = append(h.Sent, now)
		err = s.saveHistory(ctx, connID, h, now)
	}
	if err != nil {
		s.log().Warn("signin history", "connection_id", connID, "err", err)
	}
}

// noteDeclined records that connID's member declined a sign-in.
func (s *Service) noteDeclined(ctx context.Context, connID string, now time.Time) {
	mu := s.lock("conn:" + connID)
	mu.Lock()
	defer mu.Unlock()
	h, err := s.history(ctx, connID)
	if err == nil {
		h.DeclinedAt = now
		err = s.saveHistory(ctx, connID, h, now)
	}
	if err != nil {
		s.log().Warn("signin history", "connection_id", connID, "err", err)
	}
}

// StartUnsigned sends one sign-in challenge to each eligible connection
// that has no pinned credential key (VAULT-MESSAGING §10.19.5), at most
// max of them. A connection with a sign-in challenge pending, one over
// the day's count or one whose member declined within the hour is
// skipped and says why. Each challenge is a sign-in like an email's:
// its outcome reads at GET /v1/signins/{id} and arrives as a webhook.
// Nothing here is rate limited by email or source: the caller is the
// operator. (Chosen; not in the spec.)
func (s *Service) StartUnsigned(ctx context.Context, max int) (*api.UnsignedSignIns, error) {
	ids := s.Peer.EligibleUnsigned()
	slices.Sort(ids)
	out := &api.UnsignedSignIns{SignIns: []api.UnsignedSignIn{}}
	sent := 0
	for i, connID := range ids {
		if sent >= max {
			out.More = len(ids) - i
			break
		}
		r, err := s.challengeUnsigned(ctx, connID)
		if err != nil {
			return nil, err
		}
		if r.SignInID != "" {
			sent++
		}
		out.SignIns = append(out.SignIns, r)
	}
	return out, nil
}

func (s *Service) challengeUnsigned(ctx context.Context, connID string) (api.UnsignedSignIn, error) {
	r := api.UnsignedSignIn{ConnectionID: connID}
	mu := s.lock("conn:" + connID)
	mu.Lock()
	defer mu.Unlock()
	now := s.now()
	h, err := s.history(ctx, connID)
	if err != nil {
		return r, err
	}
	day := 0
	for _, t := range h.Sent {
		if now.Sub(t) < challengeDay {
			day++
		}
	}
	switch {
	case s.Peer.HasPendingSignIn(connID):
		r.Skipped = api.SkipPending
		return r, nil
	case !h.DeclinedAt.IsZero() && now.Sub(h.DeclinedAt) < declineCooldown:
		r.Skipped = api.SkipDeclined
		return r, nil
	case day >= maxChallengesPerDay:
		r.Skipped = api.SkipDailyLimit
		return r, nil
	}
	code, err := signin.MatchCode()
	if err != nil {
		return r, err
	}
	ctxt, err := signin.Context(s.ServiceName, code)
	if err != nil {
		return r, err
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return r, err
	}
	reqID, err := s.Peer.AuthenticateSignIn(ctx, connID, ctxt, code, signin.ChallengeTTL)
	if err != nil {
		s.log().Warn("signin challenge", "connection_id", connID, "err", errName(err))
		r.Skipped = api.SkipNotSent
		return r, nil
	}
	rec := &signInRecord{ID: id, ConnID: connID, RequestID: reqID, Status: api.SignInPending, Exp: now.Add(signin.ChallengeTTL)}
	if err := s.Store.Apply(ctx, []peer.Change{s.signInChange(rec), {Kind: kindSignInReq, ID: reqID, Data: []byte(id),
		Expires: rec.Exp.Add(signInRetention), IfAbsent: true}}); err != nil {
		return r, err
	}
	h.Sent = append(h.Sent, now)
	if err := s.saveHistory(ctx, connID, h, now); err != nil {
		s.log().Warn("signin history", "connection_id", connID, "err", err)
	}
	r.SignInID, r.MatchCode = id, code
	return r, nil
}
