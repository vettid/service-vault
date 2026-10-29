// Package api is the service vault's private HTTPS API for the
// application (MEMBER-SERVICE-PLAN §3): invitations, email sign-in, admin
// approvals and health. It is reachable only from the application's network and every
// /v1 route requires an API key.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/signin"
)

// Invites makes connection invitations, remembering the email the member
// entered so the connection can be bound to it when it is accepted.
type Invites interface {
	// Create makes an invitation. emailKey is the index key of an email
	// the application verified the member controls, or "" for an
	// invitation that carries no email (it is never bound).
	Create(ctx context.Context, emailKey string) (*Invitation, error)
	// Status reports what became of an invitation, so that the site can
	// show the SAS once the member's vault completed the handshake
	// (VAULT-MESSAGING §6.4). ErrNotFound for an unknown id.
	Status(ctx context.Context, id string) (*InviteStatus, error)
}

// Invitation statuses.
const (
	InviteWaiting   = "waiting"   // not accepted yet, or the handshake runs
	InviteSAS       = "sas"       // the SAS is known: show it; the member compares and approves
	InviteConnected = "connected" // the member approved: the connection is active
	InviteDeclined  = "declined"  // the member declined
	InviteExpired   = "expired"   // nobody accepted it in time, or the request ended unapproved
)

// InviteStatus is what became of an invitation.
type InviteStatus struct {
	ID           string `json:"invite_id"`
	Status       string `json:"status"`
	SAS          string `json:"sas,omitempty"`           // with status sas
	ConnectionID string `json:"connection_id,omitempty"` // with status sas or connected
}

// Invitation is what the application shows the member.
type Invitation struct {
	ID  string    `json:"invite_id"`
	URL string    `json:"url"` // <relay>/connect#…: the button on mobile and the QR on desktop
	Exp time.Time `json:"expires_at"`
}

// SignIns starts and reports email sign-ins.
type SignIns interface {
	// Start begins a sign-in. It returns the same kind of id whether or
	// not a connection has the email and whether or not a rate limit was
	// reached; a sign-in that sends no challenge stays pending until it
	// expires.
	Start(ctx context.Context, req SignInRequest) (id string, err error)
	// Status reports a sign-in; ErrNotFound for an unknown id.
	Status(ctx context.Context, id string) (*SignInStatus, error)
}

// SignInRequest is a sign-in to start.
type SignInRequest struct {
	EmailKey  string // the email's index key
	SourceKey string // the source's key (connect.EmailIndex.SourceKey); "" when none was given
	MatchCode string
}

// Sign-in statuses.
const (
	SignInPending  = "pending"
	SignInApproved = "approved"
	SignInDenied   = "denied"
	SignInExpired  = "expired" // no answer in time, or superseded by a newer sign-in for the same email
)

// SignInStatus is what became of a sign-in.
type SignInStatus struct {
	ID           string `json:"signin_id"`
	Status       string `json:"status"`
	ConnectionID string `json:"connection_id,omitempty"` // approved only
	// KeyChanged is set when approved: true when the member signed with a
	// credential key other than the one pinned at the connection's first
	// sign-in and no rotation chain reaches it (VAULT-MESSAGING §10.4).
	KeyChanged *bool `json:"key_changed,omitempty"`
}

// Approvals runs admin approvals (approval.Manager).
type Approvals interface {
	Create(ctx context.Context, req approval.Request) (*approval.Created, error)
	Status(ctx context.Context, id string) (*approval.Status, error)
	Remind(ctx context.Context, id string) (*approval.Reminder, error)
	Admins(ctx context.Context) (*approval.Admins, error)
	Audit(ctx context.Context, since string, limit int) (*approval.AuditPage, error)
}

// Proposals creates and reports votes' proposals (ballot.Manager).
type Proposals interface {
	Create(ctx context.Context, in ballot.ProposalInput) (*ballot.Created, error)
	// Status reports a proposal, or nil for an unknown id.
	Status(ctx context.Context, id string) (*ballot.ProposalStatus, error)
}

// ErrNotFound is returned by Invites.Status and SignIns.Status for an
// unknown id.
var ErrNotFound = errors.New("api: not found")

// Server is the HTTP API.
type Server struct {
	Keys        [][32]byte // SHA-256 of the accepted API keys
	Email       *connect.EmailIndex
	Invites     Invites
	SignIns     SignIns
	Approvals   Approvals     // nil: the approval routes are not served
	Proposals   Proposals     // nil: the proposal routes are not served
	LookupFloor time.Duration // uniform response time for POST /v1/signin; default 1.5 s
	Log         *slog.Logger
}

// HashKey is how API keys are configured: their SHA-256.
func HashKey(key string) [32]byte { return sha256.Sum256([]byte(key)) }

// Handler returns the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	v1 := http.NewServeMux()
	v1.HandleFunc("POST /v1/invites", s.createInvite)
	v1.HandleFunc("GET /v1/invites/{id}", s.inviteStatus)
	v1.HandleFunc("POST /v1/signins", s.startSignIn)
	v1.HandleFunc("GET /v1/signins/{id}", s.signInStatus)
	if s.Approvals != nil {
		v1.HandleFunc("POST /v1/approvals", s.createApproval)
		v1.HandleFunc("GET /v1/approvals/{id}", s.approvalStatus)
		v1.HandleFunc("POST /v1/approvals/{id}/remind", s.remindApproval)
		v1.HandleFunc("GET /v1/admins", s.admins)
		v1.HandleFunc("GET /v1/audit", s.audit)
	}
	if s.Proposals != nil {
		v1.HandleFunc("POST /v1/proposals", s.createProposal)
		v1.HandleFunc("GET /v1/proposals/{id}", s.proposalStatus)
	}
	mux.Handle("/v1/", s.auth(v1))
	return mux
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// auth requires "Authorization: Bearer <key>" matching a configured key.
// Every configured key is compared, in constant time, so the time taken
// does not depend on which one matched. With no keys configured nothing
// is accepted.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		h := HashKey(tok)
		match := 0
		for _, k := range s.Keys {
			match |= subtle.ConstantTimeCompare(h[:], k[:])
		}
		if !ok || tok == "" || match != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

const maxBody = 4 << 10

// maxApprovalBody bounds POST /v1/approvals: a payload of up to
// approval.MaxPayload canonical bytes, with room for whitespace.
const maxApprovalBody = 2*approval.MaxPayload + maxBody

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSONMax(w, r, v, maxBody)
}

func readJSONMax(w http.ResponseWriter, r *http.Request, v any, max int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	return true
}

type inviteBody struct {
	Email string `json:"email"`
	// EmailVerified is required: true only when the application has
	// verified that the member controls the address (a one-time code
	// sent to it). Only a verified email is bound to the connection, and
	// only a bound email can make the first admin.
	EmailVerified *bool `json:"email_verified"`
}

// createInvite makes an invitation. With email_verified false the
// invitation carries no email at all, so the connection it becomes is
// never bound to one (chosen; not in the spec).
func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var b inviteBody
	if !readJSON(w, r, &b) {
		return
	}
	if b.EmailVerified == nil {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	k, err := s.Email.Key(b.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email")
		return
	}
	if !*b.EmailVerified {
		k = ""
	}
	inv, err := s.Invites.Create(r.Context(), k)
	if err != nil {
		s.log().Error("invite", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

type signInBody struct {
	Email  string `json:"email"`
	Source string `json:"source,omitempty"`
}

func (s *Server) inviteStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Invites.Status(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.log().Error("invite status", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

type signInResponse struct {
	ID        string `json:"signin_id"`
	MatchCode string `json:"match_code"`
}

// startSignIn answers the same way, after the same delay, whether or not
// the email belongs to a connection and whether or not a rate limit was
// reached (MEMBER-SERVICE-PLAN §4.2). source is the end user's address
// as the application sees it, used only for the per-source rate limit.
func (s *Server) startSignIn(w http.ResponseWriter, r *http.Request) {
	var b signInBody
	if !readJSON(w, r, &b) {
		return
	}
	k, err := s.Email.Key(b.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email")
		return
	}
	src, err := s.Email.SourceKey(b.Source)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_source")
		return
	}
	code, err := signin.MatchCode()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	floor := s.LookupFloor
	if floor <= 0 {
		floor = 1500 * time.Millisecond
	}
	var id string
	var startErr error
	if signin.Uniform(r.Context(), floor, func(ctx context.Context) {
		id, startErr = s.SignIns.Start(ctx, SignInRequest{EmailKey: k, SourceKey: src, MatchCode: code})
	}) {
		s.log().Warn("signin lookup overran the uniform floor", "floor", floor)
	}
	if startErr != nil {
		s.log().Error("signin", "err", startErr)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writeJSON(w, http.StatusAccepted, signInResponse{ID: id, MatchCode: code})
}

func (s *Server) signInStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.SignIns.Status(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.log().Error("signin status", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func (s *Server) createApproval(w http.ResponseWriter, r *http.Request) {
	var b approval.Request
	if !readJSONMax(w, r, &b, maxApprovalBody) {
		return
	}
	c, err := s.Approvals.Create(r.Context(), b)
	if err != nil {
		s.approvalError(w, "approval", err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) approvalStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Approvals.Status(r.Context(), r.PathValue("id"))
	if err != nil {
		s.approvalError(w, "approval status", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) remindApproval(w http.ResponseWriter, r *http.Request) {
	rm, err := s.Approvals.Remind(r.Context(), r.PathValue("id"))
	if err != nil {
		s.approvalError(w, "approval remind", err)
		return
	}
	writeJSON(w, http.StatusOK, rm)
}

func (s *Server) admins(w http.ResponseWriter, r *http.Request) {
	a, err := s.Approvals.Admins(r.Context())
	if err != nil {
		s.approvalError(w, "admins", err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// audit serves GET /v1/audit?since=<entry id>&limit=<1..100>.
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > approval.MaxAuditPage {
			writeError(w, http.StatusBadRequest, "bad_request")
			return
		}
		limit = n
	}
	since := q.Get("since")
	if len(since) > 64 {
		writeError(w, http.StatusBadRequest, "bad_request")
		return
	}
	p, err := s.Approvals.Audit(r.Context(), since, limit)
	if err != nil {
		s.approvalError(w, "audit", err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// approvalStatusCodes maps the approval error codes to HTTP statuses.
var approvalStatusCodes = map[string]int{
	approval.CodeInvalidAction:     http.StatusBadRequest,
	approval.CodeInvalidSummary:    http.StatusBadRequest,
	approval.CodeInvalidPayload:    http.StatusBadRequest,
	approval.CodeInvalidConnection: http.StatusUnprocessableEntity,
	approval.CodeUnreachable:       http.StatusUnprocessableEntity,
	approval.CodeLastAdmin:         http.StatusUnprocessableEntity,
	approval.CodeNotPending:        http.StatusConflict,
	approval.CodeTooSoon:           http.StatusTooManyRequests,
}

func (s *Server) approvalError(w http.ResponseWriter, what string, err error) {
	var ae *approval.Error
	switch {
	case errors.Is(err, approval.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.As(err, &ae) && approvalStatusCodes[ae.Code] != 0:
		writeError(w, approvalStatusCodes[ae.Code], ae.Code)
	default:
		s.log().Error(what, "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	}
}

// maxProposalBody bounds POST /v1/proposals: the text's 16 KiB, the
// title and the choices, with room for JSON escaping.
const maxProposalBody = 64 << 10

// createProposal serves POST /v1/proposals (BALLOT-PROTOCOL §3): the
// proposal is made from the roster at this moment, published and sent to
// every eligible member.
func (s *Server) createProposal(w http.ResponseWriter, r *http.Request) {
	var b ballot.ProposalInput
	if !readJSONMax(w, r, &b, maxProposalBody) {
		return
	}
	c, err := s.Proposals.Create(r.Context(), b)
	var ei *ballot.ErrInput
	switch {
	case errors.As(err, &ei):
		writeError(w, http.StatusBadRequest, "invalid_proposal")
	case errors.Is(err, ballot.ErrNoPublisher):
		writeError(w, http.StatusServiceUnavailable, "publication_not_configured")
	case err != nil:
		s.log().Error("create proposal", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		writeJSON(w, http.StatusCreated, c)
	}
}

// proposalStatus serves GET /v1/proposals/{id}: the proposal and its
// times, and nothing that counts ballots before the results.
func (s *Server) proposalStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.Proposals.Status(r.Context(), r.PathValue("id"))
	switch {
	case err != nil:
		s.log().Error("proposal status", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	case st == nil:
		writeError(w, http.StatusNotFound, "not_found")
	default:
		writeJSON(w, http.StatusOK, st)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // payloads are served as their canonical bytes
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
