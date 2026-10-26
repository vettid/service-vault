// Package api is the service vault's private HTTPS API for the
// application (MEMBER-SERVICE-PLAN §3): invitations, email sign-in and
// health. It is reachable only from the application's network and every
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
	"strings"
	"time"

	"github.com/vettid/service-vault/internal/connect"
	"github.com/vettid/service-vault/internal/signin"
)

// Invites makes connection invitations, remembering the email the member
// entered so the connection can be bound to it when it is accepted.
type Invites interface {
	Create(ctx context.Context, emailKey string) (*Invitation, error)
}

// Invitation is what the application shows the member.
type Invitation struct {
	ID  string    `json:"invite_id"`
	URL string    `json:"url"` // <relay>/connect#…: the button on mobile and the QR on desktop
	Exp time.Time `json:"expires_at"`
}

// SignIns starts and reports email sign-ins.
type SignIns interface {
	// Start begins a sign-in for emailKey with the given match code. It
	// returns the same kind of id whether or not a connection has the
	// email; for an unknown email the sign-in stays pending until it
	// expires.
	Start(ctx context.Context, emailKey, code string) (id string, err error)
	// Status reports a sign-in: "pending", "approved", "denied" or
	// "expired"; connectionID is set only when approved.
	Status(ctx context.Context, id string) (status, connectionID string, err error)
}

// ErrNotFound is returned by SignIns.Status for an unknown id.
var ErrNotFound = errors.New("api: not found")

// Server is the HTTP API.
type Server struct {
	Keys        [][32]byte // SHA-256 of the accepted API keys
	Email       *connect.EmailIndex
	Invites     Invites
	SignIns     SignIns
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
	v1.HandleFunc("POST /v1/signins", s.startSignIn)
	v1.HandleFunc("GET /v1/signins/{id}", s.signInStatus)
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

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeError(w, http.StatusBadRequest, "bad_request")
		return false
	}
	return true
}

type emailBody struct {
	Email string `json:"email"`
}

func (s *Server) createInvite(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if !readJSON(w, r, &b) {
		return
	}
	k, err := s.Email.Key(b.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email")
		return
	}
	inv, err := s.Invites.Create(r.Context(), k)
	if err != nil {
		s.log().Error("invite", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

type signInResponse struct {
	ID        string `json:"signin_id"`
	MatchCode string `json:"match_code"`
}

// startSignIn answers the same way, after the same delay, whether or not
// the email belongs to a connection (MEMBER-SERVICE-PLAN §4.2).
func (s *Server) startSignIn(w http.ResponseWriter, r *http.Request) {
	var b emailBody
	if !readJSON(w, r, &b) {
		return
	}
	k, err := s.Email.Key(b.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email")
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
		id, startErr = s.SignIns.Start(ctx, k, code)
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

type statusResponse struct {
	ID           string `json:"signin_id"`
	Status       string `json:"status"`
	ConnectionID string `json:"connection_id,omitempty"`
}

func (s *Server) signInStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	st, cid, err := s.SignIns.Status(r.Context(), id)
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.log().Error("signin status", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable")
	default:
		writeJSON(w, http.StatusOK, statusResponse{ID: id, Status: st, ConnectionID: cid})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
