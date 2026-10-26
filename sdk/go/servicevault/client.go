// Package servicevault is the Go client for the service vault's private
// API and the receiver for its signed webhooks.
//
// The client reaches the API over TLS 1.3 and accepts exactly one server
// key, identified by the pin the service vault publishes (package
// pinned); every /v1 call carries the application's API key. GET calls
// are retried a bounded number of times on network errors and 5xx
// answers; POST calls, which create invitations and sign-ins, are never
// retried.
//
// The pin and the webhook secret are configuration: in the AWS
// deployment the application reads the pin from the SSM parameter the
// stack exports (TlsPinParameterName) and the secret from the exported
// Secrets Manager ARN (WebhookSecretArn). This package has no AWS
// dependency and does not fetch them.
package servicevault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/service-vault/sdk/go/pinned"
)

// Defaults for Config.
const (
	DefaultTimeout      = 10 * time.Second
	DefaultGetAttempts  = 3
	DefaultRetryBackoff = 200 * time.Millisecond
	maxRetryBackoff     = 2 * time.Second
	maxResponseBody     = 64 << 10
)

// Config configures a Client.
type Config struct {
	// BaseURL is the API's https URL, for example
	// https://service-vault.prod.vettid.internal:8080.
	BaseURL string
	// APIKey is sent as "Authorization: Bearer <APIKey>" on /v1 routes.
	APIKey string
	// Pin is the server key's pin, "sha256/<base64url>".
	Pin string
	// Timeout bounds each attempt of a call; default DefaultTimeout.
	// POST /v1/signins answers after a uniform delay (about 1.5 s), so it
	// should not be set much lower than the default.
	Timeout time.Duration
	// GetAttempts is how many times a GET is tried in all; default
	// DefaultGetAttempts. 1 disables retries.
	GetAttempts int
	// RetryBackoff is the first delay between GET attempts, doubled each
	// time up to 2 s; default DefaultRetryBackoff.
	RetryBackoff time.Duration
}

// Option changes how New builds a Client.
type Option func(*Client)

// WithHTTPClient makes the Client use c instead of a pinned client. It is
// meant for tests: with it, Pin is not checked and BaseURL may be http.
// Production code should leave it out.
func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.hc = c }
}

// Client calls the service vault's private API. It is safe for
// concurrent use.
type Client struct {
	base     string
	key      string
	hc       *http.Client
	timeout  time.Duration
	attempts int
	backoff  time.Duration
}

// New makes a Client.
func New(cfg Config, opts ...Option) (*Client, error) {
	c := &Client{key: cfg.APIKey, timeout: cfg.Timeout, attempts: cfg.GetAttempts, backoff: cfg.RetryBackoff}
	for _, o := range opts {
		o(c)
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.attempts <= 0 {
		c.attempts = DefaultGetAttempts
	}
	if c.backoff <= 0 {
		c.backoff = DefaultRetryBackoff
	}
	if cfg.APIKey == "" {
		return nil, errors.New("servicevault: APIKey is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("servicevault: BaseURL must be an absolute URL")
	}
	if c.hc == nil {
		if u.Scheme != "https" {
			return nil, errors.New("servicevault: BaseURL must be https")
		}
		// The per-attempt timeout is applied through the request context.
		if c.hc, err = pinned.Client(cfg.Pin, 0); err != nil {
			return nil, fmt.Errorf("servicevault: %w", err)
		}
	}
	c.base = strings.TrimRight(u.String(), "/")
	return c, nil
}

// Error codes the API answers with (APIError.Code).
const (
	CodeBadRequest    = "bad_request"    // the request body was not understood
	CodeInvalidEmail  = "invalid_email"  // the email is not a valid address
	CodeInvalidSource = "invalid_source" // SignInRequest.Source is not a valid address
	CodeUnauthorized  = "unauthorized"   // the API key was missing or not accepted
	CodeNotFound      = "not_found"      // no invitation or sign-in with that id
	CodeUnavailable   = "unavailable"    // the service vault could not do it now
)

// APIError is a non-2xx answer from the API.
type APIError struct {
	Status int    // HTTP status
	Code   string // the body's "error", or "" if it had none
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return "servicevault: HTTP " + strconv.Itoa(e.Status)
	}
	return "servicevault: HTTP " + strconv.Itoa(e.Status) + " " + e.Code
}

// IsNotFound reports whether err is the API's answer for an unknown id.
func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// Invite statuses (InviteStatus.Status).
const (
	InviteStatusWaiting   = "waiting"   // not accepted yet, or the handshake runs
	InviteStatusSAS       = "sas"       // show SAS: the member compares it on the phone and approves
	InviteStatusConnected = "connected" // the member approved; the connection is active
	InviteStatusDeclined  = "declined"  // the member declined
	InviteStatusExpired   = "expired"   // nobody accepted it in time, or it ended unapproved
)

// Invite is a new connection invitation.
type Invite struct {
	ID string `json:"invite_id"`
	// URL is the button on mobile and the QR code on desktop.
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// InviteStatus is what became of an invitation.
type InviteStatus struct {
	ID           string `json:"invite_id"`
	Status       string `json:"status"`
	SAS          string `json:"sas,omitempty"`           // with status sas
	ConnectionID string `json:"connection_id,omitempty"` // with status sas or connected
}

// Sign-in statuses (SignInStatus.Status).
const (
	SignInStatusPending  = "pending"
	SignInStatusApproved = "approved"
	SignInStatusDenied   = "denied"
	SignInStatusExpired  = "expired"
)

// SignInRequest starts an email sign-in.
type SignInRequest struct {
	Email string `json:"email"`
	// Source is optional: the end user's address as the application sees
	// it (the client IP), used only for the service vault's per-source
	// sign-in rate limit. Empty is left out.
	Source string `json:"source,omitempty"`
}

// SignIn is a started sign-in. The site shows MatchCode; the member finds
// the same code in the request on the phone.
type SignIn struct {
	ID        string `json:"signin_id"`
	MatchCode string `json:"match_code"`
}

// SignInStatus reports a sign-in.
type SignInStatus struct {
	ID           string `json:"signin_id"`
	Status       string `json:"status"`
	ConnectionID string `json:"connection_id,omitempty"` // with status approved
	// KeyChanged, with status approved: true when the member signed with a
	// key other than the one pinned for the connection. nil when the
	// service vault does not report it.
	KeyChanged *bool `json:"key_changed,omitempty"`
}

// Health checks that the service vault answers GET /health with ok.
func (c *Client) Health(ctx context.Context) error {
	var b struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/health", nil, false, &b); err != nil {
		return err
	}
	if b.Status != "ok" {
		return fmt.Errorf("servicevault: health status %q", b.Status)
	}
	return nil
}

// CreateInvite makes a 10-minute, in-person invitation for the email the
// visitor entered; the connection that results is bound to it.
func (c *Client) CreateInvite(ctx context.Context, email string) (*Invite, error) {
	inv := &Invite{}
	if err := c.do(ctx, http.MethodPost, "/v1/invites", map[string]string{"email": email}, true, inv); err != nil {
		return nil, err
	}
	return inv, nil
}

// InviteStatus reports an invitation; IsNotFound(err) for an unknown id.
func (c *Client) InviteStatus(ctx context.Context, id string) (*InviteStatus, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty invite id")
	}
	st := &InviteStatus{}
	if err := c.do(ctx, http.MethodGet, "/v1/invites/"+url.PathEscape(id), nil, true, st); err != nil {
		return nil, err
	}
	return st, nil
}

// StartSignIn starts an email sign-in. It answers the same way, after the
// same delay, whether or not the email belongs to a connection.
func (c *Client) StartSignIn(ctx context.Context, req SignInRequest) (*SignIn, error) {
	si := &SignIn{}
	if err := c.do(ctx, http.MethodPost, "/v1/signins", req, true, si); err != nil {
		return nil, err
	}
	return si, nil
}

// SignInStatus reports a sign-in; IsNotFound(err) for an unknown id.
func (c *Client) SignInStatus(ctx context.Context, id string) (*SignInStatus, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty sign-in id")
	}
	st := &SignInStatus{}
	if err := c.do(ctx, http.MethodGet, "/v1/signins/"+url.PathEscape(id), nil, true, st); err != nil {
		return nil, err
	}
	return st, nil
}

// do performs a call, retrying a GET on network errors and 5xx.
func (c *Client) do(ctx context.Context, method, path string, in any, auth bool, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	attempts := 1
	if method == http.MethodGet {
		attempts = c.attempts
	}
	delay := c.backoff
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return err
			case <-t.C:
			}
			delay = min(2*delay, maxRetryBackoff)
		}
		var retry bool
		retry, err = c.once(ctx, method, path, body, auth, out)
		if err == nil || !retry || ctx.Err() != nil {
			return err
		}
	}
	return err
}

func (c *Client) once(ctx context.Context, method, path string, body []byte, auth bool, out any) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// A wrong server key will not become right on retry.
		return !errors.Is(err, pinned.ErrPin), fmt.Errorf("servicevault: %s %s: %w", method, routeName(path), err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return true, fmt.Errorf("servicevault: %s %s: %w", method, routeName(path), err)
	}
	if len(b) > maxResponseBody {
		return false, fmt.Errorf("servicevault: %s %s: response too large", method, routeName(path))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil {
			ae.Code = e.Error
		}
		return resp.StatusCode >= 500, ae
	}
	if err := json.Unmarshal(b, out); err != nil {
		return false, fmt.Errorf("servicevault: %s %s: decoding response: %w", method, routeName(path), err)
	}
	return false, nil
}

// routeName names a route without its id, for error messages.
func routeName(path string) string {
	for _, p := range []string{"/v1/invites/", "/v1/signins/"} {
		if strings.HasPrefix(path, p) {
			return p + "{id}"
		}
	}
	return path
}
