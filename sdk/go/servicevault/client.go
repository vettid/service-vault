// Package servicevault is the Go client for the service vault's private
// API and the receiver for its signed webhooks.
//
// The client reaches the API over TLS 1.3 and accepts exactly one server
// key, identified by the pin the service vault publishes (package
// pinned); every /v1 call carries the application's API key. GET calls
// are retried a bounded number of times on network errors and 5xx
// answers; POST calls, which create invitations, sign-ins and approvals
// and send reminders, are never retried.
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
	maxAuditBody        = 8 << 20 // a page of up to 100 entries with payloads of up to 16 KiB
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
	// Admin approvals.
	CodeInvalidAction     = "invalid_action"     // not one of the Action constants (400)
	CodeInvalidSummary    = "invalid_summary"    // empty, over 120 bytes, or control or bidi characters (400)
	CodeInvalidPayload    = "invalid_payload"    // not a JSON object of at most 16 KiB canonical, or a bad admin_set payload (400)
	CodeInvalidConnection = "invalid_connection" // admin_set.*: not an active connection, not an admin, or already one (422)
	CodeUnreachable       = "unreachable"        // the threshold is more than the admins there are, or would be (422)
	CodeLastAdmin         = "last_admin"         // admin_set.remove of the only admin (422)
	CodeSoleAdmin         = "sole_admin"         // admin.repin with one admin: the others can't confirm it (422)
	CodeNotPending        = "not_pending"        // the approval is settled or expired (409)
	CodeTooSoon           = "too_soon"           // a reminder within 10 minutes of the last challenges (429)
	CodeNotAdmin          = "not_admin"          // remind force: not an admin of the approval, or no longer in the set (422)
	CodeAnswered          = "answered"           // remind force: the admin has answered (409)
	CodeNothingToRemind   = "nothing_to_remind"  // every admin who has not answered holds a live challenge (409)
	CodeAskBudget         = "ask_budget"         // create or remind: too few admins can be asked, each at the ask limit: 4 approval challenges still counting, or 5 for a repair action (409)
	CodeRateLimited       = "rate_limited"       // create: the limit of the action's group is reached (SV_APPROVAL_LIMITS; 429)
)

// APIError is a non-2xx answer from the API.
type APIError struct {
	Status int    // HTTP status
	Code   string // the body's "error", or "" if it had none
	// ProposalID is the body's "proposal_id": a proposal kept but not
	// published (503 not_published), for PublishProposal to retry.
	ProposalID string
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

// UnsignedSignIn is one connection's part in StartUnsignedSignIns: the
// sign-in started (read it with SignInStatus) and its match code, or the
// reason none was started: "pending" (a sign-in challenge is still
// pending), "declined" (the member declined one within the hour),
// "daily_limit" (10 in the last 24 h), "not_sent", or "not_recorded"
// (the challenge went out with MatchCode but has no SignInID).
type UnsignedSignIn struct {
	ConnectionID string `json:"connection_id"`
	SignInID     string `json:"signin_id,omitempty"`
	MatchCode    string `json:"match_code,omitempty"`
	Skipped      string `json:"skipped,omitempty"`
}

// UnsignedSignIns is the answer of StartUnsignedSignIns. More counts the
// connections not yet looked at, which another run reaches. Stopped is
// "timeout" or "error" when the run ended early; SignIns is still what
// it did.
type UnsignedSignIns struct {
	SignIns []UnsignedSignIn `json:"signins"`
	More    int              `json:"more"`
	Stopped string           `json:"stopped,omitempty"`
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

// Actions an approval can be for (MEMBER-SERVICE-PLAN §4.5).
const (
	ActionProposalCreate         = "proposal.create"
	ActionVoteExtend             = "vote.extend"
	ActionContractTemplateChange = "contract_template.change"
	ActionAdminSetAdd            = "admin_set.add"    // payload {"connection_id": "..."}; applied by the service vault
	ActionAdminSetRemove         = "admin_set.remove" // payload {"connection_id": "..."}; applied by the service vault
	ActionAssignmentPush         = "assignment.push"
	ActionAdminRepin             = "admin.repin" // payload {"connection_id": "...", "new_key": "<base64>"} (new_key optional: the connection's credential key); applied by the service vault
)

// Approval statuses (Approval.Status).
const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusDenied   = "denied" // the threshold can no longer be reached
	ApprovalStatusExpired  = "expired"
)

// ApprovalRequest submits an action for admin approval.
type ApprovalRequest struct {
	Action string `json:"action"` // one of the Action constants
	// Summary is what the admins read on the phone: plain text, 1 to 120
	// bytes, no control or bidirectional characters, not starting with the
	// words of an action label or BINDING, ADVISORY or EXTEND. It must be
	// empty for ActionProposalCreate, ActionVoteExtend, ActionAdminSetAdd
	// and ActionAdminSetRemove: the service writes what the admins read
	// from the payload (who is added or removed, as it holds it).
	Summary string `json:"summary"`
	// Payload is the action itself, a JSON object of at most 16 KiB in
	// canonical form. ActionHash(Action, Summary, Payload) is the hash
	// the admins approve.
	Payload json.RawMessage `json:"payload"`
}

// ApprovalCreated is a new approval.
type ApprovalCreated struct {
	ID         string    `json:"approval_id"`
	ActionHash string    `json:"action_hash"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
	// AskBudget: the admins not asked because they are at the ask limit
	// (4 approval challenges still counting, or 5 for a repair action:
	// admin.repin, admin_set.add, admin_set.remove), with when each can be
	// asked again.
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
}

// AskBudget is an admin not asked because of the member vault's approval
// ask budget (5 per 24 hours).
type AskBudget struct {
	ConnectionID string `json:"connection_id"`
	// NextAskAt: the oldest challenge counted stops counting then (its
	// expiry plus 24 hours plus the clock skew).
	NextAskAt time.Time `json:"next_ask_at"`
}

// Approver is an admin's approval.
type Approver struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
	// KeyChanged: the admin signed with a key other than the one pinned
	// for the connection.
	KeyChanged bool `json:"key_changed"`
	// Counted: the approval counts toward the threshold. It does not when
	// the key is not the admin's governance key on a governance action
	// (admin_set.add, admin_set.remove, admin.repin, proposal.create,
	// vote.extend, contract_template.change): their approvals count again
	// once the other admins approve admin.repin for the key they sign with.
	Counted bool `json:"counted"`
	// GovKeyChanged: the key is not the admin's governance key.
	GovKeyChanged bool `json:"gov_key_changed"`
	// Reason, with Counted false: key_changed (a new key) or not_repinned
	// (a key the service has seen since, that the other admins have not
	// confirmed with admin.repin).
	Reason string `json:"reason,omitempty"`
}

// Denier is an admin's counted denial.
type Denier struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
}

// Approval reports an approval.
type Approval struct {
	ID         string `json:"approval_id"`
	Action     string `json:"action"`
	Summary    string `json:"summary"`
	ActionHash string `json:"action_hash"`
	// Payload is the canonical payload the hash covers; for admin.repin it
	// carries the new_key the service filled in.
	Payload   json.RawMessage `json:"payload,omitempty"`
	Status    string          `json:"status"`
	Reason    string          `json:"reason,omitempty"` // with denied: denied | admins_removed
	Threshold int             `json:"threshold"`
	Admins    []string        `json:"admins"` // the admins asked
	Approvals []Approver      `json:"approvals"`
	Denials   []Denier        `json:"denials"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	// RemindNeeded, while pending: the admins who have not answered and
	// hold no live challenge (it ran out after 10 minutes, or could not
	// be sent); RemindApproval challenges them again.
	RemindNeeded []string `json:"remind_needed"`
	// AskBudget, while pending: those of RemindNeeded at the ask budget.
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
	// RemindAfter, with RemindNeeded: the earliest RemindApproval is
	// accepted; before it the answer is too_soon.
	RemindAfter *time.Time `json:"remind_after,omitempty"`
	// Applied, for an approved admin_set.* action: whether the service
	// vault changed the admin set.
	Applied *bool `json:"applied,omitempty"`
}

// Reminder answers RemindApproval.
type Reminder struct {
	ID       string   `json:"approval_id"`
	Reminded []string `json:"reminded"` // the admins challenged again
	// AskBudget: the admins left out because they are at the ask limit
	// (4 approval challenges still counting, or 5 for a repair action).
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
}

// Admins is the admin set and the threshold m.
type Admins struct {
	Admins    []string `json:"admins"`
	Threshold int      `json:"threshold"`
}

// AuditChallenge is a challenge sent to an admin.
type AuditChallenge struct {
	ConnectionID string `json:"connection_id"`
	RequestID    string `json:"request_id"`
}

// AuditEntry is one entry of the audit log (README "Admin approvals").
type AuditEntry struct {
	ID           string           `json:"id"`
	At           time.Time        `json:"at"`
	Type         string           `json:"type"` // approval.requested | approval.response | approval.reminded | approval.approved | approval.denied | approval.expired | admin_set.changed | admin_set.bootstrap_armed
	ApprovalID   string           `json:"approval_id,omitempty"`
	Action       string           `json:"action,omitempty"`
	Summary      string           `json:"summary,omitempty"`
	ActionHash   string           `json:"action_hash,omitempty"`
	Payload      json.RawMessage  `json:"payload,omitempty"`
	Threshold    int              `json:"threshold,omitempty"`
	ExpiresAt    *time.Time       `json:"expires_at,omitempty"`
	Admins       []string         `json:"admins,omitempty"`
	Challenges   []AuditChallenge `json:"challenges,omitempty"`
	ConnectionID string           `json:"connection_id,omitempty"`
	RequestID    string           `json:"request_id,omitempty"`
	Context      string           `json:"context,omitempty"`
	Answer       string           `json:"answer,omitempty"` // approved | denied | bad_signature
	Counted      *bool            `json:"counted,omitempty"`
	Key          []byte           `json:"key,omitempty"`
	Signature    []byte           `json:"signature,omitempty"`
	SignedAt     *time.Time       `json:"signed_at,omitempty"`
	KeyChanged   bool             `json:"key_changed,omitempty"`
	Status       string           `json:"status,omitempty"`
	Reason       string           `json:"reason,omitempty"`
	Applied      *bool            `json:"applied,omitempty"`
	Added        string           `json:"added,omitempty"`
	Removed      string           `json:"removed,omitempty"`
}

// AuditPage is a page of the audit log.
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	Next    string       `json:"next,omitempty"` // pass as since for the next page; "" at the end
}

// CreateApproval submits an action for admin approval; every admin is
// asked on the phone. Check ApprovalCreated.ActionHash against
// ActionHash before relying on the approval.
func (c *Client) CreateApproval(ctx context.Context, req ApprovalRequest) (*ApprovalCreated, error) {
	out := &ApprovalCreated{}
	if err := c.do(ctx, http.MethodPost, "/v1/approvals", req, true, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Approval reports an approval; IsNotFound(err) for an unknown id.
func (c *Client) Approval(ctx context.Context, id string) (*Approval, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty approval id")
	}
	out := &Approval{}
	if err := c.do(ctx, http.MethodGet, "/v1/approvals/"+url.PathEscape(id), nil, true, out); err != nil {
		return nil, err
	}
	return out, nil
}

// RemindApproval challenges again the admins who have not answered, at
// most once per 10 minutes per approval (CodeTooSoon otherwise). Admins
// who hold a live challenge are skipped; CodeNothingToRemind if none is left.
//
// With force, only the named admins (connection ids) are challenged, each
// even if it holds a live challenge, the old one being withdrawn first
// (CodeNotAdmin, CodeAnswered otherwise). Each forced re-send uses one of
// the member's 5 approval asks per 24 hours (VAULT-MESSAGING §10.4.1), and
// a sixth would come back as a delayed denial, so a force naming an admin
// at the ask limit (4 approval challenges that still count, each until its
// expiry plus 24 hours, the fifth being kept for repair actions; or 5 for
// those) is refused (CodeAskBudget): use it only when an admin reports not
// seeing the request. Without force, an admin at the ask limit is left out (they stay in RemindNeeded), and if that
// leaves none to challenge, nothing is withdrawn or sent (CodeAskBudget).
func (c *Client) RemindApproval(ctx context.Context, id string, force ...string) (*Reminder, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty approval id")
	}
	var in any
	if len(force) > 0 {
		in = map[string][]string{"force": force}
	}
	out := &Reminder{}
	if err := c.do(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(id)+"/remind", in, true, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Admins returns the admin set (connection ids) and the threshold.
func (c *Client) Admins(ctx context.Context) (*Admins, error) {
	out := &Admins{}
	if err := c.do(ctx, http.MethodGet, "/v1/admins", nil, true, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Audit returns up to limit (1..100; 0 for 100) audit entries written
// after the entry since ("" for the first).
func (c *Client) Audit(ctx context.Context, since string, limit int) (*AuditPage, error) {
	q := url.Values{}
	if since != "" {
		q.Set("since", since)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/audit"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	out := &AuditPage{}
	if err := c.do(ctx, http.MethodGet, path, nil, true, out); err != nil {
		return nil, err
	}
	return out, nil
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

// EmailVerification says whether the application has verified that the
// member controls the email of an invitation. It has no usable zero
// value: CreateInvite refuses anything but EmailVerified and
// EmailUnverified, so the choice is always explicit.
type EmailVerification int

const (
	_ EmailVerification = iota
	// EmailUnverified: the invitation carries no email; the connection
	// is never bound to one (no email sign-in, no admin bootstrap).
	EmailUnverified
	// EmailVerified: the application verified, just before, that the
	// member controls the address (for example by a one-time code sent
	// to it). The connection is bound to it, so it is used for email
	// sign-in and can make the first admin. Use it for nothing else:
	// binding an address that was not verified lets whoever typed it
	// take it (and, with SV_ADMIN_BOOTSTRAP_EMAIL, the first admin).
	EmailVerified
)

// ErrEmailVerification is returned by CreateInvite for an
// EmailVerification other than EmailVerified and EmailUnverified.
var ErrEmailVerification = errors.New("servicevault: CreateInvite needs EmailVerified or EmailUnverified")

// CreateInvite makes a 10-minute, in-person invitation for the email the
// visitor entered. With EmailVerified the connection that results is
// bound to it; with EmailUnverified the invitation carries no email.
func (c *Client) CreateInvite(ctx context.Context, email string, v EmailVerification) (*Invite, error) {
	if v != EmailVerified && v != EmailUnverified {
		return nil, ErrEmailVerification
	}
	body := struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}{email, v == EmailVerified}
	inv := &Invite{}
	if err := c.do(ctx, http.MethodPost, "/v1/invites", body, true, inv); err != nil {
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

// StartUnsignedSignIns is for test deployments only: unless the service
// vault has SV_TEST_SIGNINS=true it returns an *APIError with status 403
// and code "test_only". It sends one sign-in challenge to each eligible
// connection (one whose vault takes votes) that has no pinned
// credential key, so that its votes are not refused for want of a
// sign-in (VAULT-MESSAGING §10.19.5). It sends at most 10 challenges
// and looks at at most 100 connections per call (More: those not looked
// at). A connection that has a challenge pending, declined one within
// the hour or has had 10 in 24 h is skipped, which keeps within the
// limits of the member's vault (§10.4.1). The call ends within about
// 8 s with what it did, Stopped set if it was cut short. It is not
// retried.
func (c *Client) StartUnsignedSignIns(ctx context.Context) (*UnsignedSignIns, error) {
	u := &UnsignedSignIns{}
	if err := c.do(ctx, http.MethodPost, "/v1/signins/unsigned", nil, true, u); err != nil {
		return nil, err
	}
	return u, nil
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
	limit := int64(maxResponseBody)
	if strings.HasPrefix(path, "/v1/audit") {
		limit = maxAuditBody
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return true, fmt.Errorf("servicevault: %s %s: %w", method, routeName(path), err)
	}
	if int64(len(b)) > limit {
		return false, fmt.Errorf("servicevault: %s %s: response too large", method, routeName(path))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		var e struct {
			Error      string `json:"error"`
			ProposalID string `json:"proposal_id"`
		}
		if json.Unmarshal(b, &e) == nil {
			ae.Code, ae.ProposalID = e.Error, e.ProposalID
		}
		return resp.StatusCode >= 500, ae
	}
	if err := json.Unmarshal(b, out); err != nil {
		return false, fmt.Errorf("servicevault: %s %s: decoding response: %w", method, routeName(path), err)
	}
	return false, nil
}

// Votes (BALLOT-PROTOCOL; README "Votes"). The documents are the API's
// JSON as served, unparsed: the proposal input and the answers are
// specified there, and an operator tool passes them through.

// AnchorKey returns GET /v1/anchor-key: the anchor key, its certificate
// and the service's identity key, for the votes site's service list.
func (c *Client) AnchorKey(ctx context.Context) (json.RawMessage, error) {
	var out json.RawMessage
	return out, c.do(ctx, http.MethodGet, "/v1/anchor-key", nil, true, &out)
}

// CreateProposal posts a proposal input (POST /v1/proposals) with the id
// of the admins' approval of it. The approval is an ActionProposalCreate
// approval whose payload is the input in canonical form with every field
// present (no summary: the service builds what the admins read from the
// payload); it must be approved, and it is used up by this call, even if
// the proposal then fails to publish. It is not retried: a retry would
// make a second proposal. A proposal kept but not published is an
// *APIError with Code "not_published" and its ProposalID, for
// PublishProposal.
func (c *Client) CreateProposal(ctx context.Context, approvalID string, in json.RawMessage) (json.RawMessage, error) {
	body, err := withApproval(approvalID, in)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	return out, c.do(ctx, http.MethodPost, "/v1/proposals", body, true, &out)
}

// ExtendProposal posts an extension of a proposal's close (POST
// /v1/proposals/{id}/extend: {closes_at, outage: {from, to, source}}) with
// the id of the admins' approval of it. The approval is an
// ActionVoteExtend approval whose payload is {"proposal_id", "closes_at",
// "outage"} in canonical form (no summary); it is used up by this call.
// It is not retried.
func (c *Client) ExtendProposal(ctx context.Context, id, approvalID string, in json.RawMessage) (json.RawMessage, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty proposal id")
	}
	body, err := withApproval(approvalID, in)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	return out, c.do(ctx, http.MethodPost, "/v1/proposals/"+url.PathEscape(id)+"/extend", body, true, &out)
}

// withApproval adds approval_id to a JSON object; the object may not
// carry one, nor repeat a name.
func withApproval(approvalID string, in json.RawMessage) (json.RawMessage, error) {
	if approvalID == "" {
		return nil, errors.New("servicevault: an approval id is required")
	}
	canon, err := CanonicalJSON(in)
	if err != nil || len(canon) == 0 || canon[0] != '{' {
		return nil, errors.New("servicevault: the input is not a JSON object")
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(canon, &m); err != nil {
		return nil, err
	}
	if _, dup := m["approval_id"]; dup {
		return nil, errors.New("servicevault: the input has an approval_id")
	}
	id, _ := json.Marshal(approvalID)
	m["approval_id"] = id
	return json.Marshal(m)
}

// Proposal returns GET /v1/proposals/{id}.
func (c *Client) Proposal(ctx context.Context, id string) (json.RawMessage, error) {
	return c.proposalCall(ctx, http.MethodGet, id, "")
}

// PublishProposal retries a proposal's publication and sending.
func (c *Client) PublishProposal(ctx context.Context, id string) (json.RawMessage, error) {
	return c.proposalCall(ctx, http.MethodPost, id, "/publish")
}

// CloseProposal counts, publishes and announces a proposal's results,
// once it has closed and the relay's messages are in (else an *APIError:
// not_closed, collecting).
func (c *Client) CloseProposal(ctx context.Context, id string) (json.RawMessage, error) {
	return c.proposalCall(ctx, http.MethodPost, id, "/close")
}

// ProposalResults returns GET /v1/proposals/{id}/results.
func (c *Client) ProposalResults(ctx context.Context, id string) (json.RawMessage, error) {
	return c.proposalCall(ctx, http.MethodGet, id, "/results")
}

func (c *Client) proposalCall(ctx context.Context, method, id, sub string) (json.RawMessage, error) {
	if id == "" {
		return nil, errors.New("servicevault: empty proposal id")
	}
	var out json.RawMessage
	return out, c.do(ctx, method, "/v1/proposals/"+url.PathEscape(id)+sub, nil, true, &out)
}

// routeName names a route without its id, for error messages.
func routeName(path string) string {
	path, _, _ = strings.Cut(path, "?")
	for _, p := range []string{"/v1/invites/", "/v1/signins/", "/v1/approvals/", "/v1/proposals/"} {
		if rest, ok := strings.CutPrefix(path, p); ok {
			if _, sub, ok := strings.Cut(rest, "/"); ok {
				return p + "{id}/" + sub
			}
			return p + "{id}"
		}
	}
	return path
}
