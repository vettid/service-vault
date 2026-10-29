// Package approval runs admin approvals of governance actions
// (MEMBER-SERVICE-PLAN §4.5, §5.2): the application submits an action,
// the service vault hashes it and asks every admin to approve it on the
// phone with a connection.authenticate.challenge (VAULT-MESSAGING §10.4)
// whose context names the action and carries its hash, and the action is
// approved once m distinct admins have signed. Until contracts land
// (Phase 3) this is the admin approval; every request, answer and
// outcome is kept in an append-only audit log.
package approval

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Actions an approval can be for (MEMBER-SERVICE-PLAN §4.5).
const (
	ActionProposalCreate         = "proposal.create"
	ActionVoteOpen               = "vote.open"
	ActionVoteClose              = "vote.close"
	ActionContractTemplateChange = "contract_template.change"
	ActionAdminSetAdd            = "admin_set.add"
	ActionAdminSetRemove         = "admin_set.remove"
	ActionAssignmentPush         = "assignment.push"
)

var actions = map[string]bool{
	ActionProposalCreate: true, ActionVoteOpen: true, ActionVoteClose: true, ActionContractTemplateChange: true,
	ActionAdminSetAdd: true, ActionAdminSetRemove: true, ActionAssignmentPush: true,
}

// Approval statuses.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied" // the threshold can no longer be reached
	StatusExpired  = "expired"
)

// Reasons of a denied approval.
const (
	ReasonDenied        = "denied"         // admins' denials left too few admins to reach the threshold
	ReasonAdminsRemoved = "admins_removed" // admins left the set and too few remain to reach it
)

// Webhook event types.
const (
	EventApproved        = "approval.approved"
	EventDenied          = "approval.denied"
	EventExpired         = "approval.expired"
	EventAdminSetChanged = "admin_set.changed"
)

// Audit entry types.
const (
	AuditRequested       = "approval.requested"
	AuditResponse        = "approval.response"
	AuditReminded        = "approval.reminded"
	AuditApproved        = "approval.approved"
	AuditDenied          = "approval.denied"
	AuditExpired         = "approval.expired"
	AuditAdminSetChanged = "admin_set.changed"
	// AuditBootstrapArmed: the operator armed a new one-shot bootstrap
	// (`service-vault admin bootstrap`); the email is not recorded.
	AuditBootstrapArmed = "admin_set.bootstrap_armed"
)

// Answers in an approval.response audit entry.
const (
	AnswerApproved     = "approved"      // signed, and the signature verified
	AnswerDenied       = "denied"        // the admin's vault answered denied
	AnswerBadSignature = "bad_signature" // signed, but the signature did not verify
)

// ReasonNoPurpose marks an approval.response signed without a purpose
// (Manager.AllowNoPurpose): weaker evidence, counted only when allowed.
const ReasonNoPurpose = "no_purpose"

// Reasons an admin set changed.
const (
	ChangeBootstrap         = "bootstrap"
	ChangeApproval          = "approval"
	ChangeConnectionRemoved = "connection_removed"
)

// Limits.
const (
	MaxSummary = 120      // bytes
	MaxPayload = 16 << 10 // bytes, canonical
	// MaxContext is the challenge context's bound (VAULT-MESSAGING §10.4).
	MaxContext = 256
	// RemindInterval: challenges go out at most this often per approval
	// (the connauth challenge's own life, so a reminder never overlaps
	// an outstanding challenge).
	RemindInterval = 10 * time.Minute
	// DefaultTTL is how long an approval stays open (SV_APPROVAL_TTL).
	DefaultTTL = 24 * time.Hour
)

// Error codes (Error.Code), as the API answers them.
const (
	CodeInvalidAction     = "invalid_action"
	CodeInvalidSummary    = "invalid_summary"
	CodeInvalidPayload    = "invalid_payload"
	CodeInvalidConnection = "invalid_connection" // admin_set.*: not an active connection, not an admin, or already one
	CodeUnreachable       = "unreachable"        // the threshold is more than the admins there are (or would be)
	CodeLastAdmin         = "last_admin"         // admin_set.remove of the only admin
	CodeNotPending        = "not_pending"
	CodeTooSoon           = "too_soon"
)

// Error is a request the service refuses, with its API error code.
type Error struct{ Code string }

func (e *Error) Error() string { return "approval: " + e.Code }

func errCode(c string) error { return &Error{Code: c} }

// Request is an action the application submits for approval.
type Request struct {
	Action  string          `json:"action"`
	Summary string          `json:"summary"`
	Payload json.RawMessage `json:"payload"`
}

// Created answers a new approval.
type Created struct {
	ID         string    `json:"approval_id"`
	ActionHash string    `json:"action_hash"`
	Status     string    `json:"status"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Approver is an admin's counted approval.
type Approver struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
	// KeyChanged: the admin signed with a credential key other than the
	// one pinned for the connection that no rotation chain reaches
	// (§10.4). The approval still counts; the application decides.
	KeyChanged bool `json:"key_changed"`
}

// Denier is an admin's counted denial.
type Denier struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
}

// Status is what became of an approval.
type Status struct {
	ID         string     `json:"approval_id"`
	Action     string     `json:"action"`
	Summary    string     `json:"summary"`
	ActionHash string     `json:"action_hash"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"` // with denied
	Threshold  int        `json:"threshold"`
	Admins     []string   `json:"admins"` // the admins asked
	Approvals  []Approver `json:"approvals"`
	Denials    []Denier   `json:"denials"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	// Applied, for an approved admin_set.* action: whether the service
	// vault changed the admin set (false when it no longer applied, for
	// example the connection was removed meanwhile).
	Applied *bool `json:"applied,omitempty"`
}

// Reminder answers a reminder.
type Reminder struct {
	ID       string   `json:"approval_id"`
	Reminded []string `json:"reminded"` // connection ids challenged again
}

// Admins is the admin set.
type Admins struct {
	Admins    []string `json:"admins"`
	Threshold int      `json:"threshold"`
}

// Challenge is one challenge sent to an admin.
type Challenge struct {
	ConnectionID string `json:"connection_id"`
	RequestID    string `json:"request_id"`
}

// AuditEntry is one entry of the audit log. Entries are written once and
// never changed or deleted; ids increase in the order they are written.
type AuditEntry struct {
	ID         string          `json:"id"`
	At         time.Time       `json:"at"`
	Type       string          `json:"type"`
	ApprovalID string          `json:"approval_id,omitempty"`
	Action     string          `json:"action,omitempty"`
	Summary    string          `json:"summary,omitempty"`
	ActionHash string          `json:"action_hash,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"` // canonical; approval.requested
	Threshold  int             `json:"threshold,omitempty"`
	ExpiresAt  *time.Time      `json:"expires_at,omitempty"`
	Admins     []string        `json:"admins,omitempty"` // the admins asked, or the admin set after a change
	Challenges []Challenge     `json:"challenges,omitempty"`
	// An admin's answer (approval.response): the evidence.
	ConnectionID string     `json:"connection_id,omitempty"`
	RequestID    string     `json:"request_id,omitempty"`
	Context      string     `json:"context,omitempty"` // the challenge's context, as signed
	Answer       string     `json:"answer,omitempty"`
	Counted      *bool      `json:"counted,omitempty"`
	Key          []byte     `json:"key,omitempty"`       // the admin's credential key (Ed25519)
	Signature    []byte     `json:"signature,omitempty"` // over the challenge (VAULT-MESSAGING §10.4)
	Purpose      string     `json:"purpose,omitempty"`   // the purpose the signature covers; "" for none (0.65.0)
	SignedAt     *time.Time `json:"signed_at,omitempty"`
	// What else the signature covers (§10.4), so the entry verifies on
	// its own (AuditEntry.Verify).
	Nonce      []byte `json:"nonce,omitempty"`
	ServiceIK  []byte `json:"service_ik,omitempty"`
	MemberIK   []byte `json:"member_ik,omitempty"`
	KeyChanged bool   `json:"key_changed,omitempty"`
	// An outcome or an admin set change.
	Status  string `json:"status,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Applied *bool  `json:"applied,omitempty"`
	Added   string `json:"added,omitempty"`
	Removed string `json:"removed,omitempty"`
}

// AuditPage is a page of the audit log.
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	// Next is the since of the next page; "" at the end.
	Next string `json:"next,omitempty"`
}

// checkSummary accepts plain text of 1 to MaxSummary bytes: valid UTF-8,
// no control characters, no line or paragraph separators and no
// bidirectional controls (so the admin reads on the phone what the
// application meant).
func checkSummary(s string) error {
	if s == "" || len(s) > MaxSummary || !utf8.ValidString(s) {
		return errCode(CodeInvalidSummary)
	}
	for _, r := range s {
		if unicode.IsControl(r) || isBidiControl(r) || r == '\u2028' || r == '\u2029' {
			return errCode(CodeInvalidSummary)
		}
	}
	return nil
}

func isBidiControl(r rune) bool {
	switch {
	case r == '\u061c', r == '\u200e', r == '\u200f':
		return true
	case r >= '\u202a' && r <= '\u202e':
		return true
	case r >= '\u2066' && r <= '\u2069':
		return true
	}
	return false
}

// ChallengeContext is the context of an approval challenge:
// "Approve on <service>: <summary> — ref <first 8 hex of the hash>",
// with the summary cut (on a character boundary, ending in "…") so that
// the whole is at most MaxContext bytes.
func ChallengeContext(serviceName, summary, actionHash string) (string, error) {
	if len(actionHash) < 8 {
		return "", fmt.Errorf("approval: short action hash")
	}
	f := func(s string) string {
		return fmt.Sprintf("Approve on %s: %s — ref %s", serviceName, s, actionHash[:8])
	}
	if s := f(summary); len(s) <= MaxContext {
		return s, nil
	}
	const ell = "…"
	room := MaxContext - len(f("")) - len(ell)
	if room < 1 {
		return "", fmt.Errorf("approval: service name too long for a challenge context")
	}
	cut := 0
	for i := range summary {
		if i > room {
			break
		}
		cut = i
	}
	return f(summary[:cut] + ell), nil
}

// ErrNoEvidence is an entry without a signed answer's evidence: not a
// signed approval.response, or one written before the nonce and the
// identity keys were kept.
var ErrNoEvidence = errors.New("approval: the entry holds no complete signed answer")

// Verify checks a signed approval.response entry's signature over the
// challenge it answered (VAULT-MESSAGING §10.4), from the entry alone.
func (e *AuditEntry) Verify() error {
	if e.Type != AuditResponse || len(e.Signature) == 0 || len(e.Key) != ed25519.PublicKeySize || len(e.Nonce) == 0 ||
		len(e.ServiceIK) != ed25519.PublicKeySize || len(e.MemberIK) != ed25519.PublicKeySize {
		return ErrNoEvidence
	}
	ch := &peerwire.ConnAuthChallenge{RequestID: e.RequestID, Nonce: e.Nonce, Context: e.Context, Purpose: e.Purpose}
	r := &peerwire.ConnAuthResponse{RequestID: e.RequestID, Status: peerwire.ConnAuthSigned, Key: e.Key, Sig: e.Signature,
		Purpose: e.Purpose, HasPurpose: e.Purpose != ""}
	return peerwire.VerifyConnAuthResponse(r, e.ServiceIK, e.MemberIK, ch)
}
