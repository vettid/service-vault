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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Actions an approval can be for (MEMBER-SERVICE-PLAN §4.5).
const (
	ActionProposalCreate         = "proposal.create"
	ActionVoteExtend             = "vote.extend"
	ActionContractTemplateChange = "contract_template.change"
	ActionAdminSetAdd            = "admin_set.add"
	ActionAdminSetRemove         = "admin_set.remove"
	ActionAssignmentPush         = "assignment.push"
	ActionAdminRepin             = "admin.repin"
)

var actions = map[string]bool{
	ActionProposalCreate: true, ActionVoteExtend: true, ActionContractTemplateChange: true,
	ActionAdminSetAdd: true, ActionAdminSetRemove: true, ActionAssignmentPush: true, ActionAdminRepin: true,
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

// Reasons an approval response was audited as not counted, for a
// governance action (Governance): the admin signed with a credential key
// other than their governance key, either one the service had not seen
// (key_changed: it is not the key pinned at the last sign-in either) or
// one it has seen sign in since but that the other admins have not
// re-pinned (not_repinned).
const (
	ReasonKeyChanged  = "key_changed"
	ReasonNotRepinned = "not_repinned"
	// ReasonLegacy: a governance approval stored before approvals were
	// checked against a governance key.
	ReasonLegacy = "legacy_unpinned"
)

// Reasons of the migration of governance keys (AuditGovKeyMigrated and
// AuditGovKeyRefused) and of the approvals it ends.
const (
	// ReasonEvidence: the key pinned is that of the admin's earliest signed
	// approval in the audit log; a different current key then needs a
	// re-pin. ReasonNoEvidence: there is none, the current key was pinned.
	ReasonEvidence     = "evidence"
	ReasonNoEvidence   = "no_evidence"
	ReasonAuthKeyMoved = "auth_key_moved" // the key shown is no longer the credential key
	// ReasonGovMigrated ends an open governance approval at the migration.
	ReasonGovMigrated = "gov_key_migrated"
)

// Governance reports whether an action decides who governs or what binds
// the members: the admin set and its governance keys, new votes, extended
// votes and the contract template. An approval of one signed with a changed credential key does
// not count, since someone else may now hold the member's credential.
// assignment.push is not governance: it hands work to named members, and
// changes neither who decides nor what binds them (chosen).
func Governance(action string) bool {
	switch action {
	case ActionAdminSetAdd, ActionAdminSetRemove, ActionAdminRepin, ActionProposalCreate, ActionVoteExtend, ActionContractTemplateChange:
		return true
	}
	return false
}

// Webhook event types.
const (
	EventApproved = "approval.approved"
	EventDenied   = "approval.denied"
	EventExpired  = "approval.expired"
	// EventChallengeExpired: an admin's challenge ran out unanswered
	// (VAULT-MESSAGING §10.4: 10 minutes) while the approval is still
	// open; the admin has none until a reminder.
	EventChallengeExpired = "approval.challenge_expired"
	EventAdminSetChanged  = "admin_set.changed"
)

// Audit entry types.
const (
	AuditRequested = "approval.requested"
	AuditResponse  = "approval.response"
	AuditReminded  = "approval.reminded"
	AuditApproved  = "approval.approved"
	AuditDenied    = "approval.denied"
	AuditExpired   = "approval.expired"
	// AuditConsumed: an approved proposal.create or vote.extend was used,
	// once, for the proposal or extension it approved.
	AuditConsumed        = "approval.consumed"
	AuditAdminSetChanged = "admin_set.changed"
	AuditAdminRepinned   = "admin.repinned" // an admin's governance key was re-pinned (admin.repin applied)
	// AuditGovKeyMigrated: an existing admin's governance key was pinned
	// when the feature began (Reason: the evidence, see ReasonNoEvidence);
	// AuditGovKeyRefused: an approved change would have pinned a key that
	// is no longer the connection's credential key (ReasonAuthKeyMoved).
	AuditGovKeyMigrated = "gov_key.migrated"
	AuditGovKeyRefused  = "gov_key.refused"
	// AuditBootstrapArmed: the operator armed a new one-shot bootstrap
	// (`service-vault admin bootstrap`); the email is not recorded.
	AuditBootstrapArmed     = "admin_set.bootstrap_armed"
	AuditBootstrapConfirmed = "admin_set.bootstrap_confirmed"
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

// RefLen is how many hex digits of the action hash the challenge shows
// as its ref: 64 bits. That is about 2^32 work to find two actions with
// the same ref (a birthday collision), which someone who writes both
// payloads could do; it holds against someone who must match a ref
// already shown (2^64). The approval itself is bound to the whole
// 256-bit payload, not to the ref.
const RefLen = 16

// MaxServiceName is the longest service name: the context holds 256
// bytes, and the name, the action's label and the framing leave room for
// a summary built from a payload to be shown whole.
const MaxServiceName = 32

// CheckServiceName refuses a name that is empty, too long or not plain.
func CheckServiceName(name string) error {
	if name == "" || len(name) > MaxServiceName || checkSummary(name) != nil {
		return fmt.Errorf("approval: a service name is 1 to %d plain bytes", MaxServiceName)
	}
	return nil
}

// ActionLabels are put by the service at the front of every approval's
// challenge context, so that whatever follows is read as that kind of
// action: an application's summary for one action can't pass as another.
var ActionLabels = map[string]string{
	ActionProposalCreate:         "New vote:",
	ActionVoteExtend:             "Extend vote:",
	ActionAdminSetAdd:            "Add admin:",
	ActionAdminSetRemove:         "Remove admin:",
	ActionContractTemplateChange: "Contract template:",
	ActionAssignmentPush:         "Push assignment:",
	ActionAdminRepin:             "Re-pin admin:",
}

// builtSummary reports whether the service builds the action's summary
// from its payload, and so shows it whole (never cut).
func builtSummary(action string) bool { return BuiltSummary(action) }

// BuiltSummary reports whether the service writes the action's summary
// from its payload (the application gives none).
func BuiltSummary(action string) bool {
	switch action {
	case ActionProposalCreate, ActionVoteExtend, ActionAdminSetAdd, ActionAdminSetRemove, ActionAdminRepin:
		return true
	}
	return false
}

// Limits.
const (
	MaxSummary = 120      // bytes
	MaxPayload = 16 << 10 // bytes, canonical
	// MaxContext is the challenge context's bound (VAULT-MESSAGING §10.4).
	MaxContext = 256
	// RemindInterval: challenges go out at most this often per approval.
	// A challenge lasts at least this long (the connauth challenge life).
	RemindInterval = 10 * time.Minute
	// DefaultTTL is how long an approval stays open (SV_APPROVAL_TTL).
	DefaultTTL = 24 * time.Hour
)

// Error codes (Error.Code), as the API answers them.
const (
	CodeInvalidAction     = "invalid_action"
	CodeInvalidSummary    = "invalid_summary"
	CodeInvalidPayload    = "invalid_payload"
	CodeUnsupportedText   = "unsupported_characters" // a title or label outside printable ASCII and Latin-1 letters
	CodeFieldNotShown     = "field_not_shown"        // proposal.create, vote.extend: a field the admins' phones would not show
	CodeUnknownProposal   = "unknown_proposal"       // vote.extend: no such proposal
	CodeInvalidConnection = "invalid_connection"     // admin_set.*: not an active connection, not an admin, or already one
	CodeUnreachable       = "unreachable"            // the threshold is more than the admins there are (or would be)
	CodeSoleAdmin         = "sole_admin"             // admin.repin with one admin: the others can't confirm it (bootstrap instead)
	CodeLastAdmin         = "last_admin"             // admin_set.remove of the only admin
	CodeNotPending        = "not_pending"
	CodeTooSoon           = "too_soon"
	CodeNotAdmin          = "not_admin"         // remind force: not an admin of the approval, or no longer in the set
	CodeAnswered          = "answered"          // remind force: the admin has answered
	CodeNothingToRemind   = "nothing_to_remind" // every admin who has not answered holds a live challenge
	CodeAskBudget         = "ask_budget"        // no send: the admins to ask have 5 approval challenges still counting (askBudget)
	CodeRateLimited       = "rate_limited"      // Create: the limit of the action's group (RateLimit) is reached

	// Using an approval (Consume).
	CodeApprovalRequired    = "approval_required"     // no approval id
	CodeApprovalNotFound    = "approval_not_found"    // no such approval
	CodeApprovalNotApproved = "approval_not_approved" // pending, denied or expired: the threshold was not met
	CodeApprovalWrongAction = "approval_wrong_action" // approved for another action
	CodeApprovalMismatch    = "approval_mismatch"     // approved for other input than the one asked for
	CodeApprovalExpired     = "approval_expired"      // approved, but its life has run out
	CodeApprovalUsed        = "approval_used"         // already used
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
	// AskBudget: the admins left out because of the ask budget (askBudget).
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
}

// AskBudget is an admin not asked because 5 approval challenges still
// count (askBudget), and when that stops being so.
type AskBudget struct {
	ConnectionID string    `json:"connection_id"`
	NextAskAt    time.Time `json:"next_ask_at"` // oldest counting challenge's exp + 24 h + clock skew
}

// Approver is an admin's approval.
type Approver struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
	// KeyChanged: the admin signed with a credential key other than the
	// one pinned at their last sign-in that no rotation chain reaches
	// (§10.4).
	KeyChanged bool `json:"key_changed"`
	// GovKeyChanged: the key is not the admin's governance key, nor
	// reached from it by a rotation chain, or none is pinned. The
	// governance key moves only when the connection becomes an admin and
	// when the other admins approve admin.repin, so unlike KeyChanged it
	// stays set for every approval until then. It alone decides whether a
	// governance approval counts: KeyChanged compares with a key any
	// sign-in moves, so it can't.
	GovKeyChanged bool `json:"gov_key_changed"`
	// Counted: the approval counts toward the threshold. It does not when
	// GovKeyChanged is set on a governance action (Governance): the admin
	// can approve again once re-pinned.
	Counted bool `json:"counted"`
	// Reason, with Counted false: key_changed, key_changed or not_repinned.
	Reason string `json:"reason,omitempty"`

	legacy bool // read without a counted field (UnmarshalJSON)
}

// UnmarshalJSON reads an approval stored before Counted existed: it counted
// unless it carried a changed key.
func (a *Approver) UnmarshalJSON(b []byte) error {
	type plain Approver
	var p struct {
		plain
		Counted *bool `json:"counted"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*a = Approver(p.plain)
	// Before Counted existed an approval counted; one that carried a changed
	// key did not (fail closed).
	a.Counted = !a.KeyChanged
	if p.Counted != nil {
		a.Counted = *p.Counted
	} else {
		a.legacy = true // on a governance action, record.load sets it aside
	}
	return nil
}

// stands reports whether the approval counts for an action. It fails
// closed: a governance approval signed with a key other than the governance key never stands,
// whatever Counted says.
func (a Approver) stands(action string) bool {
	return a.Counted && !(a.GovKeyChanged && Governance(action))
}

// Denier is an admin's counted denial.
type Denier struct {
	ConnectionID string    `json:"connection_id"`
	At           time.Time `json:"at"`
}

// Status is what became of an approval.
type Status struct {
	ID         string `json:"approval_id"`
	Action     string `json:"action"`
	Summary    string `json:"summary"`
	ActionHash string `json:"action_hash"`
	// Payload is the canonical payload the hash covers (the service may
	// have added to it: admin.repin's new_key).
	Payload   json.RawMessage `json:"payload,omitempty"`
	Status    string          `json:"status"`
	Reason    string          `json:"reason,omitempty"` // with denied
	Threshold int             `json:"threshold"`
	Admins    []string        `json:"admins"` // the admins asked
	Approvals []Approver      `json:"approvals"`
	Denials   []Denier        `json:"denials"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	// AskBudget, while pending: those of RemindNeeded at the ask budget.
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
	// RemindNeeded, while pending: the admins asked who have not answered
	// and hold no live challenge (it ran out, or could not be sent), so
	// they see nothing on the phone until a reminder.
	RemindNeeded []string `json:"remind_needed"`
	// RemindAfter, with RemindNeeded: the earliest a reminder is accepted
	// (RemindInterval after the last challenges were sent).
	RemindAfter *time.Time `json:"remind_after,omitempty"`
	// Applied, for an approved admin_set.* action: whether the service
	// vault changed the admin set (false when it no longer applied, for
	// example the connection was removed meanwhile).
	Applied *bool `json:"applied,omitempty"`
	// Used, for a proposal.create or vote.extend approval that was used:
	// when, and what it was used for (the proposal made, or the proposal
	// extended and the extension's number), so that a lost answer is
	// resolved by reading what exists.
	Used *Used `json:"used,omitempty"`
}

// Used is a used approval's record.
type Used struct {
	At         time.Time `json:"at"`
	ProposalID string    `json:"proposal_id"`
	N          int64     `json:"n,omitempty"`
}

// Reminder answers a reminder.
type Reminder struct {
	ID       string   `json:"approval_id"`
	Reminded []string `json:"reminded"` // connection ids challenged again
	// AskBudget: the admins left out because of the ask budget.
	AskBudget []AskBudget `json:"ask_budget,omitempty"`
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
	// approval.consumed: what the approval was used for.
	ProposalID string `json:"proposal_id,omitempty"`
	N          int64  `json:"n,omitempty"`
	Added      string `json:"added,omitempty"`
	Removed    string `json:"removed,omitempty"`
	// Fingerprint, with gov_key.migrated: of the credential key pinned.
	Fingerprint string `json:"fingerprint,omitempty"`
	// KeyChangesSeen, with gov_key.migrated: the evidence showed a later
	// approval signed with another key, or reporting a key change.
	KeyChangesSeen bool `json:"key_changes_seen,omitempty"`
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
	// What the service itself writes at the front of a vote's summary, and
	// the labels it puts before every summary, are not for an application
	// to start its own with.
	low := strings.ToLower(strings.TrimSpace(s))
	for _, w := range reservedStarts() {
		if strings.HasPrefix(low, w) {
			return errCode(CodeInvalidSummary)
		}
	}
	return nil
}

func reservedStarts() []string {
	out := []string{"binding", "advisory", "extend"}
	for _, l := range ActionLabels {
		out = append(out, strings.ToLower(strings.TrimSuffix(l, ":")))
	}
	return out
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
// "Approve on <service>: <label> <summary> — ref <first 16 hex of the
// hash>", the label being the action's (ActionLabels). An application's
// summary is cut (on a character boundary, ending in "…") so that the
// whole is at most MaxContext bytes; a summary the service built from a
// payload is never cut: if it does not fit, that is an error.
func ChallengeContext(serviceName, action, summary, actionHash string) (string, error) {
	if len(actionHash) < RefLen {
		return "", fmt.Errorf("approval: short action hash")
	}
	label := ActionLabels[action]
	if label == "" {
		return "", fmt.Errorf("approval: no label for action %q", action)
	}
	f := func(s string) string {
		return fmt.Sprintf("Approve on %s: %s %s — ref %s", serviceName, label, s, actionHash[:RefLen])
	}
	if s := f(summary); len(s) <= MaxContext {
		return s, nil
	}
	if builtSummary(action) {
		return "", fmt.Errorf("approval: the summary does not fit the challenge's context")
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
// It takes the entry's identity keys as given: an auditor also checks
// that service_ik is this service's identity key and member_ik the
// admin connection's.
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
