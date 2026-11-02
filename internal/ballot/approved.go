package ballot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/service-vault/vote"
)

// Approved actions. A proposal is created, and a vote extended, only
// with the admins' m-of-n approval of the exact input (MEMBER-SERVICE-PLAN
// §4.5), used once.
//
// The approval's payload is the input in its canonical form: the RFC 8785
// (JCS) form of the input with every field present, as the structs below
// marshal. The payload is parsed strictly (no duplicate names, no byte
// order mark, no unpaired surrogate escape, no unknown or differently
// cased name), so that the bytes the admins approved, the bytes compared
// when the approval is used and the input that is executed are the same.
const (
	ActionProposalCreate = "proposal.create"
	ActionVoteExtend     = "vote.extend"
)

// Approvals checks and uses the admins' approvals (approval.Manager).
type Approvals interface {
	// Consume uses an approval once, for action with exactly payload
	// (canonical): it fails unless the approval is approved, is for this
	// action and payload, and has not been used.
	Consume(ctx context.Context, approvalID, action string, payload []byte) error
}

// ErrNoApprovals is a service vault with no way to check approvals: it
// creates and extends nothing.
var ErrNoApprovals = errors.New("ballot: approvals can't be checked here")

// ExtensionPayload is the input of a vote.extend approval: the extension
// asked for and the proposal it is for.
type ExtensionPayload struct {
	ProposalID string      `json:"proposal_id"`
	ClosesAt   int64       `json:"closes_at"`
	Outage     vote.Outage `json:"outage"`
}

// canonical returns the canonical form of v with every field present.
func canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return servicevault.CanonicalJSON(raw)
}

// CanonicalProposal is the payload of a proposal.create approval for in.
func CanonicalProposal(in ProposalInput) ([]byte, error) { return canonical(in) }

// CanonicalExtension is the payload of a vote.extend approval for an
// extension of proposal id.
func CanonicalExtension(id string, in ExtensionInput) ([]byte, error) {
	return canonical(ExtensionPayload{ProposalID: id, ClosesAt: in.ClosesAt, Outage: in.Outage})
}

// parseCanonical parses payload into v, which must be a pointer to a
// struct, and reports an error unless payload is exactly the canonical
// form of what it parsed.
func parseCanonical(payload []byte, v any) error {
	c, err := servicevault.CanonicalJSON(payload)
	if err != nil || !bytes.Equal(c, payload) {
		return errors.New("ballot: payload is not in canonical form")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	back, err := canonical(v)
	if err != nil || !bytes.Equal(back, payload) {
		return errors.New("ballot: payload is not the full form of its input")
	}
	return nil
}

// What a proposal.create approval's payload carries, field by field
// (BALLOT-PROTOCOL §3.4): the fields shown to the admins (title, choices'
// labels, binding, removed_may_vote, opens_at, closes_at, quorum's
// min_ballots), the fields the service sets (the choice ids, the default
// abstain choice, outage_rule, record_at, the roster) and the fields it
// refuses unless they say what the service would set anyway (text, quorum
// text, outage_rule).
const (
	// DefaultOutageRule is the outage_rule of every proposal (§10.2): the
	// only value accepted, or empty.
	DefaultOutageRule = "Extended by a relay outage over 1 hour, 24 h at most."
	// MaxLabelRunes is the longest choice label (the admins read it whole).
	MaxLabelRunes = 24
	// MaxSource is the longest outage source of an extension (the admins
	// read it whole).
	MaxSource = 32
	// MaxRealChoices is the most choices an application may list; the
	// service adds abstain.
	MaxRealChoices = 16
)

// Limits of the summary the admins read: a challenge's context holds 256
// bytes (VAULT-MESSAGING §10.4), and the service's name (at most
// approval.MaxServiceName), the action's label, the framing and the ref
// take the rest. A summary is shown whole or refused, never cut.
const (
	maxSummaryFixed = 115 // everything but the title
	maxSummary      = 165 // the whole; the title is cut to fit
)

var errTooLong = errors.New("ballot: too long to show the admins")

// ErrNotShown is a field the admins' phones would not show, and that is
// not what the service sets: it can't be part of an approved action.
type ErrNotShown struct{ Field string }

func (e *ErrNotShown) Error() string { return "ballot: " + e.Field + " is not shown to the admins" }

// plain accepts text that can be shown: valid UTF-8 with no control,
// line-separator or bidirectional-control characters.
func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\u061c' || r == '\u200e' || r == '\u200f' ||
			r >= '\u202a' && r <= '\u202e' || r >= '\u2066' && r <= '\u2069' {
			return false
		}
	}
	return true
}

func when(t int64) (string, error) {
	if t < 946684800 || t > 7258118400 { // years 2000 to 2200
		return "", errors.New("ballot: time out of range")
	}
	return time.Unix(t, 0).UTC().Format("2006-01-02 15:04Z"), nil
}

// checkInput refuses what an approval can't carry: a field the admins
// would not see that isn't the service's own, choice labels that can't be
// shown whole or that the admins could mix up, or a time the summary can't
// print. Create and the summary both call it, so what is approved is
// what can be executed.
func checkInput(in *ProposalInput) error {
	if !plain(in.Title) || strings.TrimSpace(in.Title) == "" || len(in.Title) > 200 {
		return errors.New("ballot: the title can't be shown")
	}
	if in.Text != "" && in.Text != in.Title {
		return &ErrNotShown{"text"}
	}
	if in.Quorum.Text != "" {
		return &ErrNotShown{"quorum.text"}
	}
	if in.OutageRule != "" && in.OutageRule != DefaultOutageRule {
		return &ErrNotShown{"outage_rule"}
	}
	if len(in.Choices) < 2 || len(in.Choices) > MaxRealChoices {
		return errors.New("ballot: two to sixteen choices")
	}
	seen := map[string]bool{}
	for _, c := range in.Choices {
		l := c.Label
		key := strings.ToLower(l)
		switch {
		case !plain(l) || l == "" || l != strings.TrimSpace(l):
			return errors.New("ballot: a choice label can't be shown")
		case utf8.RuneCountInString(l) > MaxLabelRunes:
			return errors.New("ballot: a choice label is over 24 characters")
		case key == "abstain" || seen[key]:
			return errors.New("ballot: choice labels must be distinct, and none is Abstain")
		}
		seen[key] = true
	}
	if in.Quorum.MinBallots < 0 {
		return errors.New("ballot: negative quorum")
	}
	return nil
}

// ProposalSummary is what the admins read when asked to approve a
// proposal.create payload: whether the vote is binding, its window, its
// quorum, its choices and its title, all taken from the payload, after
// the action's label (approval.ActionLabel). It is an error unless the
// payload is the canonical full form of a proposal input that checkInput
// accepts.
func ProposalSummary(payload []byte) (string, error) {
	var in ProposalInput
	if err := parseCanonical(payload, &in); err != nil {
		return "", err
	}
	if err := checkInput(&in); err != nil {
		return "", err
	}
	opens, err := when(in.OpensAt)
	if err != nil {
		return "", err
	}
	closes, err := when(in.ClosesAt)
	if err != nil {
		return "", err
	}
	labels := make([]string, 0, len(in.Choices))
	for _, c := range in.Choices {
		labels = append(labels, strconv.Quote(c.Label))
	}
	kind := "ADVISORY"
	if in.Binding {
		kind = "BINDING"
	}
	head := fmt.Sprintf("%s, opens %s, closes %s, quorum %d, choices %s", kind, opens, closes, in.Quorum.MinBallots,
		strings.Join(labels, "/"))
	if in.RemovedMayVote {
		head += ", removed may vote"
	}
	head += ", title "
	if len(head) > maxSummaryFixed {
		return "", errTooLong
	}
	return head + quoteFit(in.Title, maxSummary-len(head)), nil
}

// quoteFit is s quoted, its end cut (and marked with …) so that the
// whole is at most n bytes.
func quoteFit(s string, n int) string {
	if q := strconv.Quote(s); len(q) <= n {
		return q
	}
	for room := n; room > 0; room-- {
		c := strings.TrimSuffix(strconv.Quote(cutBytes(s, room)), `"`) + `…"`
		if len(c) <= n {
			return c
		}
	}
	return `"…"`
}

// cutBytes cuts s to at most n bytes on a character boundary.
func cutBytes(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// ExtensionProposalID is the proposal a vote.extend payload is for.
func ExtensionProposalID(payload []byte) (string, error) {
	var x ExtensionPayload
	if err := parseCanonical(payload, &x); err != nil {
		return "", err
	}
	if err := checkExtension(&x); err != nil {
		return "", err
	}
	return x.ProposalID, nil
}

func checkExtension(x *ExtensionPayload) error {
	if len(x.ProposalID) != 26 || strings.Trim(x.ProposalID, "0123456789ABCDEFGHJKMNPQRSTVWXYZ") != "" {
		return errors.New("ballot: bad proposal id")
	}
	src := x.Outage.Source
	if !strings.HasPrefix(src, "https://") || !plain(src) || strings.ContainsAny(src, " \"") {
		return &ErrNotShown{"outage.source"}
	}
	if len(src) > MaxSource {
		return &ErrNotShown{"outage.source"}
	}
	return nil
}

// ExtensionSummary is what the admins read when asked to approve a
// vote.extend payload for the proposal titled title: the proposal (its
// title, quoted, and its id), the new close, the outage and its source,
// from the payload and the stored proposal.
func ExtensionSummary(payload []byte, title string) (string, error) {
	var x ExtensionPayload
	if err := parseCanonical(payload, &x); err != nil {
		return "", err
	}
	if err := checkExtension(&x); err != nil {
		return "", err
	}
	if !plain(title) || title == "" {
		return "", errors.New("ballot: the proposal's title can't be shown")
	}
	closes, err := when(x.ClosesAt)
	if err != nil {
		return "", err
	}
	from, err := when(x.Outage.From)
	if err != nil {
		return "", err
	}
	to, err := when(x.Outage.To)
	if err != nil {
		return "", err
	}
	tail := fmt.Sprintf(" (%s) new close %s, outage %s to %s, source %s", x.ProposalID, closes, from, to, x.Outage.Source)
	if len(tail) > maxSummaryFixed+MaxSource {
		return "", errTooLong
	}
	return quoteFit(title, maxSummary-len(tail)) + tail, nil
}

// SummaryFor builds the summary of an approval for action from payload
// (and, for vote.extend, the proposal's title); ok is false for an
// action whose summary the application writes.
func SummaryFor(action string, payload []byte, title string) (summary string, ok bool, err error) {
	switch action {
	case ActionProposalCreate:
		summary, err = ProposalSummary(payload)
	case ActionVoteExtend:
		summary, err = ExtensionSummary(payload, title)
	default:
		return "", false, nil
	}
	return summary, true, err
}

// consume uses the approval for action and payload, or fails closed.
func (m *Manager) consume(ctx context.Context, approvalID, action string, payload []byte) error {
	if m.Approvals == nil {
		return ErrNoApprovals
	}
	return m.Approvals.Consume(ctx, approvalID, action, payload)
}
