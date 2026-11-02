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

// Limits of the summary the admins read (a challenge's context holds 256
// bytes, VAULT-MESSAGING §10.4; the service's name, the ref and the
// framing take some).
const (
	maxSummaryFixed = 150 // everything but the title
	maxSummary      = 190 // the whole; the title is cut to fit
	maxLabelRunes   = 24
)

var errTooLong = errors.New("ballot: too long to show the admins")

// plain accepts text that can be shown: valid UTF-8 with no control,
// line-separator or bidirectional-control characters.
func plain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || r == '؜' || r == '‎' || r == '‏' ||
			r >= '‪' && r <= '‮' || r >= '⁦' && r <= '⁩' {
			return false
		}
	}
	return true
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

func when(t int64) (string, error) {
	if t < 946684800 || t > 7258118400 { // years 2000 to 2200
		return "", errors.New("ballot: time out of range")
	}
	return time.Unix(t, 0).UTC().Format("2006-01-02 15:04Z"), nil
}

// ProposalSummary is what the admins read when asked to approve a
// proposal.create payload: whether the vote is binding, its window, its
// quorum, its choices and its title, all taken from the payload. It is an
// error unless the payload is the canonical full form of a proposal input.
func ProposalSummary(payload []byte) (string, error) {
	var in ProposalInput
	if err := parseCanonical(payload, &in); err != nil {
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
	if !plain(in.Title) || strings.TrimSpace(in.Title) == "" {
		return "", errors.New("ballot: the title can't be shown")
	}
	labels := make([]string, 0, len(in.Choices))
	for _, c := range in.Choices {
		if !plain(c.Label) || c.Label == "" {
			return "", errors.New("ballot: a choice label can't be shown")
		}
		labels = append(labels, strconv.Quote(cutRunes(c.Label, maxLabelRunes)))
	}
	kind := "ADVISORY"
	if in.Binding {
		kind = "BINDING"
	}
	head := fmt.Sprintf("%s vote opens %s closes %s, quorum %d, choices %s", kind, opens, closes, in.Quorum.MinBallots,
		strings.Join(labels, "/"))
	if in.RemovedMayVote {
		head += ", removed members may vote"
	}
	head += ", title "
	if len(head) > maxSummaryFixed {
		return "", errTooLong
	}
	title := strconv.Quote(in.Title)
	if len(head)+len(title) > maxSummary {
		room := maxSummary - len(head) - len(`"…"`)
		title = strconv.Quote(cutBytes(in.Title, room))
		title = strings.TrimSuffix(title, `"`) + `…"`
	}
	return head + title, nil
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

// ExtensionSummary is what the admins read when asked to approve a
// vote.extend payload: the proposal and the new close, from the payload.
func ExtensionSummary(payload []byte) (string, error) {
	var x ExtensionPayload
	if err := parseCanonical(payload, &x); err != nil {
		return "", err
	}
	if len(x.ProposalID) != 26 || !plain(x.ProposalID) || strings.ContainsAny(x.ProposalID, " \"") {
		return "", errors.New("ballot: bad proposal id")
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
	return fmt.Sprintf("EXTEND vote %s: new close %s, for an outage from %s to %s", x.ProposalID, closes, from, to), nil
}

// SummaryFor builds the summary of an approval for action from payload;
// ok is false for an action whose summary the application writes.
func SummaryFor(action string, payload []byte) (summary string, ok bool, err error) {
	switch action {
	case ActionProposalCreate:
		summary, err = ProposalSummary(payload)
	case ActionVoteExtend:
		summary, err = ExtensionSummary(payload)
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
