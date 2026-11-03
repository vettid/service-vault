package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
)

// usedRecord is an apv_used record: an approval that was used.
type usedRecord struct {
	At time.Time `json:"at"`
	// What the approval was used for (ballot.Use): the proposal made, or
	// the proposal extended and the extension's number.
	ProposalID string `json:"proposal_id,omitempty"`
	N          int64  `json:"n,omitempty"`
}

// Consume uses an approved proposal.create or vote.extend approval, once,
// for the exact input it approved (BALLOT-PROTOCOL §3, §10.2). Under the
// manager's lock it checks that the approval is approved (its threshold
// met by the admins still in the set), is for this action, carries exactly payload (the canonical bytes
// of the input about to be executed, compared byte for byte) and has not
// run out; then it writes the apv_used record with IfAbsent together with
// an approval.consumed audit entry, in one batch. Of any number of
// concurrent calls for one approval, one succeeds. A call with use.Retry
// for the same proposal and number of an approval already used for them
// returns nil: it is a retry of that use, and nothing more is written.
//
// The caller executes only after Consume returns nil. Whatever fails
// after that leaves the approval used (fail closed): the admins approve
// again. A call that fails leaves the approval as it was, usable, except
// that a store error may leave it unknown whether the write happened, and
// then the approval is used or unused but never both.
//
// use says what the caller is about to make: the new proposal's id, or the
// proposal and the number of the extension. It is kept in the apv_used
// record and the audit entry, so that a lost answer or a crash is
// resolved by reading what the approval made (Status.Used).
func (m *Manager) Consume(ctx context.Context, id, action string, payload []byte, use ballot.Use) error {
	if action != ActionProposalCreate && action != ActionVoteExtend {
		return errCode(CodeInvalidAction)
	}
	if id == "" {
		return errCode(CodeApprovalRequired)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.load(ctx, id)
	if err != nil {
		return err
	}
	now := m.now()
	switch {
	case r == nil:
		return errCode(CodeApprovalNotFound)
	case r.Status != StatusApproved:
		return errCode(CodeApprovalNotApproved)
	case r.Action != action:
		return errCode(CodeApprovalWrongAction)
	case len(payload) == 0 || !bytes.Equal(r.Payload, payload):
		return errCode(CodeApprovalMismatch)
	}
	// A caller that says it repeats a use (use.Retry) and finds the
	// approval already used for exactly that proposal and number has the
	// same use, not a second one.
	if use.Retry {
		if u, used, err := m.usedBy(ctx, id); err != nil {
			return err
		} else if used {
			if u.ProposalID == use.ProposalID && u.N == use.N {
				return nil
			}
			return errCode(CodeApprovalUsed)
		}
	}
	if !now.Before(r.Exp) {
		return errCode(CodeApprovalExpired)
	}
	// Recount: an admin removed since approving no longer stands behind
	// the action, so the signatures of the current admin set (not those of a changed key) must still
	// meet the threshold, the approval's own or the current one if higher.
	set, err := m.admins(ctx)
	if err != nil {
		return err
	}
	n := r.standing(set)
	if n < m.needed(r, set) {
		return errCode(CodeApprovalNotApproved)
	}
	// The summary the admins read must be the one the service builds from
	// the payload (and, for an extension, the stored proposal's title):
	// an approval made with a summary an application wrote is refused.
	title := ""
	if action == ActionVoteExtend {
		pid, err := ballot.ExtensionProposalID(payload)
		if err != nil || m.ProposalTitle == nil {
			return errCode(CodeApprovalMismatch)
		}
		t, ok, err := m.ProposalTitle(ctx, pid)
		if err != nil {
			return err
		}
		if !ok {
			return errCode(CodeApprovalMismatch)
		}
		title = t
	}
	if want, _, err := ballot.SummaryFor(action, payload, title); err != nil || want != r.Summary {
		return errCode(CodeApprovalMismatch)
	}
	if use.ProposalID == "" {
		return errCode(CodeApprovalMismatch)
	}
	if _, used, err := m.Store.Get(ctx, kindUsed, id); err != nil {
		return err
	} else if used {
		return errCode(CodeApprovalUsed)
	}
	b := m.batch(now)
	if err := b.putNew(kindUsed, id, &usedRecord{At: now.UTC().Truncate(time.Millisecond), ProposalID: use.ProposalID, N: use.N}); err != nil {
		return err
	}
	if err := b.audit(&AuditEntry{Type: AuditConsumed, ApprovalID: r.ID, Action: r.Action, ActionHash: r.Hash,
		ProposalID: use.ProposalID, N: use.N}); err != nil {
		return err
	}
	if err := b.apply(ctx); errors.Is(err, peer.ErrConflict) {
		return errCode(CodeApprovalUsed) // another process used it meanwhile
	} else if err != nil {
		return err
	}
	m.log().Info("approval used", "approval_id", id, "action", action)
	return nil
}

// usedBy returns the use recorded for an approval already used.
func (m *Manager) usedBy(ctx context.Context, id string) (usedRecord, bool, error) {
	var u usedRecord
	data, ok, err := m.Store.Get(ctx, kindUsed, id)
	if err != nil || !ok {
		return u, false, err
	}
	if err := json.Unmarshal(data, &u); err != nil {
		return u, false, err
	}
	return u, true, nil
}
