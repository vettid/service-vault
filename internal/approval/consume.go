package approval

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/vettid/service-vault/internal/peer"
)

// usedRecord is an apv_used record: an approval that was used.
type usedRecord struct {
	At time.Time `json:"at"`
}

// Consume uses an approved proposal.create or vote.extend approval, once,
// for the exact input it approved (BALLOT-PROTOCOL §3, §10.2). Under the
// manager's lock it checks that the approval is approved (its threshold
// met), is for this action, carries exactly payload (the canonical bytes
// of the input about to be executed, compared byte for byte) and has not
// run out; then it writes the apv_used record with IfAbsent together with
// an approval.consumed audit entry, in one batch. Of any number of
// concurrent calls for one approval, one succeeds.
//
// The caller executes only after Consume returns nil. Whatever fails
// after that leaves the approval used (fail closed): the admins approve
// again. A call that fails leaves the approval as it was, usable, except
// that a store error may leave it unknown whether the write happened, and
// then the approval is used or unused but never both.
func (m *Manager) Consume(ctx context.Context, id, action string, payload []byte) error {
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
	case !now.Before(r.Exp):
		return errCode(CodeApprovalExpired)
	}
	if _, used, err := m.Store.Get(ctx, kindUsed, id); err != nil {
		return err
	} else if used {
		return errCode(CodeApprovalUsed)
	}
	b := m.batch(now)
	if err := b.putNew(kindUsed, id, &usedRecord{At: now.UTC().Truncate(time.Millisecond)}); err != nil {
		return err
	}
	if err := b.audit(&AuditEntry{Type: AuditConsumed, ApprovalID: r.ID, Action: r.Action, ActionHash: r.Hash}); err != nil {
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
