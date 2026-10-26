package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Record kinds the manager keeps in the peer's store (DynamoDB in a
// deployment).
const (
	kindApproval = "apv"       // an approval
	kindOpen     = "apv_open"  // approval id -> "" while it is pending
	kindReq      = "apv_req"   // challenge request id -> approval id
	kindSeen     = "apv_seen"  // peer event id -> "": an answer already handled
	kindHook     = "apv_hook"  // a webhook event waiting to be delivered
	kindAdmins   = "admin_set" // "admins" -> the admin set
	// KindAudit is the append-only audit log: one record per entry, by
	// increasing id, written once (IfAbsent), never updated or deleted.
	KindAudit = "audit"

	adminsID      = "admins"
	seenRetention = 16 * 24 * time.Hour // as the peer's dedupe markers (VAULT-MESSAGING §8)
	reqRetention  = 24 * time.Hour      // past the approval's expiry
)

// Peer is the part of peer.Peer the manager uses.
type Peer interface {
	Connection(id string) (peer.ConnectionInfo, bool)
	Authenticate(ctx context.Context, connID, ctxt string, ttl time.Duration) (string, error)
	CancelChallenge(ctx context.Context, requestID string) (bool, error)
}

// Webhooks delivers webhook events (webhook.Dispatcher).
type Webhooks interface {
	Deliver(ctx context.Context, e *webhook.Event) error
}

// Pager reads an append-only kind in id order (store.Table, peer.MemStore).
type Pager interface {
	Page(ctx context.Context, kind, after string, limit int) ([]peer.Record, error)
}

// Manager runs approvals. It assumes it is the only writer of its
// records (one task runs the service vault) and serializes its work.
type Manager struct {
	Peer     Peer
	Store    peer.Store
	Pager    Pager
	Webhooks Webhooks
	// ServiceName is named in the challenge's context.
	ServiceName string
	// Threshold is m: how many distinct admins must approve
	// (SV_ADMIN_THRESHOLD, default 1). An approval keeps the threshold
	// it was created with.
	Threshold int
	// TTL is how long an approval stays open (SV_APPROVAL_TTL, default
	// DefaultTTL).
	TTL time.Duration
	// BootstrapKey is the email index key of SV_ADMIN_BOOTSTRAP_EMAIL
	// ("" for none): while the admin set is empty, the connection bound
	// to it becomes the first admin.
	BootstrapKey string
	// BoundConnection returns the connection bound to an email index key.
	BoundConnection func(ctx context.Context, emailKey string) (string, bool, error)
	Now             func() time.Time
	Log             *slog.Logger

	mu      sync.Mutex
	flushMu sync.Mutex
	lastID  string
	kick    chan struct{}
	once    sync.Once
}

// record is a stored approval.
type record struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Summary   string            `json:"summary"`
	Payload   json.RawMessage   `json:"payload"` // canonical
	Hash      string            `json:"action_hash"`
	Status    string            `json:"status"`
	Reason    string            `json:"reason,omitempty"`
	Threshold int               `json:"threshold"`
	Admins    []string          `json:"admins"` // the admin set when it was created
	Created   time.Time         `json:"created"`
	Exp       time.Time         `json:"exp"`
	LastSent  time.Time         `json:"last_sent"`
	Approvals []Approver        `json:"approvals,omitempty"`
	Denials   []Denier          `json:"denials,omitempty"`
	Pending   map[string]string `json:"pending,omitempty"` // admin connection id -> its outstanding challenge
	Applied   *bool             `json:"applied,omitempty"`
	Settled   time.Time         `json:"settled,omitzero"`
}

func (r *record) answered(connID string) bool {
	return slices.ContainsFunc(r.Approvals, func(a Approver) bool { return a.ConnectionID == connID }) ||
		slices.ContainsFunc(r.Denials, func(d Denier) bool { return d.ConnectionID == connID })
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Manager) log() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

func (m *Manager) threshold() int { return max(m.Threshold, 1) }

func (m *Manager) ttl() time.Duration {
	if m.TTL > 0 {
		return m.TTL
	}
	return DefaultTTL
}

// nextID returns a fresh ULID greater than every id it returned before,
// so the audit log reads in the order it was written.
func (m *Manager) nextID(now time.Time) (string, error) {
	id, err := envelope.NewULID(now)
	if err != nil {
		return "", err
	}
	if id <= m.lastID {
		id = incrementULID(m.lastID)
	}
	m.lastID = id
	return id, nil
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func incrementULID(s string) string {
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		j := 0
		for j < len(crockford) && crockford[j] != b[i] {
			j++
		}
		if j+1 < len(crockford) {
			b[i] = crockford[j+1]
			return string(b)
		}
		b[i] = '0'
	}
	return string(b)
}

// batch collects the changes of one step, written all or nothing.
type batch struct {
	m       *Manager
	now     time.Time
	changes []peer.Change
}

func (m *Manager) batch(now time.Time) *batch { return &batch{m: m, now: now} }

func (b *batch) put(kind, id string, v any, exp time.Time) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, peer.Change{Kind: kind, ID: id, Data: data, Expires: exp})
	return nil
}

func (b *batch) del(kind, id string) { b.changes = append(b.changes, peer.Change{Kind: kind, ID: id}) }

func (b *batch) audit(e *AuditEntry) error {
	id, err := b.m.nextID(b.now)
	if err != nil {
		return err
	}
	e.ID, e.At = id, b.now.UTC().Truncate(time.Millisecond)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, peer.Change{Kind: KindAudit, ID: id, Data: data, IfAbsent: true})
	return nil
}

func (b *batch) hook(typ, connID string, data any) error {
	id, err := b.m.nextID(b.now)
	if err != nil {
		return err
	}
	e := &webhook.Event{ID: id, Type: typ, ConnectionID: connID, CreatedAt: b.now.UTC().Truncate(time.Second)}
	if e.Data, err = json.Marshal(data); err != nil {
		return err
	}
	return b.put(kindHook, id, e, time.Time{})
}

func (b *batch) apply(ctx context.Context) error { return b.m.Store.Apply(ctx, b.changes) }

func (m *Manager) admins(ctx context.Context) ([]string, error) {
	data, ok, err := m.Store.Get(ctx, kindAdmins, adminsID)
	if err != nil || !ok {
		return nil, err
	}
	var v struct {
		Admins []string `json:"admins"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v.Admins, nil
}

func (b *batch) setAdmins(set []string) error {
	slices.Sort(set)
	return b.put(kindAdmins, adminsID, map[string][]string{"admins": set}, time.Time{})
}

// adminSetChanged records a change of the admin set: the set itself, the
// audit entry and the admin_set.changed webhook.
func (b *batch) adminSetChanged(set []string, added, removed, reason, approvalID string) error {
	if set == nil {
		set = []string{}
	}
	if err := b.setAdmins(set); err != nil {
		return err
	}
	if err := b.audit(&AuditEntry{Type: AuditAdminSetChanged, ApprovalID: approvalID, Admins: set, Added: added,
		Removed: removed, Reason: reason}); err != nil {
		return err
	}
	data := map[string]any{"admins": set, "reason": reason}
	if added != "" {
		data["added"] = added
	}
	if removed != "" {
		data["removed"] = removed
	}
	if approvalID != "" {
		data["approval_id"] = approvalID
	}
	return b.hook(EventAdminSetChanged, added+removed, data)
}

func (m *Manager) load(ctx context.Context, id string) (*record, error) {
	data, ok, err := m.Store.Get(ctx, kindApproval, id)
	if err != nil || !ok {
		return nil, err
	}
	r := &record{}
	if err := json.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

func (b *batch) save(r *record) error { return b.put(kindApproval, r.ID, r, time.Time{}) }

func (m *Manager) active(connID string) bool {
	c, ok := m.Peer.Connection(connID)
	return ok && c.State == peer.StateActive
}

type connPayload struct {
	ConnectionID string `json:"connection_id"`
}

func adminSetTarget(payload json.RawMessage) (string, error) {
	var p connPayload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || p.ConnectionID == "" {
		return "", errCode(CodeInvalidPayload)
	}
	return p.ConnectionID, nil
}

// Create submits an action for approval: it is checked and hashed, and
// a challenge goes to every admin. It returns the approval's id and hash.
func (m *Manager) Create(ctx context.Context, req Request) (*Created, error) {
	if !actions[req.Action] {
		return nil, errCode(CodeInvalidAction)
	}
	if err := checkSummary(req.Summary); err != nil {
		return nil, err
	}
	payload, err := servicevault.CanonicalJSON(req.Payload)
	if err != nil || len(payload) == 0 || payload[0] != '{' || len(payload) > MaxPayload {
		return nil, errCode(CodeInvalidPayload)
	}
	hash, err := servicevault.ActionHash(req.Action, req.Summary, payload)
	if err != nil {
		return nil, errCode(CodeInvalidPayload)
	}
	ctxt, err := ChallengeContext(m.ServiceName, req.Summary, hash)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	set, err := m.admins(ctx)
	if err != nil {
		return nil, err
	}
	th := m.threshold()
	switch req.Action {
	case ActionAdminSetAdd:
		target, err := adminSetTarget(payload)
		if err != nil {
			return nil, err
		}
		if slices.Contains(set, target) || !m.active(target) {
			return nil, errCode(CodeInvalidConnection)
		}
	case ActionAdminSetRemove:
		target, err := adminSetTarget(payload)
		if err != nil {
			return nil, err
		}
		switch {
		case !slices.Contains(set, target):
			return nil, errCode(CodeInvalidConnection)
		case len(set) == 1:
			return nil, errCode(CodeLastAdmin)
		case len(set)-1 < th:
			return nil, errCode(CodeUnreachable)
		}
	}
	if th > len(set) {
		return nil, errCode(CodeUnreachable)
	}
	now := m.now()
	id, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	r := &record{ID: id, Action: req.Action, Summary: req.Summary, Payload: payload, Hash: hash, Status: StatusPending,
		Threshold: th, Admins: slices.Clone(set), Created: now.UTC().Truncate(time.Millisecond),
		Exp: now.Add(m.ttl()).UTC().Truncate(time.Second), LastSent: now, Pending: map[string]string{}}
	b := m.batch(now)
	sent := m.challenge(ctx, b, r, set, ctxt)
	exp := r.Exp
	if err := errors.Join(b.save(r), b.put(kindOpen, id, "", time.Time{}), b.audit(&AuditEntry{Type: AuditRequested,
		ApprovalID: id, Action: r.Action, Summary: r.Summary, ActionHash: hash, Payload: payload, Threshold: th,
		ExpiresAt: &exp, Admins: r.Admins, Challenges: sent})); err != nil {
		return nil, err
	}
	if err := b.apply(ctx); err != nil {
		m.cancel(ctx, sent)
		return nil, err
	}
	m.log().Info("approval requested", "approval_id", id, "action", r.Action, "threshold", th, "admins", len(set),
		"challenged", len(sent))
	return &Created{ID: id, ActionHash: hash, Status: StatusPending, ExpiresAt: r.Exp}, nil
}

// challenge sends the approval's challenge to each of conns (each with
// the connauth maximum life, 10 minutes) and records the request ids.
// An admin who cannot be reached now is skipped (and can be reminded).
func (m *Manager) challenge(ctx context.Context, b *batch, r *record, conns []string, ctxt string) []Challenge {
	var sent []Challenge
	for _, c := range conns {
		reqID, err := m.Peer.Authenticate(ctx, c, ctxt, 0)
		if err != nil {
			m.log().Warn("approval challenge", "approval_id", r.ID, "connection_id", c, "err", errName(err))
			continue
		}
		r.Pending[c] = reqID
		b.changes = append(b.changes, peer.Change{Kind: kindReq, ID: reqID, Data: []byte(r.ID),
			Expires: r.Exp.Add(reqRetention)})
		sent = append(sent, Challenge{ConnectionID: c, RequestID: reqID})
	}
	return sent
}

func (m *Manager) cancel(ctx context.Context, chs []Challenge) {
	for _, c := range chs {
		if _, err := m.Peer.CancelChallenge(ctx, c.RequestID); err != nil {
			m.log().Warn("approval cancel", "request_id", c.RequestID, "err", errName(err))
		}
	}
}

func errName(err error) string {
	switch {
	case errors.Is(err, peer.ErrLimit):
		return "limit"
	case errors.Is(err, peer.ErrNotFound):
		return "not_found"
	case errors.Is(err, peer.ErrNotStarted):
		return "not_started"
	}
	return "error"
}

// Status reports an approval; ErrNotFound for an unknown id.
func (m *Manager) Status(ctx context.Context, id string) (*Status, error) {
	r, err := m.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrNotFound
	}
	st := &Status{ID: r.ID, Action: r.Action, Summary: r.Summary, ActionHash: r.Hash, Status: r.Status, Reason: r.Reason,
		Threshold: r.Threshold, Admins: r.Admins, Approvals: r.Approvals, Denials: r.Denials, CreatedAt: r.Created,
		ExpiresAt: r.Exp, Applied: r.Applied}
	if st.Status == StatusPending && !m.now().Before(r.Exp) {
		st.Status = StatusExpired
	}
	if st.Approvals == nil {
		st.Approvals = []Approver{}
	}
	if st.Denials == nil {
		st.Denials = []Denier{}
	}
	return st, nil
}

// ErrNotFound is an unknown approval.
var ErrNotFound = errors.New("approval: not found")

// Remind sends the challenge again to the admins who have not answered,
// at most once per RemindInterval per approval (the creation counts).
func (m *Manager) Remind(ctx context.Context, id string) (*Reminder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, ErrNotFound
	}
	now := m.now()
	if r.Status != StatusPending || !now.Before(r.Exp) {
		return nil, errCode(CodeNotPending)
	}
	if now.Before(r.LastSent.Add(RemindInterval)) {
		return nil, errCode(CodeTooSoon)
	}
	set, err := m.admins(ctx)
	if err != nil {
		return nil, err
	}
	var to []Challenge
	var conns []string
	for _, a := range r.Admins {
		if slices.Contains(set, a) && !r.answered(a) {
			conns = append(conns, a)
			if old := r.Pending[a]; old != "" {
				to = append(to, Challenge{ConnectionID: a, RequestID: old})
				delete(r.Pending, a)
			}
		}
	}
	m.cancel(ctx, to)
	ctxt, err := ChallengeContext(m.ServiceName, r.Summary, r.Hash)
	if err != nil {
		return nil, err
	}
	if r.Pending == nil {
		r.Pending = map[string]string{}
	}
	b := m.batch(now)
	sent := m.challenge(ctx, b, r, conns, ctxt)
	r.LastSent = now
	if err := errors.Join(b.save(r), b.audit(&AuditEntry{Type: AuditReminded, ApprovalID: r.ID, Challenges: sent})); err != nil {
		return nil, err
	}
	if err := b.apply(ctx); err != nil {
		m.cancel(ctx, sent)
		return nil, err
	}
	out := &Reminder{ID: r.ID, Reminded: []string{}}
	for _, c := range sent {
		out.Reminded = append(out.Reminded, c.ConnectionID)
	}
	m.log().Info("approval reminded", "approval_id", r.ID, "challenged", len(sent))
	return out, nil
}

// Admins returns the admin set and the threshold.
func (m *Manager) Admins(ctx context.Context) (*Admins, error) {
	set, err := m.admins(ctx)
	if err != nil {
		return nil, err
	}
	if set == nil {
		set = []string{}
	}
	return &Admins{Admins: set, Threshold: m.threshold()}, nil
}

// MaxAuditPage bounds a page of the audit log.
const MaxAuditPage = 100

// Audit returns up to limit (1..MaxAuditPage; 0: MaxAuditPage) entries
// written after the entry since ("" for the first).
func (m *Manager) Audit(ctx context.Context, since string, limit int) (*AuditPage, error) {
	if limit <= 0 || limit > MaxAuditPage {
		limit = MaxAuditPage
	}
	recs, err := m.Pager.Page(ctx, KindAudit, since, limit)
	if err != nil {
		return nil, err
	}
	p := &AuditPage{Entries: make([]AuditEntry, 0, len(recs))}
	for _, rec := range recs {
		var e AuditEntry
		if err := json.Unmarshal(rec.Data, &e); err != nil {
			return nil, err
		}
		p.Entries = append(p.Entries, e)
	}
	if len(recs) == limit {
		p.Next = recs[len(recs)-1].ID
	}
	return p, nil
}

// Answer handles the outcome of a challenge (a signin.* peer event). It
// reports false when the challenge is not an approval's. Every answer is
// audited with its evidence; it counts when the approval is pending, the
// answer is to the admin's outstanding challenge and the admin is still
// in the set and has not answered. A bad signature is audited and does
// not count. A redelivered event is recognized and changes nothing.
func (m *Manager) Answer(ctx context.Context, e *peer.Event) (bool, error) {
	aid, ok, err := m.Store.Get(ctx, kindReq, e.RequestID)
	if err != nil || !ok {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.load(ctx, string(aid))
	if err != nil || r == nil {
		return r != nil, err
	}
	now := m.now()
	b := m.batch(now)
	outstanding := r.Pending[e.ConnectionID] == e.RequestID
	if e.Type == peer.EventSignInExpired {
		if outstanding {
			delete(r.Pending, e.ConnectionID)
			if err := b.save(r); err != nil {
				return true, err
			}
		}
		return true, b.apply(ctx)
	}
	b.changes = append(b.changes, peer.Change{Kind: kindSeen, ID: e.ID, Data: []byte{}, Expires: now.Add(seenRetention), IfAbsent: true})
	set, err := m.admins(ctx)
	if err != nil {
		return true, err
	}
	answer := AnswerApproved
	switch {
	case e.Type == peer.EventSignInDenied && e.Reason == "bad_signature":
		answer = AnswerBadSignature
	case e.Type == peer.EventSignInDenied:
		answer = AnswerDenied
	}
	counted := r.Status == StatusPending && now.Before(r.Exp) && outstanding && slices.Contains(set, e.ConnectionID) &&
		!r.answered(e.ConnectionID) && answer != AnswerBadSignature
	if outstanding {
		delete(r.Pending, e.ConnectionID)
	}
	at := e.At.UTC().Truncate(time.Millisecond)
	ent := &AuditEntry{Type: AuditResponse, ApprovalID: r.ID, ActionHash: r.Hash, ConnectionID: e.ConnectionID,
		RequestID: e.RequestID, Context: e.Context, Answer: answer, Counted: &counted, Key: e.Key, Signature: e.Signature,
		KeyChanged: answer == AnswerApproved && e.KeyChanged}
	if !e.SignedAt.IsZero() {
		sa := e.SignedAt.UTC()
		ent.SignedAt = &sa
	}
	if err := b.audit(ent); err != nil {
		return true, err
	}
	var settled []Challenge
	if counted {
		switch answer {
		case AnswerApproved:
			r.Approvals = append(r.Approvals, Approver{ConnectionID: e.ConnectionID, At: at, KeyChanged: e.KeyChanged})
		case AnswerDenied:
			r.Denials = append(r.Denials, Denier{ConnectionID: e.ConnectionID, At: at})
		}
		if settled, err = m.evaluate(ctx, b, r, set, ReasonDenied); err != nil {
			return true, err
		}
	}
	if err := b.save(r); err != nil {
		return true, err
	}
	if err := b.apply(ctx); err != nil {
		if errors.Is(err, peer.ErrConflict) {
			return true, nil // handled before
		}
		return true, err
	}
	m.log().Info("approval answer", "approval_id", r.ID, "connection_id", e.ConnectionID, "answer", answer, "counted", counted,
		"status", r.Status)
	m.afterSettle(ctx, r, settled)
	return true, nil
}

// evaluate settles a pending approval if m approvals are in (approved)
// or can no longer be (denied, with reason). It returns the challenges
// still outstanding at a settlement, to be cancelled once it is written.
func (m *Manager) evaluate(ctx context.Context, b *batch, r *record, set []string, reason string) ([]Challenge, error) {
	if r.Status != StatusPending {
		return nil, nil
	}
	if len(r.Approvals) >= r.Threshold {
		return m.settle(ctx, b, r, StatusApproved, "", set)
	}
	open := 0
	for _, a := range r.Admins {
		if slices.Contains(set, a) && !r.answered(a) {
			open++
		}
	}
	if len(r.Approvals)+open < r.Threshold {
		return m.settle(ctx, b, r, StatusDenied, reason, set)
	}
	return nil, nil
}

// settle ends an approval: its status, the audit entry, its webhook and,
// for an approved admin_set.* action, the change of the admin set.
func (m *Manager) settle(ctx context.Context, b *batch, r *record, status, reason string, set []string) ([]Challenge, error) {
	r.Status, r.Reason, r.Settled = status, reason, b.now.UTC().Truncate(time.Millisecond)
	var out []Challenge
	for c, req := range r.Pending {
		out = append(out, Challenge{ConnectionID: c, RequestID: req})
	}
	r.Pending = nil
	b.del(kindOpen, r.ID)
	if status == StatusApproved && (r.Action == ActionAdminSetAdd || r.Action == ActionAdminSetRemove) {
		applied, err := m.applyAdminSet(b, r, set)
		if err != nil {
			return nil, err
		}
		r.Applied = &applied
	}
	typ := map[string]string{StatusApproved: AuditApproved, StatusDenied: AuditDenied, StatusExpired: AuditExpired}[status]
	hookType := map[string]string{StatusApproved: EventApproved, StatusDenied: EventDenied, StatusExpired: EventExpired}[status]
	if err := b.audit(&AuditEntry{Type: typ, ApprovalID: r.ID, Action: r.Action, ActionHash: r.Hash, Status: status,
		Reason: reason, Applied: r.Applied}); err != nil {
		return nil, err
	}
	data := map[string]any{"approval_id": r.ID, "action": r.Action, "action_hash": r.Hash}
	if reason != "" {
		data["reason"] = reason
	}
	if r.Applied != nil {
		data["applied"] = *r.Applied
	}
	return out, b.hook(hookType, "", data)
}

// applyAdminSet changes the admin set for an approved admin_set.*
// action, if it still applies: an added connection must still be active
// and not an admin; a removed one must still be an admin, and the set
// never becomes empty this way.
func (m *Manager) applyAdminSet(b *batch, r *record, set []string) (bool, error) {
	target, err := adminSetTarget(r.Payload)
	if err != nil {
		return false, nil
	}
	switch r.Action {
	case ActionAdminSetAdd:
		if slices.Contains(set, target) || !m.active(target) {
			return false, nil
		}
		return true, b.adminSetChanged(append(slices.Clone(set), target), target, "", ChangeApproval, r.ID)
	default:
		if !slices.Contains(set, target) || len(set) <= 1 {
			return false, nil
		}
		next := slices.DeleteFunc(slices.Clone(set), func(c string) bool { return c == target })
		return true, b.adminSetChanged(next, "", target, ChangeApproval, r.ID)
	}
}

// afterSettle cancels a settled approval's outstanding challenges, so a
// late answer matches nothing, and wakes the webhook delivery. An
// admin_set.remove that was applied re-evaluates the open approvals.
func (m *Manager) afterSettle(ctx context.Context, r *record, outstanding []Challenge) {
	if r.Status == StatusPending {
		return
	}
	m.cancel(ctx, outstanding)
	if r.Action == ActionAdminSetRemove && r.Applied != nil && *r.Applied {
		if err := m.reevaluate(ctx); err != nil {
			m.log().Warn("approval reevaluate", "err", errName(err))
		}
	}
	m.wake()
}

// reevaluate settles the open approvals that have expired or can no
// longer reach their threshold (after admins left the set).
func (m *Manager) reevaluate(ctx context.Context) error {
	open, err := m.Store.Load(ctx, kindOpen)
	if err != nil {
		return err
	}
	set, err := m.admins(ctx)
	if err != nil {
		return err
	}
	for _, o := range open {
		r, err := m.load(ctx, o.ID)
		if err != nil {
			return err
		}
		now := m.now()
		b := m.batch(now)
		var settled []Challenge
		switch {
		case r == nil:
			b.del(kindOpen, o.ID)
		case r.Status != StatusPending:
			b.del(kindOpen, o.ID)
		case !now.Before(r.Exp):
			if settled, err = m.settle(ctx, b, r, StatusExpired, "", set); err != nil {
				return err
			}
		default:
			// An admin no longer in the set cannot answer.
			var gone []Challenge
			for c, req := range r.Pending {
				if !slices.Contains(set, c) {
					gone = append(gone, Challenge{ConnectionID: c, RequestID: req})
					delete(r.Pending, c)
				}
			}
			m.cancel(ctx, gone)
			if settled, err = m.evaluate(ctx, b, r, set, ReasonAdminsRemoved); err != nil {
				return err
			}
		}
		if r != nil {
			if err := b.save(r); err != nil {
				return err
			}
		}
		if err := b.apply(ctx); err != nil {
			return err
		}
		if r != nil && r.Status != StatusPending {
			m.log().Info("approval settled", "approval_id", r.ID, "status", r.Status, "reason", r.Reason)
			m.cancel(ctx, settled)
			m.wake()
		}
	}
	return nil
}

// ConnectionAdded makes the connection the first admin when the admin
// set is empty and the connection holds the binding of the bootstrap
// email (SV_ADMIN_BOOTSTRAP_EMAIL).
func (m *Manager) ConnectionAdded(ctx context.Context, connID, emailKey string, bound bool) error {
	if m.BootstrapKey == "" || !bound || emailKey != m.BootstrapKey {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bootstrap(ctx, connID)
}

func (m *Manager) bootstrap(ctx context.Context, connID string) error {
	set, err := m.admins(ctx)
	if err != nil || len(set) > 0 {
		return err
	}
	b := m.batch(m.now())
	if err := b.adminSetChanged([]string{connID}, connID, "", ChangeBootstrap, ""); err != nil {
		return err
	}
	if err := b.apply(ctx); err != nil {
		return err
	}
	m.log().Info("admin set bootstrapped", "connection_id", connID)
	m.wake()
	return nil
}

// ConnectionRemoved takes a removed connection out of the admin set (a
// member can always sever, so this may empty the set) and settles the
// open approvals that can no longer reach their threshold.
func (m *Manager) ConnectionRemoved(ctx context.Context, connID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, err := m.admins(ctx)
	if err != nil || !slices.Contains(set, connID) {
		return err
	}
	next := slices.DeleteFunc(slices.Clone(set), func(c string) bool { return c == connID })
	b := m.batch(m.now())
	if err := b.adminSetChanged(next, "", connID, ChangeConnectionRemoved, ""); err != nil {
		return err
	}
	if err := b.apply(ctx); err != nil {
		return err
	}
	m.log().Info("admin removed with its connection", "connection_id", connID, "admins", len(next))
	m.wake()
	return m.reevaluate(ctx)
}

// Start checks the bootstrap setting against the stored admin set; it is
// logged when the set is not empty (the setting is then ignored).
func (m *Manager) Start(ctx context.Context) error {
	set, err := m.admins(ctx)
	if err != nil {
		return err
	}
	if m.BootstrapKey != "" && len(set) > 0 {
		m.log().Info("admin bootstrap setting ignored: the admin set is not empty", "admins", len(set))
	}
	return nil
}

// Tick does the periodic work: bootstrap from an already bound, active
// connection while the set is empty; expire or settle the open
// approvals; deliver the waiting webhooks.
func (m *Manager) Tick(ctx context.Context) error {
	err := m.tickState(ctx)
	return errors.Join(err, m.Flush(ctx))
}

func (m *Manager) tickState(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.BootstrapKey != "" && m.BoundConnection != nil {
		set, err := m.admins(ctx)
		if err != nil {
			return err
		}
		if len(set) == 0 {
			c, ok, err := m.BoundConnection(ctx, m.BootstrapKey)
			if err != nil {
				return err
			}
			if ok && m.active(c) {
				if err := m.bootstrap(ctx, c); err != nil {
					return err
				}
			}
		}
	}
	return m.reevaluate(ctx)
}

// Flush delivers the waiting webhooks in order; one the endpoint rejects
// is dropped after logging, and delivery stops at the first that could
// not be delivered (it is tried again at the next tick).
func (m *Manager) Flush(ctx context.Context) error {
	if m.Webhooks == nil {
		return nil
	}
	m.flushMu.Lock()
	defer m.flushMu.Unlock()
	recs, err := m.Store.Load(ctx, kindHook)
	if err != nil {
		return err
	}
	for _, rec := range recs {
		e := &webhook.Event{}
		if err := json.Unmarshal(rec.Data, e); err != nil {
			return err
		}
		err := m.Webhooks.Deliver(ctx, e)
		if errors.Is(err, webhook.ErrRejected) {
			m.log().Error("webhook rejected", "event_id", e.ID, "type", e.Type)
		} else if err != nil {
			m.log().Warn("webhook delivery", "event_id", e.ID, "type", e.Type, "err", "error")
			return err
		}
		if err := m.Store.Apply(ctx, []peer.Change{{Kind: kindHook, ID: rec.ID}}); err != nil {
			return err
		}
	}
	return nil
}

// TickInterval is how often Run ticks.
const TickInterval = 15 * time.Second

func (m *Manager) wake() {
	m.once.Do(func() { m.kick = make(chan struct{}, 1) })
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// Run ticks until ctx ends: at once, every TickInterval, and soon after
// an approval settles or the admin set changes.
func (m *Manager) Run(ctx context.Context) {
	m.once.Do(func() { m.kick = make(chan struct{}, 1) })
	t := time.NewTicker(TickInterval)
	defer t.Stop()
	for {
		if err := m.Tick(ctx); err != nil && ctx.Err() == nil {
			m.log().Warn("approval tick", "err", errName(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.kick:
		}
	}
}
