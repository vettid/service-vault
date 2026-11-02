package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Record kinds the manager keeps in the peer's store (DynamoDB in a
// deployment).
const (
	kindApproval = "apv"        // an approval
	kindOpen     = "apv_open"   // approval id -> "" while it is pending
	kindReq      = "apv_req"    // challenge request id -> approval id
	kindSeen     = "apv_seen"   // peer event id -> "": an answer already handled
	kindAdmins   = "admin_set"  // "admins" -> the admin set
	kindBoot     = "admin_boot" // "state" -> the bootstrap state (bootState)
	kindAsks     = "apv_asks"   // admin connection id -> its newest approval challenges (askLog)
	kindUsed     = "apv_used"   // approval id -> when it was used (Consume); written once (IfAbsent), never changed
	// HookKind is the kind of the approvals' webhook Outbox: an event
	// waiting to be delivered.
	HookKind = "apv_hook"
	// KindAudit is the append-only audit log: one record per entry, by
	// increasing id, written once (IfAbsent), never updated or deleted.
	KindAudit = "audit"

	adminsID      = "admins"
	bootID        = "state"
	seenRetention = 16 * 24 * time.Hour // as the peer's dedupe markers (VAULT-MESSAGING §8)
	reqRetention  = 24 * time.Hour      // past the approval's expiry
)

// The member vault's approval rate bucket (VAULT-MESSAGING §10.4.1): 5
// approval challenges per connection in a fixed 24-hour window that starts
// when the first reaches the member. A challenge can reach the member at
// any time until its exp (the outbox holds it while the relay or the
// member's vault is away; an expired one is dropped there), so the service
// counts each challenge it sends until its exp plus askWindow plus
// peer.ClockSkew. Any 5 in one member window reached it within 24 hours
// before the next one, so all 5 still count here when that one would be
// sent: every send (a new approval, a reminder, a forced one) skips an
// admin at the budget, and a forced one is refused, before it could come
// back as a delayed denial. A suppressed, lost or unsent challenge counts here and
// not there, which only refuses more.
const (
	askBudget = 5
	askWindow = 24 * time.Hour
	askSlack  = time.Minute // added to a logged exp (challenge)
)

// askLog is the exps of the approval challenges sent to one connection
// that count longest, at most askBudget, in increasing order.
type askLog struct {
	Exp []time.Time `json:"exp"`
}

// next is when a full log stops being full: its oldest counting entry's end.
func (l *askLog) next() time.Time {
	return l.Exp[len(l.Exp)-askBudget].Add(askWindow + peer.ClockSkew)
}

// budgetEntry reports connID as left out for the budget, if its log is full.
func (m *Manager) budgetEntry(ctx context.Context, connID string) (AskBudget, bool) {
	l, err := m.asks(ctx, connID)
	if err != nil || !l.full(m.now()) {
		return AskBudget{}, false
	}
	return AskBudget{ConnectionID: connID, NextAskAt: l.next().UTC()}, true
}

// counts reports whether a challenge with this exp still counts at now.
func counts(exp, now time.Time) bool { return now.Before(exp.Add(askWindow + peer.ClockSkew)) }

// full reports whether askBudget logged challenges still count at now.
func (l *askLog) full(now time.Time) bool {
	return len(l.Exp) >= askBudget && counts(l.Exp[len(l.Exp)-askBudget], now)
}

func (m *Manager) asks(ctx context.Context, connID string) (*askLog, error) {
	l, _, err := m.asksVersion(ctx, connID)
	return l, err
}

// errAskUndecodable is an ask log that is stored but does not decode.
var errAskUndecodable = errors.New("approval: ask log undecodable")

// asksVersion is asks with the stored record's version (0: absent, or the
// store has no versions).
func (m *Manager) asksVersion(ctx context.Context, connID string) (*askLog, uint64, error) {
	l := &askLog{}
	var data []byte
	var ver uint64
	if rg, ok := m.Store.(peer.RecordGetter); ok {
		rec, found, err := rg.GetRecord(ctx, kindAsks, connID)
		if err != nil || !found {
			return l, 0, err
		}
		data, ver = rec.Data, rec.Version
	} else {
		d, found, err := m.Store.Get(ctx, kindAsks, connID)
		if err != nil || !found {
			return l, 0, err
		}
		data = d
	}
	if err := json.Unmarshal(data, l); err != nil {
		// Fails closed: that admin is neither challenged nor forced until
		// the record expires.
		m.log().Error("approval ask log unreadable", "connection_id", connID)
		return nil, 0, errAskUndecodable
	}
	return l, ver, nil
}

// Peer is the part of peer.Peer the manager uses.
type Peer interface {
	Connection(id string) (peer.ConnectionInfo, bool)
	Authenticate(ctx context.Context, connID, ctxt, purpose string, ttl time.Duration) (string, error)
	CancelChallenge(ctx context.Context, requestID string) (bool, error)
	// PinGov pins a connection's governance key to its credential key as
	// it is now (when it becomes an admin; with onlyIfEmpty only if none
	// is pinned). RepinGov moves it to key if that is still the
	// connection's credential key. Both report whether they did.
	PinGov(ctx context.Context, connID string, onlyIfEmpty bool) (bool, error)
	RepinGov(ctx context.Context, connID string, key []byte) (bool, error)
}

// Pager reads an append-only kind in id order (store.Table, peer.MemStore).
type Pager interface {
	Page(ctx context.Context, kind, after string, limit int) ([]peer.Record, error)
}

// Manager runs approvals. It assumes it is the only writer of its
// records (one task runs the service vault) and serializes its work.
type Manager struct {
	Peer  Peer
	Store peer.Store
	Pager Pager
	// Hooks queues the approvals' webhooks (Kind HookKind); its own Run
	// delivers them. nil sends none.
	Hooks *webhook.Outbox
	// ServiceName is named in the challenge's context.
	ServiceName string
	// Threshold is m: how many distinct admins must approve
	// (SV_ADMIN_THRESHOLD, default 1). An approval keeps the threshold
	// it was created with.
	Threshold int
	// TTL is how long an approval stays open (SV_APPROVAL_TTL, default
	// DefaultTTL).
	TTL time.Duration
	// LongChallenges sends an approval challenge with the approval's own
	// expiry, at most 24 hours (SV_LONG_APPROVAL_CHALLENGES; VAULT-MESSAGING
	// 0.82.0 §10.4), and reminds only admins holding no live challenge.
	// Off, a challenge lasts 10 minutes and a reminder challenges every
	// admin who has not answered. Turn it on for a channel only once its
	// member vaults carry 0.82.0: an older one clamps the challenge to 10
	// minutes without telling the service, which could not then see that
	// the admin holds none.
	LongChallenges bool
	// AllowNoPurpose counts an approval signed without a purpose, from a
	// vault older than VAULT-MESSAGING 0.65.0 (SV_APPROVAL_ALLOW_NO_PURPOSE,
	// for a transition only). Without it such an answer is audited and not
	// counted: §10.4 says a challenger SHOULD NOT count it, since nothing
	// in the signature shows it was an approval rather than a sign-in.
	// Either way its entry has reason no_purpose.
	AllowNoPurpose bool
	// ProposalTitle returns the title of a stored proposal, for the summary
	// of a vote.extend approval; nil refuses every extension.
	ProposalTitle func(ctx context.Context, proposalID string) (title string, ok bool, err error)
	// BootstrapKey is the email index key of SV_ADMIN_BOOTSTRAP_EMAIL
	// ("" for none): while the admin set is empty and no bootstrap has
	// happened, the connection bound to it becomes the first admin. The
	// bootstrap is one-shot: once it has happened (or once the set was
	// seen not empty) it is recorded in the store and the setting is never
	// used again; only ArmBootstrap arms a new one.
	BootstrapKey string
	// BoundConnection returns the connection bound to an email index key.
	BoundConnection func(ctx context.Context, emailKey string) (string, bool, error)
	Now             func() time.Time
	Log             *slog.Logger

	mu     sync.Mutex
	lastID string
	kick   chan struct{}
	once   sync.Once
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
	// An approval that does not count (a changed key) is not an answer: the
	// admin may be asked again.
	return slices.ContainsFunc(r.Approvals, func(a Approver) bool { return a.ConnectionID == connID && a.stands(r.Action) }) ||
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
	hooks   bool // changes queue a webhook
}

func (m *Manager) batch(now time.Time) *batch { return &batch{m: m, now: now} }

// marshal encodes v without HTML escaping: an action's payload is kept
// and served as its canonical bytes, so that hashing them as served gives
// its action_hash (json.Marshal would turn <, > and & into \u003c...).
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func (b *batch) put(kind, id string, v any, exp time.Time) error {
	data, err := marshal(v)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, peer.Change{Kind: kind, ID: id, Data: data, Expires: exp})
	return nil
}

// putNew writes a record that must not exist yet (IfAbsent): the whole
// batch fails with peer.ErrConflict if it does.
func (b *batch) putNew(kind, id string, v any) error {
	data, err := marshal(v)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, peer.Change{Kind: kind, ID: id, Data: data, IfAbsent: true})
	return nil
}

func (b *batch) del(kind, id string) { b.changes = append(b.changes, peer.Change{Kind: kind, ID: id}) }

func (b *batch) audit(e *AuditEntry) error {
	id, err := b.m.nextID(b.now)
	if err != nil {
		return err
	}
	e.ID, e.At = id, b.now.UTC().Truncate(time.Millisecond)
	data, err := marshal(e)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, peer.Change{Kind: KindAudit, ID: id, Data: data, IfAbsent: true})
	return nil
}

func (b *batch) hook(typ, connID string, data any) error {
	if b.m.Hooks == nil {
		return nil
	}
	id, err := b.m.nextID(b.now)
	if err != nil {
		return err
	}
	e := &webhook.Event{ID: id, Type: typ, ConnectionID: connID, CreatedAt: b.now.UTC().Truncate(time.Second)}
	if e.Data, err = json.Marshal(data); err != nil {
		return err
	}
	c, err := b.m.Hooks.Change(id, e) // ids increase (nextID)
	if err != nil {
		return err
	}
	b.changes = append(b.changes, c)
	b.hooks = true
	return nil
}

func (b *batch) apply(ctx context.Context) error {
	if err := b.m.Store.Apply(ctx, b.changes); err != nil {
		return err
	}
	if b.hooks {
		b.m.Hooks.Wake()
	}
	return nil
}

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

// MaxAdminName is the longest name shown for a connection added as an
// admin; a longer one is refused, never cut.
const MaxAdminName = 32

// adminSetSummary is what the admins read for an admin_set.* action:
//
//	name given "<name>", connected <date>, key <fingerprint>, connection <id>
//
// The name is what the member's vault sent when it connected: the admins
// are told it is self-declared (anyone the API key can invite can choose
// any name), and the date, the fingerprint and the id are what the
// service holds. The fingerprint is the first 16 hex digits, in the first
// 4 of the 8 groups of 4 that apps show, of
// SHA-256("vettid/vms/2/ik-fp" || ik) of the connection's pinned identity
// key (VAULT-MESSAGING §10.8). The member's own app does not show its
// vault's fingerprint; an admin connected to that member can compare it
// with the vault key fingerprint on their own connection with them, since
// the vault presents one ik everywhere. Nothing is cut or replaced: an added connection whose name is
// over MaxAdminName characters or has characters outside printable ASCII
// and Latin-1 letters, that is unknown or not active, or has no pinned
// credential key (it has never signed in) or no identity key, is refused.
// Removing a connection the service no longer knows names only its id.
func (m *Manager) adminSetSummary(action string, payload []byte) (string, error) {
	target, err := adminSetTarget(payload)
	if err != nil {
		return "", err
	}
	if len(target) > 40 || checkSummary(target) != nil || strings.ContainsAny(target, "\"") {
		return "", errCode(CodeInvalidPayload)
	}
	if m.Peer == nil {
		return "", errCode(CodeInvalidConnection)
	}
	info, ok := m.Peer.Connection(target)
	add := action == ActionAdminSetAdd
	if add && (!ok || info.State != peer.StateActive || len(info.AuthKey) == 0 || len(info.IK) != ed25519.PublicKeySize ||
		info.Activated.IsZero()) {
		return "", errCode(CodeInvalidConnection)
	}
	if !ok {
		return "connection " + target, nil
	}
	name, err := shownName(info.Name, add)
	if err != nil {
		return "", err
	}
	s := name
	if !info.Activated.IsZero() {
		s += ", connected " + info.Activated.UTC().Format("2006-01-02")
	}
	if len(info.IK) == ed25519.PublicKeySize {
		s += ", key " + fingerprint("vettid/vms/2/ik-fp", info.IK)
	}
	s += ", connection " + target
	if len(s) > MaxAdminSummary {
		return "", errCode(CodeFieldNotShown)
	}
	return s, nil
}

// shownName is how a connection's self-declared name is shown to the
// admins. A name that can't be shown whole is refused with strict, and
// otherwise reads "name not shown".
func shownName(n string, strict bool) (string, error) {
	switch {
	case n == "":
		return "name not given", nil
	case utf8.RuneCountInString(n) > MaxAdminName || !adminNameOK(n):
		if strict {
			return "", errCode(CodeFieldNotShown)
		}
		return "name not shown", nil
	}
	return "name given " + strconv.Quote(n), nil
}

// ckFPLabel domain-separates the fingerprint of a credential key, as
// VAULT-MESSAGING §10.8's label does the identity key's.
const ckFPLabel = "vettid/vms/2/ck-fp"

// fingerprint is the first 16 hex digits, in 4 groups of 4, of
// SHA-256(label || key).
func fingerprint(label string, key []byte) string {
	fp := sha256.Sum256(append([]byte(label), key...))
	h := hex.EncodeToString(fp[:8])
	return h[:4] + " " + h[4:8] + " " + h[8:12] + " " + h[12:]
}

// repinPayload is the payload of admin.repin: the admin and the
// credential key their governance key is to become.
type repinPayload struct {
	ConnectionID string `json:"connection_id"`
	NewKey       string `json:"new_key,omitempty"` // base64 (standard), 32 bytes
}

// parseRepin reads an admin.repin payload strictly. key is nil when the
// payload gives none.
func parseRepin(payload []byte) (target string, key []byte, err error) {
	var p repinPayload
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || p.ConnectionID == "" || len(p.ConnectionID) > 40 ||
		checkSummary(p.ConnectionID) != nil || strings.ContainsAny(p.ConnectionID, "\"") {
		return "", nil, errCode(CodeInvalidPayload)
	}
	if p.NewKey == "" {
		return p.ConnectionID, nil, nil
	}
	key, err = base64.StdEncoding.DecodeString(p.NewKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return "", nil, errCode(CodeInvalidPayload)
	}
	return p.ConnectionID, key, nil
}

// repinSummary checks an admin.repin payload against the connection the
// service holds, fills in new_key when the payload gives none (the
// connection's credential key now), and builds what the other admins read:
//
//	name given "<name>", old key xxxx xxxx xxxx xxxx, new key xxxx xxxx xxxx xxxx, connection <id>
//
// The fingerprints are of the credential keys (ckFPLabel). Nothing is cut:
// a name that can't be shown whole is refused. It returns the payload to
// approve, with new_key.
func (m *Manager) repinSummary(payload []byte) (out []byte, summary string, err error) {
	target, key, err := parseRepin(payload)
	if err != nil {
		return nil, "", err
	}
	if m.Peer == nil {
		return nil, "", errCode(CodeInvalidConnection)
	}
	info, ok := m.Peer.Connection(target)
	if !ok || info.State != peer.StateActive || len(info.AuthKey) != ed25519.PublicKeySize || len(info.GovKey) != ed25519.PublicKeySize {
		return nil, "", errCode(CodeInvalidConnection)
	}
	if key == nil {
		key = info.AuthKey
	}
	// Only the key the connection signs in with now; and only if that is
	// not the governance key already.
	if !bytes.Equal(key, info.AuthKey) || bytes.Equal(key, info.GovKey) {
		return nil, "", errCode(CodeInvalidPayload)
	}
	name, err := shownName(info.Name, true)
	if err != nil {
		return nil, "", err
	}
	summary = name + ", old key " + fingerprint(ckFPLabel, info.GovKey) + ", new key " + fingerprint(ckFPLabel, key) +
		", connection " + target
	if len(summary) > MaxAdminSummary {
		return nil, "", errCode(CodeFieldNotShown)
	}
	raw, err := json.Marshal(repinPayload{ConnectionID: target, NewKey: base64.StdEncoding.EncodeToString(key)})
	if err != nil {
		return nil, "", err
	}
	out, err = servicevault.CanonicalJSON(raw)
	if err != nil {
		return nil, "", errCode(CodeInvalidPayload)
	}
	return out, summary, nil
}

// MaxAdminSummary bounds an admin_set.* summary, so that it is shown
// whole in a challenge's context with the longest service name.
const MaxAdminSummary = 165

// adminNameOK accepts printable ASCII and Latin-1 letters only, with no
// space at either end.
func adminNameOK(n string) bool {
	if n != strings.TrimSpace(n) {
		return false
	}
	for _, r := range n {
		if !(r >= 0x20 && r <= 0x7e || r >= 0xc0 && r <= 0xff && r != 0xd7 && r != 0xf7) {
			return false
		}
	}
	return true
}

// summaryError is the refusal of a payload whose summary can't be built.
func summaryError(err error) error {
	var ns *ballot.ErrNotShown
	if errors.Is(err, ballot.ErrCharset) {
		return errCode(CodeUnsupportedText)
	}
	if errors.As(err, &ns) {
		return errCode(CodeFieldNotShown)
	}
	return errCode(CodeInvalidPayload)
}

// Create submits an action for approval: it is checked and hashed, and
// a challenge goes to every admin. It returns the approval's id and hash.
func (m *Manager) Create(ctx context.Context, req Request) (*Created, error) {
	if !actions[req.Action] {
		return nil, errCode(CodeInvalidAction)
	}
	payload, err := servicevault.CanonicalJSON(req.Payload)
	if err != nil || len(payload) == 0 || payload[0] != '{' || len(payload) > MaxPayload {
		return nil, errCode(CodeInvalidPayload)
	}
	// The admins read a summary the service builds from the payload for
	// the actions that start or extend a vote; the application supplies
	// no text for them.
	title := ""
	if req.Action == ActionVoteExtend {
		// The admins are shown the proposal's title, from the store.
		id, err := ballot.ExtensionProposalID(payload)
		if err != nil {
			return nil, summaryError(err)
		}
		if m.ProposalTitle == nil {
			return nil, errCode(CodeUnknownProposal)
		}
		t, ok, err := m.ProposalTitle(ctx, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errCode(CodeUnknownProposal)
		}
		title = t
	}
	summary, built, err := ballot.SummaryFor(req.Action, payload, title)
	if req.Action == ActionAdminSetAdd || req.Action == ActionAdminSetRemove {
		// The admins are shown who is added or removed, as the service
		// holds it, not text the application wrote.
		if req.Summary != "" {
			return nil, errCode(CodeInvalidSummary)
		}
		if summary, err = m.adminSetSummary(req.Action, payload); err != nil {
			return nil, err
		}
		built, err = true, nil
	}
	if req.Action == ActionAdminRepin {
		// The other admins read who is re-pinned, from what the service
		// holds, not text the application wrote.
		if req.Summary != "" {
			return nil, errCode(CodeInvalidSummary)
		}
		if payload, summary, err = m.repinSummary(payload); err != nil {
			return nil, err
		}
		built, err = true, nil
	}
	switch {
	case !built:
		summary = req.Summary
		if err := checkSummary(summary); err != nil {
			return nil, err
		}
	case req.Summary != "":
		return nil, errCode(CodeInvalidSummary)
	case err != nil:
		return nil, summaryError(err)
	}
	req.Summary = summary
	hash, err := servicevault.ActionHash(req.Action, req.Summary, payload)
	if err != nil {
		return nil, errCode(CodeInvalidPayload)
	}
	ctxt, err := ChallengeContext(m.ServiceName, req.Action, req.Summary, hash)
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
	asked := set // the admins asked; admin.repin leaves out the admin re-pinned
	switch req.Action {
	case ActionAdminRepin:
		target, _, err := parseRepin(payload)
		if err != nil {
			return nil, err
		}
		switch {
		case !slices.Contains(set, target) || !m.active(target):
			return nil, errCode(CodeInvalidConnection)
		case len(set) == 1:
			return nil, errCode(CodeSoleAdmin)
		}
		asked = slices.DeleteFunc(slices.Clone(set), func(c string) bool { return c == target })
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
	if th > len(asked) {
		return nil, errCode(CodeUnreachable)
	}
	now := m.now()
	// Before anything is sent or stored: too few admins can be asked now
	// (canAsk) for the threshold to be met.
	askable := 0
	for _, a := range asked {
		ok, err := m.canAsk(ctx, a, now)
		if err != nil {
			return nil, err
		}
		if ok {
			askable++
		}
	}
	if askable < th {
		return nil, errCode(CodeAskBudget)
	}
	id, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	r := &record{ID: id, Action: req.Action, Summary: req.Summary, Payload: payload, Hash: hash, Status: StatusPending,
		Threshold: th, Admins: slices.Clone(asked), Created: now.UTC().Truncate(time.Millisecond),
		Exp: now.Add(m.ttl()).UTC().Truncate(time.Second), LastSent: now, Pending: map[string]string{}}
	b := m.batch(now)
	sent, skipped, _ := m.challenge(ctx, b, r, asked, ctxt)
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
	return &Created{ID: id, ActionHash: hash, Status: StatusPending, ExpiresAt: r.Exp, AskBudget: skipped}, nil
}

// challengeTTL is the life of a challenge sent at now for r: the
// approval's own remaining life, at least peerwire.ConnAuthChallengeTTL
// and at most peer.MaxApprovalChallengeTTL (VAULT-MESSAGING 0.82.0 §10.4,
// "Long-lived approval challenges").
func challengeTTL(r *record, now time.Time) time.Duration {
	return min(max(r.Exp.Sub(now), peerwire.ConnAuthChallengeTTL), peer.MaxApprovalChallengeTTL)
}

// challenge sends the approval's challenge to each of conns, each lasting
// as long as the approval (challengeTTL), and records the request ids.
// An admin who cannot be reached now is skipped (and can be reminded).
// Each challenge is logged (logAsk) before it is sent; an admin whose log
// is full or cannot be written is skipped too.
func (m *Manager) challenge(ctx context.Context, b *batch, r *record, conns []string, ctxt string) (sent []Challenge, skipped []AskBudget, full int) {
	var ttl time.Duration // 0: the connauth default, 10 minutes
	if m.LongChallenges {
		ttl = challengeTTL(r, m.now())
	}
	for _, c := range conns {
		// A minute of slack: the peer sets the challenge's exp from its own
		// clock a little later, after this write.
		exp := m.now().Add(max(ttl, peerwire.ConnAuthChallengeTTL) + askSlack)
		if err := m.logAsk(ctx, c, exp); err != nil {
			m.log().Warn("approval ask log", "approval_id", r.ID, "connection_id", c, "err", errName(err))
			if errors.Is(err, errAskFull) {
				full++
				if e, ok := m.budgetEntry(ctx, c); ok {
					skipped = append(skipped, e)
				}
			}
			continue
		}
		reqID, err := m.Peer.Authenticate(ctx, c, ctxt, peerwire.PurposeApproval, ttl)
		if err != nil {
			m.log().Warn("approval challenge", "approval_id", r.ID, "connection_id", c, "err", errName(err))
			continue
		}
		r.Pending[c] = reqID
		b.changes = append(b.changes, peer.Change{Kind: kindReq, ID: reqID, Data: []byte(r.ID),
			Expires: r.Exp.Add(reqRetention)})
		sent = append(sent, Challenge{ConnectionID: c, RequestID: reqID})
	}
	return sent, skipped, full
}

// errAskFull is an admin whose askLog is full (askBudget).
var errAskFull = errors.New("approval: ask budget full")

// canAsk reports whether another challenge to connID is within the
// member's budget at now. An admin whose log is full, or is stored but
// does not decode, is not askable; a store error is returned. m.mu is
// held across the check and the logAsk that follows, and logAsk's write
// is conditional, so no other send can fill the log in between.
func (m *Manager) canAsk(ctx context.Context, connID string, now time.Time) (bool, error) {
	l, err := m.asks(ctx, connID)
	if errors.Is(err, errAskUndecodable) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !l.full(now), nil
}

// logAsk adds a challenge to connID's askLog, with exp (at least the
// challenge's own, so it counts at least as long), and writes the log at
// once, on its own: a challenge is counted before it is sent, even if the
// send or the approval's batch then fails (counting one never sent only
// refuses more). So sends that fail before going out (an admin not
// reachable now, the peer's limits) still fill the log, and may refuse a
// later forced reminder to that admin. It refuses (errAskFull) when the
// log is already full, so no send is a sixth.
func (m *Manager) logAsk(ctx context.Context, connID string, exp time.Time) error {
	l, ver, err := m.asksVersion(ctx, connID)
	if err != nil {
		return err
	}
	if l.full(m.now()) {
		return errAskFull
	}
	l.Exp = append(l.Exp, exp.UTC().Truncate(time.Millisecond).Add(time.Millisecond))
	slices.SortFunc(l.Exp, time.Time.Compare)
	if n := len(l.Exp); n > askBudget {
		l.Exp = l.Exp[n-askBudget:]
	}
	data, err := marshal(l)
	if err != nil {
		return err
	}
	last := l.Exp[len(l.Exp)-1]
	c := peer.Change{Kind: kindAsks, ID: connID, Data: data, Expires: last.Add(askWindow + peer.ClockSkew)}
	if _, ok := m.Store.(peer.RecordGetter); ok {
		// Another task (a deploy overlaps two) may have written since the
		// read: that is a log that may be full, so fail closed.
		if ver == 0 {
			c.IfAbsent = true
		} else {
			c.IfVersion = ver
		}
	}
	if err := m.Store.Apply(ctx, []peer.Change{c}); errors.Is(err, peer.ErrConflict) {
		return errAskFull
	} else {
		return err
	}
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
	case errors.Is(err, errAskFull):
		return "ask_budget"
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
		ExpiresAt: r.Exp, Applied: r.Applied, RemindNeeded: []string{}}
	if r.Action == ActionProposalCreate || r.Action == ActionVoteExtend {
		if data, ok, err := m.Store.Get(ctx, kindUsed, id); err != nil {
			return nil, err
		} else if ok {
			var u usedRecord
			if err := json.Unmarshal(data, &u); err != nil {
				return nil, err
			}
			st.Used = &Used{At: u.At, ProposalID: u.ProposalID, N: u.N}
		}
	}
	if st.Status == StatusPending && !m.now().Before(r.Exp) {
		st.Status = StatusExpired
	}
	if st.Status == StatusPending {
		set, err := m.admins(ctx)
		if err != nil {
			return nil, err
		}
		for _, a := range r.Admins {
			if slices.Contains(set, a) && r.Pending[a] == "" && !r.answered(a) {
				st.RemindNeeded = append(st.RemindNeeded, a)
			}
		}
		for _, a := range st.RemindNeeded {
			if e, ok := m.budgetEntry(ctx, a); ok {
				st.AskBudget = append(st.AskBudget, e)
			}
		}
		if len(st.RemindNeeded) > 0 {
			ra := r.LastSent.Add(RemindInterval).UTC().Truncate(time.Second)
			st.RemindAfter = &ra
		}
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
// at most once per RemindInterval per approval (the creation counts). With
// LongChallenges only to those holding no live challenge (the
// remind_needed ones), each lasting as long as the approval, and
// CodeNothingToRemind when there are none (checked before the interval).
// Otherwise to every admin who has not answered, replacing their challenge.
// An admin sent 5 approval challenges that still count is left out, with
// their challenge not withdrawn; CodeAskBudget when that leaves nobody
// to send to (checked before anything is withdrawn).
// With force, only to the named admins (CodeNotAdmin for one outside the
// approval's admins or the current set, CodeAnswered for one who has
// answered, CodeAskBudget for one sent 5 approval challenges that still
// count, see askBudget): each one's live challenge is withdrawn and a new
// one sent, whatever the gate says, still at most once per
// RemindInterval. Each
// forced re-send uses one of the member's approval asks (VAULT-MESSAGING
// §10.4.1). (chosen; not in the spec)
func (m *Manager) Remind(ctx context.Context, id string, force ...string) (*Reminder, error) {
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
	set, err := m.admins(ctx)
	if err != nil {
		return nil, err
	}
	var to []Challenge
	var conns []string
	for _, a := range force {
		if !slices.Contains(r.Admins, a) || !slices.Contains(set, a) {
			return nil, errCode(CodeNotAdmin)
		}
		if r.answered(a) {
			return nil, errCode(CodeAnswered)
		}
		if slices.Contains(conns, a) {
			continue
		}
		if ok, err := m.canAsk(ctx, a, now); err != nil {
			return nil, err
		} else if !ok {
			return nil, errCode(CodeAskBudget)
		}
		// Forced: any live challenge is withdrawn and a new one sent,
		// whatever the gate says (the member vault may have lost it).
		if old := r.Pending[a]; old != "" {
			to = append(to, Challenge{ConnectionID: a, RequestID: old})
			delete(r.Pending, a)
		}
		conns = append(conns, a)
	}
	var skipped []AskBudget
	cands, limited := 0, 0 // admins to remind; of those left out for a full or unreadable ask log
	for _, a := range r.Admins {
		if len(force) > 0 {
			break // only the named admins
		}
		if !slices.Contains(set, a) || r.answered(a) {
			continue
		}
		if m.LongChallenges {
			// An admin who still holds a live challenge is not challenged
			// again: it outlives RemindInterval, and each challenge that
			// reaches a member's vault uses its approval bucket
			// (VAULT-MESSAGING §10.4.1).
			if r.Pending[a] != "" {
				continue
			}
		}
		cands++
		// Before anything is withdrawn: an admin at the budget keeps the
		// challenge they hold, and stays in remind_needed if they hold none.
		ok, err := m.canAsk(ctx, a, now)
		if err != nil {
			return nil, err
		}
		if !ok {
			limited++
			if e, ok := m.budgetEntry(ctx, a); ok {
				skipped = append(skipped, e)
			}
			continue
		}
		if old := r.Pending[a]; old != "" && !m.LongChallenges {
			to = append(to, Challenge{ConnectionID: a, RequestID: old})
			delete(r.Pending, a)
		}
		conns = append(conns, a)
	}
	if len(force) == 0 && m.LongChallenges && cands == 0 {
		return nil, errCode(CodeNothingToRemind)
	}
	if len(force) == 0 && len(conns) == 0 && limited > 0 {
		return nil, errCode(CodeAskBudget)
	}
	if now.Before(r.LastSent.Add(RemindInterval)) {
		return nil, errCode(CodeTooSoon)
	}
	m.cancel(ctx, to)
	ctxt, err := ChallengeContext(m.ServiceName, r.Action, r.Summary, r.Hash)
	if err != nil {
		return nil, err
	}
	if r.Pending == nil {
		r.Pending = map[string]string{}
	}
	b := m.batch(now)
	sent, lost, full := m.challenge(ctx, b, r, conns, ctxt)
	if len(force) == 0 && len(sent) == 0 && full > 0 {
		// Every send lost a race for the last slot: as if refused.
		return nil, errCode(CodeAskBudget)
	}
	skipped = append(skipped, lost...)
	r.LastSent = now
	if err := errors.Join(b.save(r), b.audit(&AuditEntry{Type: AuditReminded, ApprovalID: r.ID, Challenges: sent})); err != nil {
		return nil, err
	}
	if err := b.apply(ctx); err != nil {
		m.cancel(ctx, sent)
		return nil, err
	}
	out := &Reminder{ID: r.ID, Reminded: []string{}, AskBudget: skipped}
	for _, c := range sent {
		out.Reminded = append(out.Reminded, c.ConnectionID)
	}
	m.log().Info("approval reminded", "approval_id", r.ID, "challenged", len(sent), "forced", len(force) > 0)
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
		if !outstanding {
			return true, b.apply(ctx)
		}
		delete(r.Pending, e.ConnectionID)
		// A challenge that ended with the approval (its exp at or after the
		// approval's own expiry, the normal case for a long challenge) is
		// not reported: the approval's own expiry is (approval.expired).
		live := r.Status == StatusPending && now.Before(r.Exp) && e.Exp.Before(r.Exp)
		if live {
			set, err := m.admins(ctx)
			if err != nil {
				return true, err
			}
			live = slices.Contains(set, e.ConnectionID)
		}
		if live {
			if err := b.hook(EventChallengeExpired, e.ConnectionID, map[string]any{"approval_id": r.ID, "action": r.Action,
				"connection_id": e.ConnectionID, "request_id": e.RequestID, "expires_at": r.Exp}); err != nil {
				return true, err
			}
		}
		if err := b.save(r); err != nil {
			return true, err
		}
		if err := b.apply(ctx); err != nil {
			return true, err
		}
		if live {
			m.log().Info("approval challenge expired", "approval_id", r.ID, "connection_id", e.ConnectionID,
				"request_id", e.RequestID)
		}
		return true, nil
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
	noPurpose := answer == AnswerApproved && e.Purpose == ""
	valid := r.Status == StatusPending && now.Before(r.Exp) && outstanding && slices.Contains(set, e.ConnectionID) &&
		!r.answered(e.ConnectionID) && answer != AnswerBadSignature && (!noPurpose || m.AllowNoPurpose)
	// A governance approval signed with a changed key does not count: it
	// is recorded and audited, and the admin may approve again.
	keyChanged := answer == AnswerApproved && e.GovKeyChanged && Governance(r.Action)
	counted := valid && !keyChanged
	if outstanding {
		delete(r.Pending, e.ConnectionID)
	}
	at := e.At.UTC().Truncate(time.Millisecond)
	ent := &AuditEntry{Type: AuditResponse, ApprovalID: r.ID, ActionHash: r.Hash, ConnectionID: e.ConnectionID,
		RequestID: e.RequestID, Context: e.Context, Answer: answer, Counted: &counted, Key: e.Key, Signature: e.Signature, Purpose: e.Purpose,
		Nonce: e.Nonce, ServiceIK: e.ServiceIK, MemberIK: e.MemberIK,
		KeyChanged: answer == AnswerApproved && e.KeyChanged}
	if noPurpose {
		ent.Reason = ReasonNoPurpose
	}
	why := ReasonNotRepinned
	if e.KeyChanged {
		why = ReasonKeyChanged
	}
	if valid && keyChanged {
		ent.Reason = why
	}
	if !e.SignedAt.IsZero() {
		sa := e.SignedAt.UTC()
		ent.SignedAt = &sa
	}
	if err := b.audit(ent); err != nil {
		return true, err
	}
	var settled []Challenge
	if valid && keyChanged {
		r.Approvals = slices.DeleteFunc(r.Approvals, func(a Approver) bool { return a.ConnectionID == e.ConnectionID })
		r.Approvals = append(r.Approvals, Approver{ConnectionID: e.ConnectionID, At: at, KeyChanged: e.KeyChanged, GovKeyChanged: true, Reason: why})
	}
	if counted {
		switch answer {
		case AnswerApproved:
			// Replaces an earlier approval of theirs that did not count.
			r.Approvals = slices.DeleteFunc(r.Approvals, func(a Approver) bool { return a.ConnectionID == e.ConnectionID })
			r.Approvals = append(r.Approvals, Approver{ConnectionID: e.ConnectionID, At: at, KeyChanged: e.KeyChanged, Counted: true})
		case AnswerDenied:
			r.Denials = append(r.Denials, Denier{ConnectionID: e.ConnectionID, At: at})
		}
		if settled, err = m.evaluate(ctx, b, r, set, r.Threshold, ReasonDenied); err != nil {
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

// evaluate settles a pending approval if m approvals of current admins
// are in (approved) or can no longer be (denied, with reason). It returns the challenges
// still outstanding at a settlement, to be cancelled once it is written.
func (m *Manager) evaluate(ctx context.Context, b *batch, r *record, set []string, threshold int, reason string) ([]Challenge, error) {
	if r.Status != StatusPending {
		return nil, nil
	}
	// Only approvals of admins still in the set count: an admin removed
	// (or severed) since approving no longer stands behind the action.
	counted := r.standing(set)
	if counted >= threshold {
		return m.settle(ctx, b, r, StatusApproved, "", set)
	}
	open := 0
	for _, a := range r.Admins {
		if slices.Contains(set, a) && !r.answered(a) {
			open++
		}
	}
	if counted+open < threshold {
		return m.settle(ctx, b, r, StatusDenied, reason, set)
	}
	return nil, nil
}

// standing counts the approvals that count toward the threshold: those of
// admins in set, not set aside for a changed key.
func (r *record) standing(set []string) int {
	n := 0
	self := "" // admin.repin: the admin re-pinned never approves their own
	if r.Action == ActionAdminRepin {
		t, _, err := parseRepin(r.Payload)
		if err != nil {
			return 0
		}
		self = t
	}
	for _, a := range r.Approvals {
		if a.stands(r.Action) && slices.Contains(set, a.ConnectionID) && a.ConnectionID != self {
			n++
		}
	}
	return n
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
	if status == StatusApproved && (r.Action == ActionAdminSetAdd || r.Action == ActionAdminSetRemove || r.Action == ActionAdminRepin) {
		applied, err := m.applyAdminSet(ctx, b, r, set)
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
func (m *Manager) applyAdminSet(ctx context.Context, b *batch, r *record, set []string) (bool, error) {
	// Defence in depth: whatever settled the approval, the set is never
	// changed on an approval signed with a changed key, or one that does
	// not meet its threshold with the approvals that count.
	for _, a := range r.Approvals {
		if a.Counted && a.GovKeyChanged && slices.Contains(set, a.ConnectionID) {
			return false, nil
		}
	}
	if r.standing(set) < r.Threshold {
		return false, nil
	}
	if r.Action == ActionAdminRepin {
		// The governance key becomes the connection's credential key,
		// if that is still the key the admins were shown.
		target, key, err := parseRepin(r.Payload)
		if err != nil || key == nil || !slices.Contains(set, target) || !m.active(target) {
			return false, nil
		}
		if ok, err := m.Peer.RepinGov(ctx, target, key); err != nil || !ok {
			return false, err
		}
		return true, b.audit(&AuditEntry{Type: AuditAdminRepinned, ApprovalID: r.ID, ConnectionID: target})
	}
	target, err := adminSetTarget(r.Payload)
	if err != nil {
		return false, nil
	}
	switch r.Action {
	case ActionAdminSetAdd:
		if slices.Contains(set, target) || !m.active(target) {
			return false, nil
		}
		// The new admin's governance key is their credential key now.
		if ok, err := m.Peer.PinGov(ctx, target, false); err != nil || !ok {
			return false, err
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
			if settled, err = m.evaluate(ctx, b, r, set, max(r.Threshold, m.threshold()), ReasonAdminsRemoved); err != nil {
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

// Bootstrap states (bootState.State).
const (
	bootArmed = "armed" // ArmBootstrap armed a bootstrap for EmailKey
	bootDone  = "done"  // the first admin was set: no bootstrap applies
)

// bootState is the stored bootstrap state. With none stored, the
// configured BootstrapKey applies.
type bootState struct {
	State    string    `json:"state"`
	EmailKey string    `json:"email_key,omitempty"` // armed
	At       time.Time `json:"at"`
}

// ErrAdminsExist is returned by ArmBootstrap when the admin set is not
// empty.
var ErrAdminsExist = errors.New("approval: the admin set is not empty")

func (m *Manager) bootState(ctx context.Context) (*bootState, error) {
	data, ok, err := m.Store.Get(ctx, kindBoot, bootID)
	if err != nil || !ok {
		return nil, err
	}
	st := &bootState{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	return st, nil
}

// bootstrapKey returns the email index key that may make the first
// admin now: the armed one, else the configured one unless a bootstrap
// has happened; "" for none.
func (m *Manager) bootstrapKey(ctx context.Context) (string, error) {
	st, err := m.bootState(ctx)
	switch {
	case err != nil:
		return "", err
	case st == nil:
		return m.BootstrapKey, nil
	case st.State == bootArmed:
		return st.EmailKey, nil
	}
	return "", nil
}

// ConnectionAdded makes the connection the first admin when the admin
// set is empty, a bootstrap applies, and the connection holds the binding
// of the bootstrap email. Only an email the application verified is
// bound (api: email_verified), so only a verified email makes an admin.
func (m *Manager) ConnectionAdded(ctx context.Context, connID, emailKey string, bound bool) error {
	if !bound || emailKey == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.bootstrapKey(ctx)
	if err != nil || key == "" || key != emailKey {
		return err
	}
	return m.bootstrap(ctx, connID)
}

// bootstrap makes connID the first admin and records, in the same
// write, that the bootstrap has happened.
func (m *Manager) bootstrap(ctx context.Context, connID string) error {
	set, err := m.admins(ctx)
	if err != nil || len(set) > 0 {
		return err
	}
	now := m.now()
	// Pinned now if it has a credential key; otherwise by its first sign-in.
	if m.Peer != nil {
		if _, err := m.Peer.PinGov(ctx, connID, false); err != nil {
			return err
		}
	}
	b := m.batch(now)
	if err := b.adminSetChanged([]string{connID}, connID, "", ChangeBootstrap, ""); err != nil {
		return err
	}
	if err := b.put(kindBoot, bootID, &bootState{State: bootDone, At: now.UTC()}, time.Time{}); err != nil {
		return err
	}
	if err := b.apply(ctx); err != nil {
		return err
	}
	m.log().Info("admin set bootstrapped", "connection_id", connID)
	m.wake()
	return nil
}

// ArmBootstrap arms a new one-shot bootstrap for an email index key: the
// connection bound to it (from an invitation with a verified email)
// becomes the first admin, once. It is the operator's recovery when the
// admin set has become empty (`service-vault admin bootstrap`); it is
// refused with ErrAdminsExist while the set is not empty, and it replaces
// a bootstrap armed earlier. It is audited without the email.
func (m *Manager) ArmBootstrap(ctx context.Context, emailKey string) error {
	if emailKey == "" {
		return errors.New("approval: empty bootstrap email key")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// The admin CLI is a process of its own, beside the running daemon:
	// the write holds only if the admin set is still the empty one read
	// here (the daemon may bootstrap an admin meanwhile).
	recs, err := m.Store.Load(ctx, kindAdmins)
	if err != nil {
		return err
	}
	var guard peer.Change
	switch {
	case len(recs) == 0:
		guard = peer.Change{Kind: kindAdmins, ID: adminsID, Data: []byte(`{"admins":[]}`), IfAbsent: true}
	default:
		var v struct {
			Admins []string `json:"admins"`
		}
		if err := json.Unmarshal(recs[0].Data, &v); err != nil {
			return err
		}
		if len(v.Admins) > 0 {
			return ErrAdminsExist
		}
		guard = peer.Change{Kind: kindAdmins, ID: adminsID, Data: recs[0].Data, IfVersion: recs[0].Version}
	}
	now := m.now()
	b := m.batch(now)
	b.changes = append(b.changes, guard)
	if err := b.put(kindBoot, bootID, &bootState{State: bootArmed, EmailKey: emailKey, At: now.UTC()}, time.Time{}); err != nil {
		return err
	}
	if err := b.audit(&AuditEntry{Type: AuditBootstrapArmed}); err != nil {
		return err
	}
	if err := b.apply(ctx); errors.Is(err, peer.ErrConflict) {
		return ErrAdminsExist // an admin was set meanwhile
	} else if err != nil {
		return err
	}
	m.log().Info("admin bootstrap armed")
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
	if th := m.threshold(); len(next) < th {
		// No approval can pass until the operator mends it: a lower m,
		// or a bootstrap once the set is empty (README "Recovering
		// admins").
		m.log().Error("admin set below the threshold: approvals cannot pass", "alarm", "admins_short",
			"admins", len(next), "threshold", th)
	}
	m.wake()
	return m.reevaluate(ctx)
}

// Start checks the bootstrap setting against the stored state. A store
// whose admin set is not empty but has no bootstrap state (one from
// before the bootstrap was one-shot) is marked as bootstrapped. The
// setting is logged as ignored when a bootstrap has happened.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	set, err := m.admins(ctx)
	if err != nil {
		return err
	}
	st, err := m.bootState(ctx)
	if err != nil {
		return err
	}
	if st == nil && len(set) > 0 {
		now := m.now()
		b := m.batch(now)
		if err := b.put(kindBoot, bootID, &bootState{State: bootDone, At: now.UTC()}, time.Time{}); err != nil {
			return err
		}
		if err := b.apply(ctx); err != nil {
			return err
		}
		st = &bootState{State: bootDone}
	}
	// Admins from before the governance key existed: pinned to the
	// credential key they have now.
	if m.Peer != nil {
		for _, a := range set {
			if _, err := m.Peer.PinGov(ctx, a, true); err != nil {
				return err
			}
		}
	}
	switch {
	case st != nil && st.State == bootArmed:
		m.log().Info("admin bootstrap armed: waiting for its connection", "admins", len(set))
	case m.BootstrapKey != "" && st != nil && st.State == bootDone:
		m.log().Info("admin bootstrap setting ignored: the bootstrap has happened", "admins", len(set))
	}
	return nil
}

// Tick does the periodic work: bootstrap from an already bound, active
// connection while the set is empty and a bootstrap applies; expire or settle the open
// approvals. The webhooks are delivered by Hooks.Run.
func (m *Manager) Tick(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key, err := m.bootstrapKey(ctx)
	if err != nil {
		return err
	}
	if key != "" && m.BoundConnection != nil {
		set, err := m.admins(ctx)
		if err != nil {
			return err
		}
		if len(set) == 0 {
			c, ok, err := m.BoundConnection(ctx, key)
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

// Kinds lists every record kind the approvals store (the audit log and
// their webhook outbox included), for a migration that must touch them
// all.
func Kinds() []string {
	return []string{kindApproval, kindOpen, kindReq, kindSeen, kindAdmins, kindBoot, kindAsks, kindUsed, KindAudit, HookKind}
}
