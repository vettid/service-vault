package approval

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/webhook"
	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// fakePeer stands in for the peer: the connections in active are
// active; every challenge is sent and recorded.
type fakePeer struct {
	mu        sync.Mutex
	active    map[string]bool
	n         int
	sent      []sent
	cancelled []string
	fail      map[string]error // Authenticate fails for these connections
	purposes  []string         // each Authenticate's purpose
	now       func() time.Time
}

type sent struct {
	conn, req, ctxt string
	at              time.Time     // when it was sent
	ttl             time.Duration // the life it was sent with
}

func (p *fakePeer) Connection(id string) (peer.ConnectionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active[id] {
		return peer.ConnectionInfo{}, false
	}
	return peer.ConnectionInfo{ID: id, State: peer.StateActive}, true
}

func (p *fakePeer) Authenticate(_ context.Context, conn, ctxt, purpose string, ttl time.Duration) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.purposes = append(p.purposes, purpose)
	if err := p.fail[conn]; err != nil {
		return "", err
	}
	p.n++
	req := fmt.Sprintf("req%02d", p.n)
	// As the peer sends it: 10 minutes unless longer is asked, and only two
	// long ones per connection at a time.
	now := p.now()
	if ttl <= 0 {
		ttl = peerwire.ConnAuthChallengeTTL
	}
	if ttl > peerwire.ConnAuthChallengeTTL {
		// Every approval challenge holds a place, whatever its life (a
		// member clock that lags sees even a 10-minute one as long); a
		// cancelled one has been withdrawn.
		long := 0
		for _, o := range p.sent {
			if o.conn == conn && now.Before(o.at.Add(o.ttl)) && !slices.Contains(p.cancelled, o.req) {
				long++
			}
		}
		if long >= peer.MaxLongLivedChallenges {
			ttl = peerwire.ConnAuthChallengeTTL
		}
	}
	p.sent = append(p.sent, sent{conn, req, ctxt, now, ttl})
	return req, nil
}

func (p *fakePeer) CancelChallenge(_ context.Context, req string) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancelled = append(p.cancelled, req)
	return true, nil
}

// last returns the last challenge sent to conn.
func (p *fakePeer) last(conn string) sent {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.sent) - 1; i >= 0; i-- {
		if p.sent[i].conn == conn {
			return p.sent[i]
		}
	}
	return sent{}
}

// hooks is the webhook endpoint; of delivers what the outbox holds
// first.
type hooks struct {
	mu     sync.Mutex
	evs    []*webhook.Event
	failed error
	out    *webhook.Outbox
}

func (h *hooks) Deliver(_ context.Context, e *webhook.Event) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failed != nil {
		return h.failed
	}
	h.evs = append(h.evs, e)
	return nil
}

func (h *hooks) of(typ string) []map[string]any {
	if h.out != nil {
		_ = h.out.Flush(context.Background())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]any
	for _, e := range h.evs {
		if e.Type == typ {
			var d map[string]any
			_ = json.Unmarshal(e.Data, &d)
			d["_connection_id"] = e.ConnectionID
			out = append(out, d)
		}
	}
	return out
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	t    *testing.T
	m    *Manager
	p    *fakePeer
	st   *peer.MemStore
	hk   *hooks
	clk  *clock
	logs *bytes.Buffer
	ev   int
}

func newFixture(t *testing.T, threshold int, admins ...string) *fixture {
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	st := peer.NewMemStore()
	st.Now = clk.Now
	p := &fakePeer{active: map[string]bool{}, now: clk.Now}
	for _, a := range admins {
		p.active[a] = true
	}
	logs := &bytes.Buffer{}
	f := &fixture{t: t, p: p, st: st, hk: &hooks{}, clk: clk, logs: logs}
	f.hk.out = &webhook.Outbox{Store: st, Kind: HookKind, Sender: f.hk, Now: clk.Now}
	f.m = &Manager{Peer: p, Store: st, Pager: st, Hooks: f.hk.out, ServiceName: "VettID Member Service",
		Threshold: threshold, Now: clk.Now, Log: slog.New(slog.NewTextHandler(logs, nil))}
	if len(admins) > 0 {
		b := f.m.batch(clk.Now())
		if err := b.setAdmins(slices.Clone(admins)); err != nil {
			t.Fatal(err)
		}
		if err := b.apply(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fixture) create(action, summary, payload string) *Created {
	f.t.Helper()
	c, err := f.m.Create(context.Background(), Request{Action: action, Summary: summary, Payload: json.RawMessage(payload)})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) status(id string) *Status {
	f.t.Helper()
	s, err := f.m.Status(context.Background(), id)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) admins() []string {
	f.t.Helper()
	a, err := f.m.Admins(context.Background())
	if err != nil {
		f.t.Fatal(err)
	}
	return a.Admins
}

// answer delivers conn's answer to its last challenge: "approve",
// "approve-changed", "deny", "bad" or "expire". It returns the event.
func (f *fixture) answer(conn, how string) *peer.Event {
	f.t.Helper()
	return f.answerTo(f.p.last(conn), how)
}

// first returns the first challenge sent to conn.
func (p *fakePeer) first(conn string) sent {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sent {
		if s.conn == conn {
			return s
		}
	}
	return sent{}
}

func (f *fixture) answerTo(s sent, how string) *peer.Event {
	f.t.Helper()
	conn := s.conn
	if s.req == "" {
		f.t.Fatalf("no challenge to %s", conn)
	}
	f.ev++
	e := &peer.Event{ID: fmt.Sprintf("ev%03d", f.ev), ConnectionID: conn, RequestID: s.req, Context: s.ctxt, At: f.clk.Now()}
	sig := func() {
		e.Key = bytes.Repeat([]byte{0x11}, 32)
		e.Signature = bytes.Repeat([]byte{0x22}, 64)
		e.SignedAt = f.clk.Now()
		e.Purpose = peerwire.PurposeApproval
	}
	switch how {
	case "approve", "approve-changed":
		e.Type, e.KeyChanged = peer.EventSignInApproved, how == "approve-changed"
		sig()
	case "approve-no-purpose": // a vault before VAULT-MESSAGING 0.65.0
		e.Type = peer.EventSignInApproved
		sig()
		e.Purpose = ""
	case "deny":
		e.Type, e.Reason = peer.EventSignInDenied, "denied"
	case "bad":
		e.Type, e.Reason = peer.EventSignInDenied, "bad_signature"
		sig()
	case "expire": // the challenge ran out: at the exp it was sent with
		e.Type = peer.EventSignInExpired
		e.Exp = s.at.Add(s.ttl)
	}
	f.deliver(e)
	return e
}

func (f *fixture) deliver(e *peer.Event) {
	f.t.Helper()
	ok, err := f.m.Answer(context.Background(), e)
	if err != nil || !ok {
		f.t.Fatalf("answer: %v %v", ok, err)
	}
}

func (f *fixture) tick() {
	f.t.Helper()
	if err := f.m.Tick(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) audit() []AuditEntry {
	f.t.Helper()
	var all []AuditEntry
	since := ""
	for {
		p, err := f.m.Audit(context.Background(), since, 3)
		if err != nil {
			f.t.Fatal(err)
		}
		all = append(all, p.Entries...)
		if p.Next == "" {
			return all
		}
		since = p.Next
	}
}

func codeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

const votePayload = `{"proposal": 7, "options": ["yes", "no"]}`

// 1-of-n: every admin is asked; the first approval approves; the other
// challenges are cancelled; a late answer is audited but does not count.
func TestOneOfN(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2", "c3")
	c := f.create(ActionVoteOpen, "Open the vote on proposal 7", votePayload)
	want, _ := servicevault.ActionHash(ActionVoteOpen, "Open the vote on proposal 7", json.RawMessage(votePayload))
	if c.Status != StatusPending || c.ActionHash != want || !c.ExpiresAt.Equal(f.clk.Now().Add(DefaultTTL)) {
		t.Fatalf("created %+v", c)
	}
	if len(f.p.sent) != 3 {
		t.Fatalf("%d challenges", len(f.p.sent))
	}
	wantCtx := "Approve on VettID Member Service: Open the vote on proposal 7 — ref " + want[:8]
	for _, s := range f.p.sent {
		if s.ctxt != wantCtx {
			t.Fatalf("context %q", s.ctxt)
		}
	}
	f.answer("c2", "approve")
	s := f.status(c.ID)
	if s.Status != StatusApproved || len(s.Approvals) != 1 || s.Approvals[0].ConnectionID != "c2" || s.Applied != nil {
		t.Fatalf("status %+v", s)
	}
	if len(f.p.cancelled) != 2 {
		t.Fatalf("cancelled %v", f.p.cancelled)
	}
	f.answer("c3", "approve") // raced the cancellation
	if s := f.status(c.ID); s.Status != StatusApproved || len(s.Approvals) != 1 {
		t.Fatalf("late answer counted: %+v", s)
	}
	f.tick()
	ap := f.hk.of(EventApproved)
	if len(ap) != 1 || ap[0]["approval_id"] != c.ID || ap[0]["action_hash"] != want || ap[0]["action"] != ActionVoteOpen {
		t.Fatalf("webhooks %+v", ap)
	}
	// The audit log: the request, both answers with their evidence, the
	// outcome.
	var types []string
	for _, e := range f.audit() {
		types = append(types, e.Type)
	}
	if strings.Join(types, " ") != "approval.requested approval.response approval.approved approval.response" {
		t.Fatalf("audit %v", types)
	}
	logs := f.logs.String()
	if strings.Contains(logs, "proposal 7") || strings.Contains(logs, want[:8]) ||
		strings.Contains(logs, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 64))[:16]) {
		t.Fatalf("logs carry a context or signature:\n%s", logs)
	}
}

// 2-of-n: a denial does not veto while two approvals remain possible;
// a redelivered answer changes nothing; a bad signature does not count.
func TestTwoOfN(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionProposalCreate, "Create proposal: bylaws v2", `{"title":"Bylaws v2"}`)
	e := f.answer("c1", "approve-changed")
	f.deliver(e) // redelivered
	if s := f.status(c.ID); s.Status != StatusPending || len(s.Approvals) != 1 || !s.Approvals[0].KeyChanged {
		t.Fatalf("after one: %+v", s)
	}
	f.answer("c2", "deny")
	if s := f.status(c.ID); s.Status != StatusPending || len(s.Denials) != 1 {
		t.Fatalf("after a denial: %+v", s)
	}
	f.answer("c3", "bad")
	if s := f.status(c.ID); s.Status != StatusPending {
		t.Fatalf("bad signature counted: %+v", s)
	}
	f.clk.Advance(RemindInterval)
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || len(r.Reminded) != 1 || r.Reminded[0] != "c3" {
		t.Fatalf("remind %+v %v", r, err)
	}
	f.answer("c3", "approve")
	s := f.status(c.ID)
	if s.Status != StatusApproved || len(s.Approvals) != 2 || s.Approvals[1].ConnectionID != "c3" {
		t.Fatalf("status %+v", s)
	}
	var resp []AuditEntry
	for _, e := range f.audit() {
		if e.Type == AuditResponse {
			resp = append(resp, e)
		}
	}
	if len(resp) != 4 {
		t.Fatalf("%d responses audited", len(resp))
	}
	first := resp[0]
	if first.Answer != AnswerApproved || !*first.Counted || !first.KeyChanged || len(first.Signature) != 64 ||
		len(first.Key) != 32 || first.SignedAt == nil || !strings.HasPrefix(first.Context, "Approve on ") ||
		first.RequestID == "" || first.ActionHash != s.ActionHash {
		t.Fatalf("evidence %+v", first)
	}
	if resp[1].Answer != AnswerDenied || !*resp[1].Counted || resp[2].Answer != AnswerBadSignature || *resp[2].Counted {
		t.Fatalf("responses %+v", resp[1:3])
	}
}

// A denial that leaves too few admins to reach m denies the approval.
func TestDenyMakesUnreachable(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionVoteClose, "Close the vote", `{}`)
	f.answer("c1", "deny")
	if s := f.status(c.ID); s.Status != StatusPending {
		t.Fatalf("%+v", s)
	}
	f.answer("c2", "deny")
	s := f.status(c.ID)
	if s.Status != StatusDenied || s.Reason != ReasonDenied {
		t.Fatalf("%+v", s)
	}
	f.tick()
	if d := f.hk.of(EventDenied); len(d) != 1 || d[0]["reason"] != ReasonDenied {
		t.Fatalf("webhooks %+v", d)
	}
	if !slices.Contains(f.p.cancelled, f.p.last("c3").req) {
		t.Fatal("outstanding challenge not cancelled")
	}
	// 1-of-1: the only admin denies.
	g := newFixture(t, 1, "c1")
	c = g.create(ActionVoteClose, "Close the vote", `{}`)
	g.answer("c1", "deny")
	if s := g.status(c.ID); s.Status != StatusDenied {
		t.Fatalf("%+v", s)
	}
}

// m > n is refused at creation.
func TestUnreachableAtCreation(t *testing.T) {
	f := newFixture(t, 2, "c1")
	_, err := f.m.Create(context.Background(), Request{Action: ActionVoteOpen, Summary: "x", Payload: json.RawMessage(`{}`)})
	if codeOf(err) != CodeUnreachable {
		t.Fatalf("%v", err)
	}
	g := newFixture(t, 1)
	_, err = g.m.Create(context.Background(), Request{Action: ActionVoteOpen, Summary: "x", Payload: json.RawMessage(`{}`)})
	if codeOf(err) != CodeUnreachable {
		t.Fatalf("no admins: %v", err)
	}
	if len(f.p.sent)+len(g.p.sent) != 0 || len(f.audit()) != 0 {
		t.Fatal("refused request went out")
	}
}

func TestExpiry(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.m.TTL = time.Hour
	c := f.create(ActionAssignmentPush, "Push assignment 3", `{"assignment":3}`)
	f.answer("c1", "expire") // the 10-minute challenge ran out: the admin can be reminded
	f.clk.Advance(time.Hour)
	if s := f.status(c.ID); s.Status != StatusExpired {
		t.Fatalf("%+v", s)
	}
	f.tick()
	if e := f.hk.of(EventExpired); len(e) != 1 || e[0]["approval_id"] != c.ID {
		t.Fatalf("webhooks %+v", e)
	}
	if !slices.Contains(f.p.cancelled, f.p.last("c2").req) || slices.Contains(f.p.cancelled, f.p.last("c1").req) {
		t.Fatalf("cancelled %v", f.p.cancelled)
	}
	f.answer("c2", "approve") // after expiry
	if s := f.status(c.ID); s.Status != StatusExpired || len(s.Approvals) != 0 {
		t.Fatalf("%+v", s)
	}
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeNotPending {
		t.Fatalf("remind expired: %v", err)
	}
	f.tick()
	if len(f.hk.of(EventExpired)) != 1 {
		t.Fatal("expired twice")
	}
}

// Reminders: at most once per 10 minutes (the creation counts), only to
// admins who have not answered; the previous challenge is cancelled.
func TestRemindRateLimit(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	f.p.fail = map[string]error{"c3": peer.ErrNotFound} // not reachable at creation
	c := f.create(ActionVoteOpen, "Open", `{}`)
	if len(f.p.sent) != 2 {
		t.Fatalf("%d sent", len(f.p.sent))
	}
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeTooSoon {
		t.Fatalf("%v", err)
	}
	f.clk.Advance(RemindInterval - time.Second)
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeTooSoon {
		t.Fatalf("%v", err)
	}
	f.answer("c1", "approve")
	f.p.fail = nil
	f.clk.Advance(time.Second)
	old := f.p.last("c2").req
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || strings.Join(r.Reminded, ",") != "c2,c3" {
		t.Fatalf("%+v %v", r, err)
	}
	if !slices.Contains(f.p.cancelled, old) {
		t.Fatal("previous challenge not cancelled")
	}
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeTooSoon {
		t.Fatalf("%v", err)
	}
	if _, err := f.m.Remind(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	f.answer("c3", "approve")
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeNotPending {
		t.Fatalf("%v", err)
	}
	n := 0
	for _, e := range f.audit() {
		if e.Type == AuditReminded {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d reminders audited", n)
	}
}

func TestBootstrap(t *testing.T) {
	f := newFixture(t, 1)
	f.m.BootstrapKey = "boot-key"
	ctx := context.Background()
	for _, c := range []struct {
		conn, key string
		bound     bool
	}{{"c0", "other-key", true}, {"c0", "boot-key", false}} {
		if err := f.m.ConnectionAdded(ctx, c.conn, c.key, c.bound); err != nil || len(f.admins()) != 0 {
			t.Fatalf("%+v: %v %v", c, err, f.admins())
		}
	}
	if err := f.m.ConnectionAdded(ctx, "c1", "boot-key", true); err != nil {
		t.Fatal(err)
	}
	if a := f.admins(); len(a) != 1 || a[0] != "c1" {
		t.Fatalf("admins %v", a)
	}
	// The set is not empty: the setting is ignored.
	if err := f.m.ConnectionAdded(ctx, "c2", "boot-key", true); err != nil || len(f.admins()) != 1 {
		t.Fatalf("%v %v", err, f.admins())
	}
	f.tick()
	ch := f.hk.of(EventAdminSetChanged)
	if len(ch) != 1 || ch[0]["reason"] != ChangeBootstrap || ch[0]["added"] != "c1" || ch[0]["_connection_id"] != "c1" {
		t.Fatalf("webhooks %+v", ch)
	}
	if err := f.m.Start(ctx); err != nil || !strings.Contains(f.logs.String(), "bootstrap setting ignored") {
		t.Fatalf("start: %v", err)
	}
}

// Already connected at start: the first tick bootstraps.
func TestBootstrapAtStart(t *testing.T) {
	f := newFixture(t, 1)
	f.m.BootstrapKey = "boot-key"
	bound := map[string]string{"boot-key": "c1"}
	f.m.BoundConnection = func(_ context.Context, k string) (string, bool, error) { c, ok := bound[k]; return c, ok, nil }
	f.tick() // c1 not active yet
	if len(f.admins()) != 0 {
		t.Fatal("bootstrapped an inactive connection")
	}
	f.p.active["c1"] = true
	f.tick()
	if a := f.admins(); len(a) != 1 || a[0] != "c1" {
		t.Fatalf("admins %v", a)
	}
}

// The bootstrap is one-shot: once the first admin is set, the setting
// is not used again even when the set empties; the operator arms a new
// one, which is one-shot too.
func TestBootstrapOneShot(t *testing.T) {
	f := newFixture(t, 1)
	f.m.BootstrapKey = "boot-key"
	bound := map[string]string{}
	f.m.BoundConnection = func(_ context.Context, k string) (string, bool, error) { c, ok := bound[k]; return c, ok, nil }
	ctx := context.Background()
	if err := f.m.ConnectionAdded(ctx, "c1", "boot-key", true); err != nil || len(f.admins()) != 1 {
		t.Fatalf("%v %v", err, f.admins())
	}
	// Armed while the set is not empty: refused.
	if err := f.m.ArmBootstrap(ctx, "new-key"); !errors.Is(err, ErrAdminsExist) {
		t.Fatalf("arm with admins: %v", err)
	}
	if err := f.m.ConnectionRemoved(ctx, "c1"); err != nil || len(f.admins()) != 0 {
		t.Fatalf("%v %v", err, f.admins())
	}
	// The set is empty, the setting is still there: no second bootstrap,
	// neither when a connection binds the email nor at a tick.
	if err := f.m.ConnectionAdded(ctx, "c2", "boot-key", true); err != nil || len(f.admins()) != 0 {
		t.Fatalf("second bootstrap: %v %v", err, f.admins())
	}
	bound["boot-key"], f.p.active["c2"] = "c2", true
	f.tick()
	if len(f.admins()) != 0 {
		t.Fatalf("second bootstrap at a tick: %v", f.admins())
	}
	if err := f.m.Start(ctx); err != nil || !strings.Contains(f.logs.String(), "bootstrap setting ignored") {
		t.Fatalf("start: %v", err)
	}

	// The operator arms a new bootstrap for another email: the old one
	// still does nothing, the armed one makes the admin, once.
	if err := f.m.ArmBootstrap(ctx, ""); err == nil {
		t.Fatal("armed an empty key")
	}
	if err := f.m.ArmBootstrap(ctx, "new-key"); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if len(f.admins()) != 0 {
		t.Fatalf("the configured email bootstrapped after arming another: %v", f.admins())
	}
	bound["new-key"], f.p.active["c3"] = "c3", true
	f.tick()
	if a := f.admins(); len(a) != 1 || a[0] != "c3" {
		t.Fatalf("armed bootstrap: %v", a)
	}
	if err := f.m.ConnectionRemoved(ctx, "c3"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.ConnectionAdded(ctx, "c4", "new-key", true); err != nil || len(f.admins()) != 0 {
		t.Fatalf("armed bootstrap applied twice: %v %v", err, f.admins())
	}
	n := 0
	for _, e := range f.audit() {
		if e.Type == AuditBootstrapArmed {
			n++
			if e.Added != "" || e.ConnectionID != "" {
				t.Fatalf("armed entry %+v", e)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d bootstrap_armed entries", n)
	}
}

// A store whose admin set is not empty but that has no bootstrap state
// (written before the bootstrap was one-shot) is marked as bootstrapped
// at the start.
func TestBootstrapStartMarksExistingSet(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.BootstrapKey = "boot-key"
	ctx := context.Background()
	if err := f.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.m.ConnectionRemoved(ctx, "c1"); err != nil || len(f.admins()) != 0 {
		t.Fatalf("%v %v", err, f.admins())
	}
	if err := f.m.ConnectionAdded(ctx, "c2", "boot-key", true); err != nil || len(f.admins()) != 0 {
		t.Fatalf("bootstrapped after the set had admins: %v %v", err, f.admins())
	}
}

// An unbound connection, or one without an email, never bootstraps.
func TestBootstrapNeedsBoundEmail(t *testing.T) {
	f := newFixture(t, 1)
	f.m.BootstrapKey = "boot-key"
	ctx := context.Background()
	for _, c := range []struct {
		key   string
		bound bool
	}{{"", true}, {"", false}, {"boot-key", false}} {
		if err := f.m.ConnectionAdded(ctx, "c1", c.key, c.bound); err != nil || len(f.admins()) != 0 {
			t.Fatalf("%+v: %v %v", c, err, f.admins())
		}
	}
}

// admin_set.add and admin_set.remove are governance actions; the service
// applies them when approved.
func TestAdminSetChanges(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.p.active["c2"] = true
	ctx := context.Background()
	_, err := f.m.Create(ctx, Request{Action: ActionAdminSetAdd, Summary: "Add", Payload: json.RawMessage(`{"connection_id":"c9"}`)})
	if codeOf(err) != CodeInvalidConnection {
		t.Fatalf("inactive: %v", err)
	}
	_, err = f.m.Create(ctx, Request{Action: ActionAdminSetAdd, Summary: "Add", Payload: json.RawMessage(`{"connection_id":"c1"}`)})
	if codeOf(err) != CodeInvalidConnection {
		t.Fatalf("already: %v", err)
	}
	_, err = f.m.Create(ctx, Request{Action: ActionAdminSetAdd, Summary: "Add", Payload: json.RawMessage(`{"connection_id":"c2","x":1}`)})
	if codeOf(err) != CodeInvalidPayload {
		t.Fatalf("extra field: %v", err)
	}
	add := f.create(ActionAdminSetAdd, "Add an admin", `{"connection_id":"c2"}`)
	f.answer("c1", "approve")
	s := f.status(add.ID)
	if s.Status != StatusApproved || s.Applied == nil || !*s.Applied || strings.Join(f.admins(), ",") != "c1,c2" {
		t.Fatalf("%+v %v", s, f.admins())
	}
	rm := f.create(ActionAdminSetRemove, "Remove an admin", `{"connection_id":"c1"}`)
	if len(f.status(rm.ID).Admins) != 2 {
		t.Fatal("not asked of both")
	}
	f.answer("c2", "approve")
	if s := f.status(rm.ID); s.Status != StatusApproved || !*s.Applied || strings.Join(f.admins(), ",") != "c2" {
		t.Fatalf("%+v %v", s, f.admins())
	}
	f.tick()
	ch := f.hk.of(EventAdminSetChanged)
	if len(ch) != 2 || ch[0]["added"] != "c2" || ch[1]["removed"] != "c1" || ch[1]["reason"] != ChangeApproval ||
		ch[1]["approval_id"] != rm.ID {
		t.Fatalf("webhooks %+v", ch)
	}
	if ap := f.hk.of(EventApproved); len(ap) != 2 || ap[1]["applied"] != true {
		t.Fatalf("approved %+v", ap)
	}
}

// The last admin cannot be removed by approval: refused at creation,
// and not applied when two removals race.
func TestLastAdminProtected(t *testing.T) {
	f := newFixture(t, 1, "c1")
	_, err := f.m.Create(context.Background(), Request{Action: ActionAdminSetRemove, Summary: "Remove",
		Payload: json.RawMessage(`{"connection_id":"c1"}`)})
	if codeOf(err) != CodeLastAdmin {
		t.Fatalf("%v", err)
	}
	g := newFixture(t, 1, "c1", "c2")
	r1 := g.create(ActionAdminSetRemove, "Remove c1", `{"connection_id":"c1"}`)
	r2 := g.create(ActionAdminSetRemove, "Remove c2", `{"connection_id":"c2"}`)
	g.answer("c2", "approve") // c2's last challenge is r2's
	if s := g.status(r2.ID); s.Status != StatusApproved || !*s.Applied {
		t.Fatalf("r2 %+v", s)
	}
	if strings.Join(g.admins(), ",") != "c1" {
		t.Fatalf("admins %v", g.admins())
	}
	// r1 is still pending: only c1 remains and can approve it, but it
	// would empty the set.
	g.answerTo(g.p.first("c1"), "approve")
	if s := g.status(r1.ID); s.Status != StatusApproved || s.Applied == nil || *s.Applied {
		t.Fatalf("r1 %+v", s)
	}
	if strings.Join(g.admins(), ",") != "c1" {
		t.Fatalf("admins %v", g.admins())
	}
	// With m = 2 and n = 2 a removal would leave the threshold unreachable.
	h := newFixture(t, 2, "c1", "c2")
	_, err = h.m.Create(context.Background(), Request{Action: ActionAdminSetRemove, Summary: "Remove",
		Payload: json.RawMessage(`{"connection_id":"c1"}`)})
	if codeOf(err) != CodeUnreachable {
		t.Fatalf("%v", err)
	}
}

// Removing an admin's connection takes it out of the set (even the last
// one) and denies the approvals that can no longer reach m.
func TestAdminConnectionRemoved(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	f.answer("c1", "deny")
	ctx := context.Background()
	if err := f.m.ConnectionRemoved(ctx, "c9"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.ConnectionRemoved(ctx, "c3"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.admins(), ",") != "c1,c2" {
		t.Fatalf("admins %v", f.admins())
	}
	if s := f.status(c.ID); s.Status != StatusDenied || s.Reason != ReasonAdminsRemoved {
		t.Fatalf("%+v", s)
	}
	for _, conn := range []string{"c1", "c2"} {
		if err := f.m.ConnectionRemoved(ctx, conn); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.admins()) != 0 {
		t.Fatalf("admins %v", f.admins())
	}
	f.tick()
	ch := f.hk.of(EventAdminSetChanged)
	if len(ch) != 3 || ch[0]["removed"] != "c3" || ch[0]["reason"] != ChangeConnectionRemoved {
		t.Fatalf("webhooks %+v", ch)
	}
}

func TestCreateRefuses(t *testing.T) {
	f := newFixture(t, 1, "c1")
	big := `{"a":"` + strings.Repeat("x", MaxPayload) + `"}`
	for _, c := range []struct {
		req  Request
		code string
	}{
		{Request{Action: "vote.delete", Summary: "x", Payload: json.RawMessage(`{}`)}, CodeInvalidAction},
		{Request{Action: ActionVoteOpen, Summary: "", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: strings.Repeat("x", MaxSummary+1), Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "a\nb", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "a\u202eb", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "a\u2066b", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "a\u2028b", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "a\x7fb", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "\xffx", Payload: json.RawMessage(`{}`)}, CodeInvalidSummary},
		{Request{Action: ActionVoteOpen, Summary: "x", Payload: json.RawMessage(`[]`)}, CodeInvalidPayload},
		{Request{Action: ActionVoteOpen, Summary: "x", Payload: nil}, CodeInvalidPayload},
		{Request{Action: ActionVoteOpen, Summary: "x", Payload: json.RawMessage(`{"a":1,"a":2}`)}, CodeInvalidPayload},
		{Request{Action: ActionVoteOpen, Summary: "x", Payload: json.RawMessage(big)}, CodeInvalidPayload},
	} {
		if _, err := f.m.Create(context.Background(), c.req); codeOf(err) != c.code {
			t.Errorf("%+v: %v, want %s", c.req.Summary, err, c.code)
		}
	}
	f.create(ActionVoteOpen, "Tâche ✓ — d’accord", `{}`) // plain Unicode text is fine
}

func TestChallengeContext(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	s, err := ChallengeContext("VettID Member Service", strings.Repeat("é", 60), hash)
	if err != nil || len(s) > MaxContext {
		t.Fatalf("%q %v", s, err)
	}
	long := strings.Repeat("Long Service Name ", 7)
	s, err = ChallengeContext(long, strings.Repeat("é", 60), hash)
	if err != nil || len(s) > MaxContext || !strings.HasSuffix(s, "… — ref abababab") || !strings.Contains(s, "é…") {
		t.Fatalf("%d %q %v", len(s), s, err)
	}
	if _, err := ChallengeContext(strings.Repeat("x", MaxContext), "y", hash); err == nil {
		t.Fatal("no room")
	}
}

// Webhooks wait in the store until delivered, in order; an endpoint that
// is down holds up neither the tick nor the approval.
func TestWebhookRetry(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.hk.failed = errors.New("down")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	f.answer("c1", "approve")
	f.tick()
	if s := f.status(c.ID); s.Status != StatusApproved {
		t.Fatalf("status %q while the endpoint is down", s.Status)
	}
	if err := f.hk.out.Flush(context.Background()); err == nil {
		t.Fatal("no error")
	}
	f.hk.failed = nil
	if ap := f.hk.of(EventApproved); len(ap) != 1 || ap[0]["approval_id"] != c.ID {
		t.Fatalf("%+v", ap)
	}
}

func TestAuditIDsIncrease(t *testing.T) {
	f := newFixture(t, 3, "c1", "c2", "c3")
	for i := 0; i < 4; i++ {
		f.create(ActionVoteOpen, fmt.Sprint("Open ", i), `{}`) // all in one millisecond
	}
	es := f.audit()
	if len(es) != 4 {
		t.Fatalf("%d entries", len(es))
	}
	for i := 1; i < len(es); i++ {
		if es[i].ID <= es[i-1].ID || es[i].Summary != fmt.Sprint("Open ", i) {
			t.Fatalf("order %v", es)
		}
	}
	p, err := f.m.Audit(context.Background(), es[3].ID, 10)
	if err != nil || len(p.Entries) != 0 || p.Next != "" {
		t.Fatalf("%+v %v", p, err)
	}
	if incrementULID("01ARZ3NDEKTSV4RRFFQ69G5FAZ") != "01ARZ3NDEKTSV4RRFFQ69G5FB0" {
		t.Fatal("increment")
	}
}

// Approval challenges carry the approval purpose (VAULT-MESSAGING 0.65.0
// §10.4.1), so a member's vault shows its approval screen and counts them
// in the approval bucket.
func TestApprovalPurpose(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.create(ActionVoteOpen, "Open the vote", `{}`)
	if len(f.p.purposes) != 2 {
		t.Fatalf("%d challenges", len(f.p.purposes))
	}
	for _, p := range f.p.purposes {
		if p != peerwire.PurposeApproval {
			t.Fatalf("purpose %q", p)
		}
	}
}

// An approval signed without a purpose is audited, marked no_purpose,
// and not counted (§10.4) unless AllowNoPurpose; then it counts, still
// marked.
func TestApprovalWithoutPurpose(t *testing.T) {
	for _, allow := range []bool{false, true} {
		f := newFixture(t, 1, "c1")
		f.m.AllowNoPurpose = allow
		a := f.create(ActionVoteOpen, "Open the vote", `{}`)
		f.answerTo(f.p.last("c1"), "approve-no-purpose")
		got := f.status(a.ID)
		if want := map[bool]string{false: StatusPending, true: StatusApproved}[allow]; got.Status != want {
			t.Fatalf("allow %v: status %q", allow, got.Status)
		}
		var resp *AuditEntry
		for _, e := range f.audit() {
			if e.Type == AuditResponse {
				resp = &e
			}
		}
		if resp == nil || resp.Reason != ReasonNoPurpose || *resp.Counted != allow {
			t.Fatalf("allow %v: entry %+v", allow, resp)
		}
	}
}

// An outstanding challenge that runs out while the approval is open is
// logged, queued as a webhook, and shows in the status as remind_needed
// until a reminder sends a new one.
func TestChallengeExpired(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 || s.RemindNeeded == nil {
		t.Fatalf("remind_needed at creation: %#v", s.RemindNeeded)
	}
	old := f.p.last("c1")
	f.clk.Advance(RemindInterval)
	f.answer("c1", "expire")
	f.tick()
	evs := f.hk.of(EventChallengeExpired)
	if len(evs) != 1 {
		t.Fatalf("webhooks %+v", evs)
	}
	d := evs[0]
	st := f.status(c.ID)
	if d["approval_id"] != c.ID || d["action"] != ActionVoteOpen || d["connection_id"] != "c1" || d["request_id"] != old.req ||
		d["expires_at"] != st.ExpiresAt.Format(time.RFC3339) || d["_connection_id"] != "c1" {
		t.Fatalf("payload %+v", d)
	}
	if got := strings.Join(st.RemindNeeded, ","); got != "c1" || st.Status != StatusPending {
		t.Fatalf("status %+v", st)
	}
	logs := f.logs.String()
	if !strings.Contains(logs, `msg="approval challenge expired"`) || !strings.Contains(logs, "request_id="+old.req) ||
		!strings.Contains(logs, "connection_id=c1") || !strings.Contains(logs, "approval_id="+c.ID) {
		t.Fatalf("logs %s", logs)
	}
	// The same event again matches no outstanding challenge.
	f.answerTo(old, "expire")
	f.tick()
	if len(f.hk.of(EventChallengeExpired)) != 1 {
		t.Fatal("webhook twice")
	}
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || strings.Join(r.Reminded, ",") != "c1,c2" {
		t.Fatalf("%+v %v", r, err)
	}
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 {
		t.Fatalf("after remind %+v", s.RemindNeeded)
	}
}

// A challenge sent for an approval lasts as long as the approval: at least
// 10 minutes, at most 24 hours (VAULT-MESSAGING 0.82.0 §10.4); a reminder
// sends the approval's remaining life.
func TestChallengeLife(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	f.m.TTL = 6 * time.Hour
	f.create(ActionVoteOpen, "Open", `{}`)
	if got := f.p.last("c1").ttl; got != 6*time.Hour {
		t.Fatalf("ttl %v", got)
	}
	f.p.fail = map[string]error{"c1": peer.ErrNotFound}
	g := f.create(ActionVoteOpen, "Open again", `{}`)
	f.p.fail = nil
	f.clk.Advance(2 * time.Hour)
	if _, err := f.m.Remind(context.Background(), g.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.p.last("c1").ttl; got != 4*time.Hour {
		t.Fatalf("reminder ttl %v", got)
	}
	f.clk.Advance(24 * time.Hour) // the first challenges are over
	f.m.TTL = 7 * 24 * time.Hour
	f.create(ActionVoteOpen, "Third", `{}`)
	if got := f.p.last("c1").ttl; got != peer.MaxApprovalChallengeTTL {
		t.Fatalf("capped ttl %v", got)
	}
	f.m.TTL = 11 * time.Minute
	f.create(ActionVoteOpen, "Fourth", `{}`)
	f.clk.Advance(5 * time.Minute)
	f.p.fail = map[string]error{"c1": peer.ErrNotFound}
	h := f.create(ActionVoteOpen, "Fifth", `{}`)
	f.p.fail = nil
	f.clk.Advance(10 * time.Minute)
	if _, err := f.m.Remind(context.Background(), h.ID); err != nil {
		t.Fatal(err)
	}
	if got := f.p.last("c1").ttl; got != RemindInterval {
		t.Fatalf("minimum ttl %v", got)
	}
}

// A challenge that ends with the approval raises no
// approval.challenge_expired: the approval's own expiry is reported.
func TestChallengeEndsWithApproval(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	f.m.TTL = time.Hour
	c := f.create(ActionVoteOpen, "Open", `{}`)
	ch := f.p.last("c1")
	f.clk.Advance(time.Hour)
	f.answerTo(ch, "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 0 {
		t.Fatalf("%d challenge_expired webhooks", n)
	}
	if strings.Contains(f.logs.String(), "approval challenge expired") {
		t.Fatal("logged")
	}
	if n := len(f.hk.of(EventExpired)); n != 1 {
		t.Fatalf("%d approval.expired webhooks", n)
	}
	if s := f.status(c.ID); s.Status != StatusExpired {
		t.Fatalf("%+v", s)
	}
}

// A long challenge that expires while the approval is still open (a
// shorter life than the approval's) is still reported.
func TestChallengeExpiresBeforeApproval(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	c := f.create(ActionVoteOpen, "Open", `{}`)
	ch := f.p.last("c1")
	ch.ttl = 2 * time.Hour // as if it had been sent with less than the approval's life
	f.clk.Advance(2 * time.Hour)
	f.answerTo(ch, "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 1 {
		t.Fatalf("%d webhooks", n)
	}
	if s := f.status(c.ID); len(s.RemindNeeded) != 1 {
		t.Fatalf("%+v", s)
	}
}

// With every unanswered admin holding a live challenge there is nothing
// to remind, and no challenge is sent.
func TestRemindNothingToRemind(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	f.m.LongChallenges = true
	c := f.create(ActionVoteOpen, "Open", `{}`)
	// Nothing to remind is answered before too_soon.
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeNothingToRemind {
		t.Fatalf("%v", err)
	}
	f.clk.Advance(RemindInterval)
	n := len(f.p.sent)
	if _, err := f.m.Remind(context.Background(), c.ID); codeOf(err) != CodeNothingToRemind {
		t.Fatalf("%v", err)
	}
	if len(f.p.sent) != n || len(f.p.cancelled) != 0 {
		t.Fatal("a live challenge was touched")
	}
}

// No webhook when the expired request is not an open approval's
// outstanding challenge: answered, settled, or past the approval's time.
func TestChallengeExpiredQuiet(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	first := f.p.last("c1")
	f.answer("c1", "approve")
	f.answerTo(first, "expire") // answered already
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 {
		t.Fatalf("answered admin needs no reminder: %v", s.RemindNeeded)
	}
	f.answer("c2", "approve") // settles
	f.answerTo(f.p.last("c2"), "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 0 {
		t.Fatalf("%d webhooks", n)
	}
	if s := f.status(c.ID); s.Status != StatusApproved || len(s.RemindNeeded) != 0 {
		t.Fatalf("%+v", s)
	}
	// Past the approval's time, before the expiry is settled.
	g := newFixture(t, 1, "c1")
	g.m.TTL = time.Hour
	d := g.create(ActionVoteOpen, "Open", `{}`)
	g.clk.Advance(time.Hour)
	g.answer("c1", "expire")
	if n := len(g.hk.of(EventChallengeExpired)); n != 0 {
		t.Fatalf("%d webhooks after the approval's time", n)
	}
	if s := g.status(d.ID); s.Status != StatusExpired || len(s.RemindNeeded) != 0 {
		t.Fatalf("%+v", s)
	}
	if strings.Contains(g.logs.String(), "approval challenge expired") {
		t.Fatal("logged")
	}
}

// An admin who left the set is not asked to be reminded, and an expiry
// of its challenge is not announced.
func TestRemindNeededLeavesWithAdmin(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	old := f.p.last("c2")
	if err := f.m.ConnectionRemoved(context.Background(), "c2"); err != nil {
		t.Fatal(err)
	}
	f.answerTo(old, "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 0 {
		t.Fatalf("%d webhooks for a removed admin", n)
	}
	if s := f.status(c.ID); s.Status != StatusPending || len(s.RemindNeeded) != 0 || s.RemindAfter != nil {
		t.Fatalf("%+v", s)
	}
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 {
		t.Fatalf("after remind %v", s.RemindNeeded)
	}
}

// An admin who could not be challenged is listed at once, with the time
// from which a reminder is accepted.
func TestRemindNeededNotSent(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	f.p.fail = map[string]error{"c2": peer.ErrNotFound}
	c := f.create(ActionVoteOpen, "Open", `{}`)
	s := f.status(c.ID)
	if strings.Join(s.RemindNeeded, ",") != "c2" || s.RemindAfter == nil ||
		!s.RemindAfter.Equal(f.clk.Now().Add(RemindInterval)) {
		t.Fatalf("%+v", s)
	}
	f.p.fail = nil
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(context.Background(), c.ID); err != nil {
		t.Fatal(err)
	}
	if s := f.status(c.ID); len(s.RemindNeeded) != 0 || s.RemindAfter != nil {
		t.Fatalf("%+v", s)
	}
}

// With the gate off (member vaults before 0.82.0) a challenge lasts 10
// minutes, and what #105 reported still holds: the webhook, remind_needed,
// and a reminder that challenges every admin who has not answered.
func TestChallengeShortWithoutGate(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2")
	c := f.create(ActionVoteOpen, "Open", `{}`)
	ch := f.p.last("c1")
	if ch.ttl != RemindInterval {
		t.Fatalf("ttl %v", ch.ttl)
	}
	f.clk.Advance(RemindInterval)
	f.answerTo(ch, "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 1 {
		t.Fatalf("%d webhooks", n)
	}
	if s := f.status(c.ID); strings.Join(s.RemindNeeded, ",") != "c1" {
		t.Fatalf("%+v", s)
	}
	r, err := f.m.Remind(context.Background(), c.ID)
	if err != nil || strings.Join(r.Reminded, ",") != "c1,c2" {
		t.Fatalf("%+v %v", r, err)
	}
	if got := f.p.last("c1").ttl; got != RemindInterval {
		t.Fatalf("reminder ttl %v", got)
	}
}

// With the gate on, a third concurrent approval challenge to a connection
// is sent with 10 minutes (the member vault keeps two long ones); when it
// runs out the approval is still open, so it is reported and the admin
// can be reminded, while the long ones end quietly with their approvals.
func TestThirdConcurrentLongChallenge(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	f.create(ActionVoteOpen, "One", `{}`)
	f.create(ActionVoteOpen, "Two", `{}`)
	third := f.create(ActionVoteOpen, "Three", `{}`)
	ch := f.p.last("c1")
	if ch.ttl != RemindInterval {
		t.Fatalf("third ttl %v", ch.ttl)
	}
	f.clk.Advance(RemindInterval)
	f.answerTo(ch, "expire")
	f.tick()
	if n := len(f.hk.of(EventChallengeExpired)); n != 1 {
		t.Fatalf("%d webhooks", n)
	}
	if s := f.status(third.ID); strings.Join(s.RemindNeeded, ",") != "c1" {
		t.Fatalf("%+v", s)
	}
	if r, err := f.m.Remind(context.Background(), third.ID); err != nil || strings.Join(r.Reminded, ",") != "c1" {
		t.Fatalf("%+v %v", r, err)
	}
}

// A forced re-send challenges the named admins again, withdrawing a live
// challenge first, whatever the gate says; only admins who have not
// answered; still at most once per RemindInterval.
func TestRemindForce(t *testing.T) {
	for _, gate := range []bool{true, false} {
		f := newFixture(t, 2, "c1", "c2")
		f.m.LongChallenges = gate
		c := f.create(ActionVoteOpen, "Open", `{}`)
		ctx := context.Background()
		old1, old2 := f.p.last("c1"), f.p.last("c2")
		if _, err := f.m.Remind(ctx, c.ID, "c1"); codeOf(err) != CodeTooSoon {
			t.Fatalf("gate %v: too soon: %v", gate, err)
		}
		f.clk.Advance(RemindInterval)
		if _, err := f.m.Remind(ctx, c.ID, "c9"); codeOf(err) != CodeNotAdmin {
			t.Fatalf("gate %v: not an admin: %v", gate, err)
		}
		r, err := f.m.Remind(ctx, c.ID, "c1")
		if err != nil || strings.Join(r.Reminded, ",") != "c1" {
			t.Fatalf("gate %v: %+v %v", gate, r, err)
		}
		if !slices.Contains(f.p.cancelled, old1.req) || slices.Contains(f.p.cancelled, old2.req) {
			t.Fatalf("gate %v: cancelled %v", gate, f.p.cancelled)
		}
		if now := f.p.last("c1"); now.req == old1.req || f.p.last("c2").req != old2.req {
			t.Fatalf("gate %v: new challenge to c1 only", gate)
		}
		// The new challenge is the one that counts.
		f.answerTo(f.p.last("c1"), "approve")
		if s := f.status(c.ID); len(s.Approvals) != 1 {
			t.Fatalf("gate %v: %+v", gate, s)
		}
		f.clk.Advance(RemindInterval)
		if _, err := f.m.Remind(ctx, c.ID, "c1"); codeOf(err) != CodeAnswered {
			t.Fatalf("gate %v: answered: %v", gate, err)
		}
		before := len(f.p.sent)
		if _, err := f.m.Remind(ctx, c.ID, "c2", "c2"); err != nil {
			t.Fatalf("gate %v: %v", gate, err)
		}
		if n := len(f.p.sent) - before; n != 1 {
			t.Fatalf("gate %v: %d challenges for a duplicate id", gate, n)
		}
	}
}

// A forced re-send follows the place limit like any challenge: with two
// other approval challenges holding the places, the new one goes out with
// 10 minutes.
func TestRemindForcePlaceLimit(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	a := f.create(ActionVoteOpen, "One", `{}`)
	f.create(ActionVoteOpen, "Two", `{}`)
	f.clk.Advance(RemindInterval)
	f.create(ActionVoteOpen, "Three", `{}`) // the places are taken: 10 minutes
	if got := f.p.last("c1").ttl; got != RemindInterval {
		t.Fatalf("third %v", got)
	}
	if _, err := f.m.Remind(context.Background(), a.ID, "c1"); err != nil {
		t.Fatal(err)
	}
	// One's old challenge is withdrawn, but Two and Three hold the places.
	if got := f.p.last("c1").ttl; got != RemindInterval {
		t.Fatalf("forced re-send %v", got)
	}
}

// A forced re-send is refused (ask_budget) while 5 approval challenges the
// service sent an admin, from any approval, still count: until each one's
// exp plus 24 hours plus the clock skew, since the member's vault may
// receive a challenge as late as its exp (VAULT-MESSAGING §10.4.1). A
// refused force withdraws and sends nothing.
func TestRemindForceAskBudget(t *testing.T) {
	for _, gate := range []bool{true, false} {
		f := newFixture(t, 1, "c1")
		f.m.LongChallenges = gate
		f.m.TTL = 72 * time.Hour
		ctx := context.Background()
		var ids []string
		for i := range askBudget {
			ids = append(ids, f.create(ActionVoteOpen, fmt.Sprint("Open ", i), `{}`).ID)
			f.clk.Advance(time.Hour)
		}
		l, err := f.m.asks(ctx, "c1")
		if err != nil || len(l.Exp) != askBudget {
			t.Fatalf("gate %v: %+v %v", gate, l, err)
		}
		// Each counts at least until its challenge's exp plus a day.
		want := f.p.first("c1").at.Add(f.p.first("c1").ttl)
		if l.Exp[0].Before(want) {
			t.Fatalf("gate %v: logged exp %v before the challenge's %v", gate, l.Exp[0], want)
		}
		f.clk.Advance(RemindInterval)
		before, cancelled := len(f.p.sent), len(f.p.cancelled)
		if _, err := f.m.Remind(ctx, ids[4], "c1"); codeOf(err) != CodeAskBudget {
			t.Fatalf("gate %v: sixth: %v", gate, err)
		}
		if len(f.p.sent) != before || len(f.p.cancelled) != cancelled || f.status(ids[4]).Status != StatusPending {
			t.Fatalf("gate %v: a refused force sent or withdrew something", gate)
		}
		// Up to the first one's exp + 24 h + skew it still counts.
		end := l.Exp[0].Add(askWindow + peer.ClockSkew)
		f.clk.Advance(end.Sub(f.clk.Now()) - time.Millisecond)
		if _, err := f.m.Remind(ctx, ids[4], "c1"); codeOf(err) != CodeAskBudget {
			t.Fatalf("gate %v: just before the end: %v", gate, err)
		}
		f.clk.Advance(time.Millisecond)
		if r, err := f.m.Remind(ctx, ids[4], "c1"); err != nil || fmt.Sprint(r.Reminded) != "[c1]" {
			t.Fatalf("gate %v: after: %+v %v", gate, r, err)
		}
		// That send counts too: the next force is refused again.
		f.clk.Advance(RemindInterval)
		if _, err := f.m.Remind(ctx, ids[3], "c1"); codeOf(err) != CodeAskBudget {
			t.Fatalf("gate %v: after the re-send: %v", gate, err)
		}
	}
}

// A long challenge delivered late (held in the outbox while the member's
// vault is away) can reach the member up to 24 hours after it was sent and
// open the member's window then: 25 hours after five long challenges a
// force is still refused.
func TestRemindForceAskBudgetLateDelivery(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.LongChallenges = true
	f.m.TTL = 72 * time.Hour
	ctx := context.Background()
	var ids []string
	for i := range askBudget {
		ids = append(ids, f.create(ActionVoteOpen, fmt.Sprint("Open ", i), `{}`).ID)
	}
	// Each is logged with the life asked for (24 h), even one the peer
	// sends shorter for want of a long place: counting longer only refuses
	// more.
	if l, err := f.m.asks(ctx, "c1"); err != nil || l.Exp[0].Before(f.clk.Now().Add(peer.MaxApprovalChallengeTTL)) {
		t.Fatalf("%+v %v", l, err)
	}
	f.clk.Advance(25 * time.Hour)
	if _, err := f.m.Remind(ctx, ids[0], "c1"); codeOf(err) != CodeAskBudget {
		t.Fatalf("25 h later: %v", err)
	}
	f.clk.Advance(23*time.Hour + askSlack + peer.ClockSkew + time.Millisecond)
	if _, err := f.m.Remind(ctx, ids[0], "c1"); err != nil {
		t.Fatalf("after exp + slack + 24 h + skew: %v", err)
	}
}

// A force naming several admins is refused when any one is at the budget,
// even if the others are not; nothing is withdrawn from them.
func TestRemindForceAskBudgetAnyNamed(t *testing.T) {
	f := newFixture(t, 1, "c1", "c2")
	ctx := context.Background()
	for range askBudget {
		if err := f.m.logAsk(ctx, "c1", f.clk.Now().Add(RemindInterval)); err != nil {
			t.Fatal(err)
		}
	}
	c := f.create(ActionVoteOpen, "Open", `{}`)
	f.clk.Advance(RemindInterval)
	old2 := f.p.last("c2")
	before := len(f.p.sent)
	if _, err := f.m.Remind(ctx, c.ID, "c2", "c1"); codeOf(err) != CodeAskBudget {
		t.Fatalf("%v", err)
	}
	if len(f.p.sent) != before || slices.Contains(f.p.cancelled, old2.req) {
		t.Fatal("a refused force sent or withdrew something")
	}
	if r, err := f.m.Remind(ctx, c.ID, "c2"); err != nil || fmt.Sprint(r.Reminded) != "[c2]" {
		t.Fatalf("c2 alone: %+v %v", r, err)
	}
}

// failStore fails Apply for any batch that writes kind, and Get of
// getKind.
type failStore struct {
	peer.Store
	kind    string
	getKind string
}

func (s *failStore) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if kind == s.getKind {
		return nil, false, errors.New("store down")
	}
	return s.Store.Get(ctx, kind, id)
}

func (s *failStore) Apply(ctx context.Context, changes []peer.Change) error {
	for _, c := range changes {
		if c.Kind == s.kind {
			return errors.New("store down")
		}
	}
	return s.Store.Apply(ctx, changes)
}

// A challenge is logged before it is sent: one whose approval cannot be
// saved still counts, and an admin whose log cannot be written is not
// challenged.
func TestAskLogBeforeSend(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, "c1")
	f.m.Store = &failStore{Store: f.st, kind: kindApproval}
	if _, err := f.m.Create(ctx, Request{Action: ActionVoteOpen, Summary: "Open", Payload: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("created with the store down")
	}
	if len(f.p.sent) != 1 {
		t.Fatalf("%d sent", len(f.p.sent))
	}
	if l, err := f.m.asks(ctx, "c1"); err != nil || len(l.Exp) != 1 {
		t.Fatalf("the unsaved approval's challenge is not counted: %+v %v", l, err)
	}
	f = newFixture(t, 1, "c1")
	f.m.Store = &failStore{Store: f.st, kind: kindAsks}
	f.create(ActionVoteOpen, "Open", `{}`)
	if len(f.p.sent) != 0 {
		t.Fatalf("sent %d without logging", len(f.p.sent))
	}
}

// Plain reminders count in the log as well; the log keeps only the
// askBudget entries that count longest, and the record lasts as long as
// the newest counts.
func TestAskLogBounded(t *testing.T) {
	f := newFixture(t, 1, "c1")
	ctx := context.Background()
	c := f.create(ActionVoteOpen, "Open", `{}`)
	for range 2 * askBudget {
		f.clk.Advance(RemindInterval)
		if _, err := f.m.Remind(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
	}
	l, err := f.m.asks(ctx, "c1")
	if err != nil || len(l.Exp) != askBudget || !l.full(f.clk.Now()) {
		t.Fatalf("%+v %v", l, err)
	}
	newest := l.Exp[askBudget-1]
	if want := f.clk.Now().Add(RemindInterval); newest.Before(want) {
		t.Fatalf("newest %v, want at least %v", newest, want)
	}
	// An entry that counts less long does not push out one that counts longer.
	if err := f.m.logAsk(ctx, "c1", l.Exp[0].Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if l2, _ := f.m.asks(ctx, "c1"); !slices.Equal(l2.Exp, l.Exp) {
		t.Fatalf("%v != %v", l2.Exp, l.Exp)
	}
	f.clk.Advance(RemindInterval)
	if _, err := f.m.Remind(ctx, c.ID, "c1"); codeOf(err) != CodeAskBudget {
		t.Fatalf("force after plain reminders: %v", err)
	}
	l, _ = f.m.asks(ctx, "c1")
	end := l.Exp[askBudget-1].Add(askWindow + peer.ClockSkew)
	f.clk.Advance(end.Sub(f.clk.Now()) - time.Millisecond)
	if _, ok, _ := f.st.Get(ctx, kindAsks, "c1"); !ok {
		t.Fatal("ask log gone while its newest entry counts")
	}
	f.clk.Advance(time.Millisecond)
	if _, ok, _ := f.st.Get(ctx, kindAsks, "c1"); ok {
		t.Fatal("ask log kept after its newest entry stopped counting")
	}
}

// An ask log that cannot be read, or does not decode, fails closed: a
// forced reminder is refused with an error before anything is withdrawn
// or sent, and a plain one skips that admin.
func TestAskLogUnreadable(t *testing.T) {
	ctx := context.Background()
	for _, how := range []string{"get", "decode"} {
		f := newFixture(t, 1, "c1")
		c := f.create(ActionVoteOpen, "Open", `{}`)
		f.clk.Advance(RemindInterval)
		old := f.p.last("c1")
		before := len(f.p.sent)
		if how == "get" {
			f.m.Store = &failStore{Store: f.st, getKind: kindAsks}
		} else if err := f.st.Apply(ctx, []peer.Change{{Kind: kindAsks, ID: "c1", Data: []byte("{"),
			Expires: f.clk.Now().Add(time.Hour)}}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.m.Remind(ctx, c.ID, "c1"); err == nil || codeOf(err) != "" {
			t.Fatalf("%s: force: %v", how, err)
		}
		if len(f.p.sent) != before || slices.Contains(f.p.cancelled, old.req) {
			t.Fatalf("%s: a failed force sent or withdrew something", how)
		}
		if r, err := f.m.Remind(ctx, c.ID); err != nil || len(r.Reminded) != 0 || len(f.p.sent) != before {
			t.Fatalf("%s: plain: %+v %v", how, r, err)
		}
		if how == "decode" && !strings.Contains(f.logs.String(), "approval ask log unreadable") {
			t.Fatalf("no log line: %s", f.logs.String())
		}
	}
}
