package approval

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
}

type sent struct{ conn, req, ctxt string }

func (p *fakePeer) Connection(id string) (peer.ConnectionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active[id] {
		return peer.ConnectionInfo{}, false
	}
	return peer.ConnectionInfo{ID: id, State: peer.StateActive}, true
}

func (p *fakePeer) Authenticate(_ context.Context, conn, ctxt string, _ time.Duration) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.fail[conn]; err != nil {
		return "", err
	}
	p.n++
	req := fmt.Sprintf("req%02d", p.n)
	p.sent = append(p.sent, sent{conn, req, ctxt})
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
	p := &fakePeer{active: map[string]bool{}}
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
	}
	switch how {
	case "approve", "approve-changed":
		e.Type, e.KeyChanged = peer.EventSignInApproved, how == "approve-changed"
		sig()
	case "deny":
		e.Type, e.Reason = peer.EventSignInDenied, "denied"
	case "bad":
		e.Type, e.Reason = peer.EventSignInDenied, "bad_signature"
		sig()
	case "expire":
		e.Type = peer.EventSignInExpired
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
	old := f.p.last("c2").req
	f.clk.Advance(time.Second)
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
