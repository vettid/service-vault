package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// confirms counts the hs.confirm the member received.
func confirms(m *peertest.Member) int {
	n := 0
	for _, in := range m.Got {
		if in.Type == handshake.TypeConfirm {
			n++
		}
	}
	return n
}

func epochOf(c *Connection) [suite.EpochIDSize]byte { return c.kr.Current().ID() }

// memberRekey has the member rekey and the service activate it as
// responder; it returns the epochs before and after.
func memberRekey(t *testing.T, f *fixture, m *peertest.Member, cid string) (e1, e2 [suite.EpochIDSize]byte) {
	t.Helper()
	e1 = epochOf(f.p.conns[cid])
	m.StartRekey()
	f.pump()
	e2 = epochOf(f.p.conns[cid])
	if e2 == e1 || m.KR.Current().ID() != e2 {
		t.Fatal("the member's rekey did not complete")
	}
	return e1, e2
}

// A connection's first epoch is its confirmed epoch. At a member's rekey
// the service activates the new epoch as responder, sends hs.confirm, and
// the confirmed epoch stays the old one, which keeps its rk, until the
// member sends something under the new one; it then moves, and the old
// epoch's rk is released (§6.3.1 Responder).
func TestConfirmedEpochMovesOnMemberMessage(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	if e := epochOf(c); !bytes.Equal(c.Confirmed, e[:]) || len(c.Epochs) != 1 || !c.Epochs[0].Received {
		t.Fatalf("first epoch not confirmed, or its flag clear: %+v", c.Epochs)
	}
	got := confirms(m)
	e1, e2 := memberRekey(t, f, m, cid)
	c = f.p.conns[cid]
	if !bytes.Equal(c.Confirmed, e1[:]) || confirms(m) != got+1 {
		t.Fatalf("after the rekey: confirmed moved or no hs.confirm (%d)", confirms(m)-got)
	}
	if old := c.kr.Find(e1); old == nil || !old.HasRK() {
		t.Fatal("the confirmed epoch did not keep its rk")
	}
	m.Send(peerwire.TypeProfileUpdate, m.ProfileBody(2))
	f.pump()
	c = f.p.conns[cid]
	if !bytes.Equal(c.Confirmed, e2[:]) {
		t.Fatal("a member message under the new epoch did not confirm it")
	}
	if old := c.kr.Find(e1); old != nil && old.HasRK() {
		t.Fatal("the old confirmed epoch kept its rk")
	}
	if !c.epochMeta(e2[:]).Received {
		t.Fatal("the received flag is not set")
	}
}

// A batch holding a member message under the confirmed epoch, while it
// is not current, gets hs.confirm again (§6.3.1 Responder, R29-R3).
func TestReconfirmPerBatch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	late, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate,
		TS: f.clk.Now(), Body: m.ProfileBody(2)})
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := memberRekey(t, f, m, cid)
	got := confirms(m)
	m.DepositTo(m.SvcStand, late) // under e1, delivered after the rekey
	f.pump()
	c := f.p.conns[cid]
	if confirms(m) != got+1 || !bytes.Equal(c.Confirmed, e1[:]) {
		t.Fatalf("%d hs.confirm for a message under the confirmed epoch", confirms(m)-got)
	}
}

// While the current epoch, activated as responder, is unconfirmed,
// hs.confirm goes out again ConfirmResend after the last one, and not
// before (§6.3.1 "hs.confirm again").
func TestConfirmResend(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	memberRekey(t, f, m, cid)
	c := f.p.conns[cid]
	first := c.ConfirmAt
	f.clk.Advance(ConfirmResend - time.Hour)
	f.tick()
	if !c.ConfirmAt.Equal(first) {
		t.Fatal("hs.confirm again before ConfirmResend")
	}
	f.clk.Advance(time.Hour)
	f.tick()
	if !c.ConfirmAt.Equal(f.clk.Now()) { // queued, and deposited by the tick
		t.Fatalf("no hs.confirm again after ConfirmResend: at %v, now %v, epochs %+v, confirmed %x current %x\n%s",
			c.ConfirmAt, f.clk.Now(), c.Epochs, c.Confirmed, c.LastEpochID, f.logs.String())
	}
}

// An hs.fin that opens under the current epoch (a duplicate) is acked and
// ignored: no answer, and it moves no confirmed epoch (R29-T3).
func TestDuplicateFinIgnored(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	e1, _ := memberRekey(t, f, m, cid)
	id := m.SendInner(&envelope.Inner{ID: m.NewID(), Type: handshake.TypeFin, TS: f.clk.Now(), Body: []byte("{}")})
	f.pump()
	c := f.p.conns[cid]
	if !bytes.Equal(c.Confirmed, e1[:]) {
		t.Fatal("an hs.fin moved the confirmed epoch")
	}
	for _, in := range m.Got {
		if in.Re == id {
			t.Fatal("an hs.fin was answered")
		}
	}
}

// A member's rekey hs.init is answered once: delivered again after its
// answer is gone, it is not answered (R29-T3).
func TestRekeyInitAnsweredOnce(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	for id := range f.p.awaiting {
		f.p.dropAwaiting(id, f.clk.Now()) // as if it expired
	}
	m.DepositTo(m.SvcStand, m.LastRekeyInit())
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 0 || !strings.Contains(f.logs.String(), "reason=rekey_init_replayed") {
		t.Fatalf("answered again: %d awaiting", len(f.p.awaiting))
	}
}

// A member's reconnect, established at its hs.fin, ends the service's
// open answers to that member's rekeys (§6.3.1 "A reconnect ends R's
// rekey answers"): the rekey's undeposited hs.resp goes with it, and the
// pair ends on the reconnect's epoch.
func TestReconnectEndsRekeyAnswers(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.StartRekey()
	f.p.mu.Lock()
	f.failDeposit = func(string, string) error { return errUnavailable }
	f.p.mu.Unlock()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if len(f.p.awaiting) != 1 {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	// The rekey's hs.resp is lost: the member never answers it.
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == cid })
	f.failDeposit = nil
	m.IgnoreStray = true
	m.Reconnect()
	f.pump()
	c := f.p.conns[cid]
	if len(f.p.awaiting) != 0 || !strings.Contains(f.logs.String(), "reason=rekey_answer_ended") {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	if epochOf(c) != m.KR.Current().ID() {
		t.Fatal("the pair is not on the reconnect's epoch")
	}
}

// The service advertises hs_confirm and relay_follow: in its messages'
// inner features and in its profile.update (§10.8; RELEASE-29 §6).
func TestFeaturesAdvertised(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	var prof *envelope.Inner
	for _, in := range m.Got {
		if in.Type == peerwire.TypeProfileUpdate {
			prof = in
		}
	}
	if prof == nil || !slices.Equal(prof.Features, serviceFeatures) {
		t.Fatalf("inner features: %v", prof)
	}
	var b struct {
		Version  uint64   `json:"version"`
		Features []string `json:"features"`
	}
	if err := json.Unmarshal(prof.Body, &b); err != nil || b.Version != 1 || !slices.Equal(b.Features, []string{"hs_confirm", "relay_follow"}) {
		t.Fatalf("profile.update: %s", prof.Body)
	}
}

// A durable message waiting under the epoch a member's rekey replaces is
// sealed again under the new one, with the same inner id, before it goes
// (§8.3 "Re-sealed at a key change").
func TestResealedAtKeyChange(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	var e *outboxEntry
	for _, o := range f.p.outbox {
		if o.ConnID == cid && !o.Confirm && o.Token == "" {
			if env, err := envelope.Parse(o.Payload); err == nil {
				if in, err := c.kr.Current().OpenSent(env); err == nil && in.ID == id {
					e = o
				}
			}
		}
	}
	if e == nil {
		t.Fatal("the message is not waiting")
	}
	f.clk.Advance(time.Minute) // a fresh ts differs from the first
	f.failDeposit = func(string, string) error { return errUnavailable }
	m.Step() // the member's hs.fin
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Parse(e.Payload)
	if err != nil {
		t.Fatal(err)
	}
	in, err := f.p.conns[cid].kr.Current().OpenSent(env)
	if err != nil || in.ID != id {
		t.Fatalf("not sealed again under the new epoch: %v", err)
	}
	if !in.TS.Equal(f.clk.Now()) {
		t.Fatalf("an untried entry kept its ts %v", in.TS)
	}
	f.failDeposit = nil
	f.clk.Advance(time.Minute) // past the deposit backoff
	f.pump()
	n := 0
	for _, g := range m.Got {
		if g.ID == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the member got it %d times", n)
	}
}

// An untried message waiting more than RestampAfter is sealed again with
// a fresh ts at deposit; a tried one past the 16-day window is not
// delivered (§8.3 "At deposit").
func TestAtDeposit(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	fresh := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	old := f.p.sendTo(c, "connection.note", []byte(`{"x":2}`), f.clk.Now())
	for _, e := range f.p.outbox {
		if e.ConnID == cid {
			e.NotBefore = f.clk.Now().Add(RestampAfter + time.Hour)
		}
	}
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, e := range f.p.outbox {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := c.kr.Current().OpenSent(env); err == nil && in.ID == old {
				e.Tried = true
				e.NotBefore = f.clk.Now().Add(DedupeRetention + time.Hour)
			}
		}
	}
	f.clk.Advance(RestampAfter + time.Hour)
	m.IgnoreStray = true
	f.p.mu.Lock()
	f.p.drainOutbox(context.Background()) // re-seals, and waits for the write
	f.p.mu.Unlock()
	f.pump()
	var gotFresh *envelope.Inner
	for _, g := range m.Got {
		if g.ID == fresh {
			gotFresh = g
		}
	}
	if gotFresh == nil || !gotFresh.TS.After(f.clk.Now().Add(-time.Hour)) {
		t.Fatalf("not re-stamped: %v", gotFresh)
	}
	f.clk.Advance(DedupeRetention)
	f.tick()
	f.pump()
	for _, g := range m.Got {
		if g.ID == old {
			t.Fatal("a tried message past the window was delivered")
		}
	}
	if !strings.Contains(f.logs.String(), "reason=undelivered_window") {
		t.Fatalf("not audited:\n%s", f.logs.String())
	}
}

// Every waiting deposit is marked tried at load: a service has no clean
// end (§8.3 "A clean end").
func TestTriedAtLoad(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.sendTo(f.p.conns[cid], "connection.note", []byte(`{"x":1}`), f.clk.Now())
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A 429 is not an attempt that may have stored it: only the load marks.
	f.failDeposit = func(string, string) error { return &relayclient.Error{Status: 429, Code: "rate_limited"} }
	f.start()
	n := 0
	for _, e := range f.p.outbox {
		if e.Op == opDeposit {
			n++
			if !e.Tried {
				t.Fatal("a waiting deposit not marked tried at load")
			}
		}
	}
	if n == 0 {
		t.Fatal("nothing waiting")
	}
}

// OneDepositAttempt makes deposits one attempt and leaves the client's
// other calls alone.
func TestOneDepositAttempt(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := relayclient.New(srv.URL, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
	r := OneDepositAttempt(c)
	if _, err := r.Deposit(context.Background(), "mb", "tok", []byte("x")); err == nil {
		t.Fatal("no error from a 503")
	}
	if n.Load() != 1 || c.MaxAttempts == 1 {
		t.Fatalf("%d requests for one deposit; client attempts %d", n.Load(), c.MaxAttempts)
	}
}

// The confirmed epoch never moves back: a late message under an older
// epoch leaves it where it is.
func TestConfirmedNeverMovesBack(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	late, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate,
		TS: f.clk.Now(), Body: m.ProfileBody(2)})
	if err != nil {
		t.Fatal(err)
	}
	_, e2 := memberRekey(t, f, m, cid)
	m.Send(peerwire.TypeProfileUpdate, m.ProfileBody(3))
	f.pump()
	m.DepositTo(m.SvcStand, late)
	f.pump()
	if c := f.p.conns[cid]; !bytes.Equal(c.Confirmed, e2[:]) {
		t.Fatal("the confirmed epoch moved back")
	}
}

// A suspension ends an open reconnect without reconnect_failed: the
// connection stays suspended, not stale.
func TestReconnectEndedBySuspension(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	c.Reconnecting, c.State = true, StateSuspended
	f.p.reconnectFailed(c)
	if c.Reconnecting || c.State != StateSuspended || strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("state %s, reconnecting %v", c.State, c.Reconnecting)
	}
}

// hs.confirm and handshake messages do not count toward MaxOutboxPerConn.
func TestConfirmExemptFromOutboxBound(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	if !f.p.queueConfirm(c, f.clk.Now()) {
		t.Fatal("hs.confirm not queued")
	}
	f.p.startRekey(c, f.clk.Now()) // our rekey hs.init waits too
	if len(f.p.outgoing) != 1 {
		t.Fatal("no rekey started")
	}
	for i := 0; i < MaxOutboxPerConn; i++ {
		if f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now()) == "" {
			t.Fatalf("message %d refused: the hs.confirm counted", i)
		}
	}
}

// A deposit refused about the attempt (timestamp_stale, replay_detected)
// is retried, never ended; replay_detected marks it tried, and a third
// timestamp_stale is logged once (relay_clock_stale). Another 4xx ends it,
// audited (§8.3 case 8).
func TestDepositRefusals(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		ended  bool
		tried  bool
	}{
		{"timestamp_stale", 401, false, false},
		{"replay_detected", 409, false, true},
		{"bad_request", 400, true, false},
	} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		c := f.p.conns[cid]
		f.failDeposit = func(string, string) error { return &relayclient.Error{Status: tc.status, Code: tc.code} }
		id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
		for i := 0; i < 3; i++ {
			f.clk.Advance(time.Minute)
			f.tick()
		}
		var e *outboxEntry
		for _, o := range f.p.outbox {
			if env, err := envelope.Parse(o.Payload); err == nil {
				if in, err := c.kr.Current().OpenSent(env); err == nil && in.ID == id {
					e = o
				}
			}
		}
		if (e == nil) != tc.ended {
			t.Fatalf("%s: ended %v", tc.code, e == nil)
		}
		if tc.ended && !strings.Contains(f.logs.String(), "reason=undelivered_refused") {
			t.Fatalf("%s: not audited", tc.code)
		}
		if e != nil && e.Tried != tc.tried {
			t.Fatalf("%s: tried %v", tc.code, e.Tried)
		}
		if tc.code == "timestamp_stale" && strings.Count(f.logs.String(), "reason=relay_clock_stale") != 1 {
			t.Fatalf("relay_clock_stale logged %d times", strings.Count(f.logs.String(), "reason=relay_clock_stale"))
		}
	}
}

// A tried entry sealed again at a key change keeps its ts (§8.3), and a
// waiting hs.confirm for the replaced epoch is dropped.
func TestResealTriedKeepsTS(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil { // answered; hs.resp deposited
		t.Fatal(err)
	}
	c := f.p.conns[cid]
	if !f.p.queueConfirm(c, f.clk.Now()) {
		t.Fatal("no hs.confirm")
	}
	sent := f.clk.Now()
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), sent)
	for _, e := range f.p.outbox {
		if e.ConnID == cid && !e.Confirm {
			e.Tried = true // an earlier attempt may have reached the relay
		}
	}
	f.clk.Advance(time.Minute)
	f.failDeposit = func(string, string) error { return errUnavailable }
	m.Step() // the member's hs.fin
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	c = f.p.conns[cid]
	if epochOf(c) != m.KR.Current().ID() {
		t.Fatal("the member's rekey did not complete")
	}
	confirmsWaiting, found := 0, false
	for _, e := range f.p.outbox {
		if e.ConnID != cid {
			continue
		}
		if e.Confirm {
			confirmsWaiting++
		}
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := c.kr.Current().OpenSent(env); err == nil && in.ID == id {
				found = true
				if !in.TS.Equal(sent.Truncate(time.Millisecond)) {
					t.Fatalf("a tried entry took a fresh ts: %v", in.TS)
				}
			}
		}
	}
	if !found || confirmsWaiting != 1 {
		t.Fatalf("re-sealed %v, %d hs.confirm waiting (the replaced one is dropped, the new epoch's queued)", found, confirmsWaiting)
	}
}

// At the service's own rekey, waiting messages are not sealed again: its
// hs.fin goes first, and they follow under the old epoch, which the member
// still opens (RELEASE-29 §14: change 2 re-seals at the confirmation).
func TestOwnRekeyLeavesWaitingUnderOldEpoch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	old := c.kr.Current()
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick() // our rekey hs.init goes
	f.failDeposit = func(string, string) error { return errUnavailable }
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	var before []byte
	for _, e := range f.p.outbox {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := old.OpenSent(env); err == nil && in.ID == id {
				before = e.Payload
			}
		}
	}
	m.Step() // the member answers
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if epochOf(f.p.conns[cid]) == old.ID() {
		t.Fatal("our rekey did not complete")
	}
	kept := false
	for _, e := range f.p.outbox {
		kept = kept || bytes.Equal(e.Payload, before)
	}
	if before == nil || !kept {
		t.Fatal("the waiting message was sealed again under our new epoch")
	}
	f.failDeposit = nil
	f.clk.Advance(time.Minute)
	f.pump()
	n := 0
	for _, g := range m.Got {
		if g.ID == id {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the member got it %d times", n)
	}
}

// A 429's retry_after holds the next attempt (§8.6).
func TestRetryAfter429(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.failDeposit = func(string, string) error {
		return &relayclient.Error{Status: 429, Code: "rate_limited", RetryAfter: 120}
	}
	f.p.sendTo(f.p.conns[cid], "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.tick()
	for _, e := range f.p.outbox {
		if e.ConnID == cid && e.NotBefore.Before(f.clk.Now().Add(120*time.Second)) {
			t.Fatalf("retried before retry_after: %v", e.NotBefore.Sub(f.clk.Now()))
		}
	}
}

// A waiting hs.confirm queued more than RestampAfter ago is replaced by a
// fresh one (it would keep its ts past the member's window).
func TestStaleConfirmReplaced(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.failDeposit = func(string, string) error { return errUnavailable }
	memberRekeyNoPump(t, f, m, cid)
	c := f.p.conns[cid]
	if !f.p.confirmQueued(c) {
		t.Fatal("no hs.confirm waiting")
	}
	first := c.ConfirmAt
	f.clk.Advance(RestampAfter + time.Hour)
	f.tick()
	if !c.ConfirmAt.After(first) || !f.p.confirmQueued(c) {
		t.Fatal("the stale hs.confirm was not replaced")
	}
	n := 0
	for _, e := range f.p.outbox {
		if e.ConnID == cid && e.Confirm {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d hs.confirm waiting", n)
	}
}

// memberRekeyNoPump completes a member's rekey while the service's
// deposits after its hs.resp fail (the hs.confirm waits).
func memberRekeyNoPump(t *testing.T, f *fixture, m *peertest.Member, cid string) {
	t.Helper()
	fail := f.failDeposit
	f.failDeposit = nil
	m.StartRekey()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	f.failDeposit = fail
	m.Step()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	if epochOf(f.p.conns[cid]) != m.KR.Current().ID() {
		t.Fatal("the member's rekey did not complete")
	}
}

// After the service's own rekey, a member message under the older
// confirmed epoch gets no hs.confirm: the service is the initiator there.
func TestNoReconfirmAfterOwnRekey(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	late, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate,
		TS: f.clk.Now(), Body: m.ProfileBody(2)})
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	f.pump()
	if cur := f.p.conns[cid].epochMeta(f.p.conns[cid].LastEpochID); cur == nil || !cur.Mine {
		t.Fatal("our rekey did not complete")
	}
	got := confirms(m)
	m.DepositTo(m.SvcStand, late)
	f.pump()
	if confirms(m) != got {
		t.Fatal("hs.confirm sent after our own rekey")
	}
}

// A connection's waiting messages end with one audit entry each, the
// inner id as ref, when it is removed or suspended (§8.3 cases 4, 7).
func TestUndeliveredAudited(t *testing.T) {
	for _, tc := range []struct {
		reason string
		end    func(*fixture, *Connection)
	}{
		{"undelivered_removed", func(f *fixture, c *Connection) { f.p.removeConnection(c, "in", f.clk.Now()) }},
		{"undelivered_suspended", func(f *fixture, c *Connection) { f.p.suspend(c, f.clk.Now()) }},
	} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		c := f.p.conns[cid]
		f.failDeposit = func(string, string) error { return errUnavailable }
		id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
		tc.end(f, c)
		if !strings.Contains(f.logs.String(), "reason="+tc.reason) || !strings.Contains(f.logs.String(), "ref="+id) {
			t.Fatalf("%s: not audited with its ref:\n%s", tc.reason, f.logs.String())
		}
	}
}

// The check runs before the ts window, dedupe and the rate limit: a
// member message under the new epoch that those refuse still confirms it
// and sets the received flag.
func TestConfirmBeforeTimeWindowAndDedupe(t *testing.T) {
	for _, tc := range []string{"stale", "duplicate"} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		_, e2 := memberRekey(t, f, m, cid)
		in := &envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate, TS: f.clk.Now(), Body: m.ProfileBody(2)}
		if tc == "stale" {
			in.TS = f.clk.Now().Add(-30 * 24 * time.Hour)
		} else {
			f.p.mark(kindInner, cid+"|"+in.ID, []byte{1}, f.clk.Now().Add(time.Hour)) // seen already
			if err := f.p.flush(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		m.SendInner(in)
		f.pump()
		c := f.p.conns[cid]
		if !bytes.Equal(c.Confirmed, e2[:]) || !c.epochMeta(e2[:]).Received {
			t.Fatalf("%s: a message the later checks refuse did not confirm", tc)
		}
	}
}

// A superseded epoch that is not the confirmed one keeps no rk; the
// service's own activation never keeps one either.
func TestKeepOnlyTheConfirmed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	e1, e2 := memberRekey(t, f, m, cid) // confirmed e1, current e2
	m.IgnoreStray = true
	m.Reconnect() // sealed mode: confirms nothing; e3, with e2 never confirmed
	f.pump()
	c := f.p.conns[cid]
	if epochOf(c) == e2 {
		t.Fatal("the reconnect did not complete")
	}
	if k := c.kr.Find(e2); k != nil && k.HasRK() {
		t.Fatal("an unconfirmed superseded epoch kept its rk")
	}
	if k := c.kr.Find(e1); k == nil || !k.HasRK() {
		t.Fatal("the confirmed epoch lost its rk")
	}
	m.Send(peerwire.TypeProfileUpdate, m.ProfileBody(2)) // confirms e3
	f.pump()
	e3 := epochOf(c)
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	f.pump() // our own rekey: e4
	if epochOf(c) == e3 {
		t.Fatal("our rekey did not complete")
	}
	if k := c.kr.Find(e3); k != nil && k.HasRK() {
		t.Fatal("our own activation kept the old epoch's rk")
	}
}

// One hs.confirm per batch, however many messages under the confirmed
// epoch it holds.
func TestOneConfirmPerBatch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	var late [][]byte
	for i := 0; i < 3; i++ {
		raw, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate,
			TS: f.clk.Now(), Body: m.ProfileBody(uint64(2 + i))})
		if err != nil {
			t.Fatal(err)
		}
		late = append(late, raw)
	}
	memberRekey(t, f, m, cid)
	got := confirms(m)
	for _, raw := range late {
		m.DepositTo(m.SvcStand, raw)
	}
	f.pump()
	if confirms(m) != got+1 {
		t.Fatalf("%d hs.confirm for one batch", confirms(m)-got)
	}
}

// A handshake message waiting in the outbox (our rekey hs.init) is never
// sealed again at a key change; a session message is.
func TestResealSkipsHandshake(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.failDeposit = func(string, string) error { return errUnavailable }
	f.p.startRekey(c, f.clk.Now())
	f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	before := map[string][]byte{}
	for _, e := range f.p.outbox {
		before[e.ID] = e.Payload
	}
	f.p.resealAtKeyChange(c, c.kr.Current(), f.clk.Now().Add(time.Minute))
	for _, e := range f.p.outbox {
		same := bytes.Equal(before[e.ID], e.Payload)
		if e.Handshake && !same {
			t.Fatal("a handshake message was sealed again")
		}
		if !e.Handshake && same {
			t.Fatal("a session message was not sealed again")
		}
	}
}

// At a key change, a tried entry past the 16-day window and an expired
// one are not delivered, each audited.
func TestResealDrops(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.failDeposit = func(string, string) error { return errUnavailable }
	old := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	exp := f.p.sendInner(c, &envelope.Inner{ID: f.p.newID(f.clk.Now()), Type: "connection.note", TS: f.clk.Now(),
		Exp: f.clk.Now().Add(time.Hour), Body: []byte(`{"x":2}`)}, f.clk.Now())
	for _, e := range f.p.outbox {
		e.Tried = true
	}
	later := f.clk.Now().Add(DedupeRetention)
	f.p.resealAtKeyChange(c, c.kr.Current(), later)
	for _, want := range []string{"reason=undelivered_window ", "ref=" + old, "reason=held_expired ", "ref=" + exp} {
		if !strings.Contains(f.logs.String()+" ", want) {
			t.Fatalf("missing %q:\n%s", want, f.logs.String())
		}
	}
	for _, e := range f.p.outbox {
		if e.ConnID == cid && !e.Handshake {
			t.Fatal("a dropped entry is still waiting")
		}
	}
}

// A re-stamped entry is not deposited in the pass that re-stamps it: it
// waits for the write. Every due entry to the mailbox is re-stamped in
// the same pass.
func TestRestampWaitsForWrite(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	ids := []string{f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now()),
		f.p.sendTo(c, "connection.note", []byte(`{"x":2}`), f.clk.Now())}
	deposits := 0
	f.failDeposit = func(string, string) error { deposits++; return nil }
	f.clk.Advance(RestampAfter + time.Hour)
	f.p.mu.Lock()
	f.p.drainOutbox(context.Background())
	f.p.mu.Unlock()
	if deposits != 0 {
		t.Fatalf("%d deposited in the pass that re-stamped", deposits)
	}
	for _, e := range f.p.outbox {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := c.kr.Current().OpenSent(env); err == nil && slices.Contains(ids, in.ID) && !in.TS.Equal(f.clk.Now().Truncate(time.Millisecond)) {
				t.Fatalf("%s not re-stamped in the same pass", in.ID)
			}
		}
	}
	f.tick()
	for _, e := range f.p.outbox {
		if env, err := envelope.Parse(e.Payload); err == nil {
			if in, err := c.kr.Current().OpenSent(env); err == nil && slices.Contains(ids, in.ID) {
				t.Fatalf("%s not deposited after the write", in.ID)
			}
		}
	}
}

// A 5xx and a transport error both mark the entry tried.
func TestTriedOnFailure(t *testing.T) {
	for name, err := range map[string]error{"5xx": errUnavailable, "transport": context.DeadlineExceeded} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		f.failDeposit = func(string, string) error { return err }
		f.p.sendTo(f.p.conns[cid], "connection.note", []byte(`{"x":1}`), f.clk.Now())
		f.tick()
		for _, e := range f.p.outbox {
			if e.ConnID == cid && !e.Tried {
				t.Fatalf("%s: not marked tried", name)
			}
		}
	}
}

// A tried entry deposited more than RestampAfter after its ts is noted
// once (unconfirmed_late).
func TestUnconfirmedLate(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.failDeposit = func(string, string) error { return errUnavailable }
	f.p.sendTo(f.p.conns[cid], "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.tick() // tried
	f.clk.Advance(RestampAfter + time.Hour)
	f.tick()
	f.clk.Advance(time.Minute)
	f.tick()
	if n := strings.Count(f.logs.String(), "reason=unconfirmed_late"); n != 1 {
		t.Fatalf("noted %d times", n)
	}
}
