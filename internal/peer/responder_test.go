package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
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
	if e := epochOf(c); !bytes.Equal(c.Confirmed, e[:]) || len(c.Epochs) != 1 {
		t.Fatalf("first epoch not confirmed: %d epochs", len(c.Epochs))
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
	if len(f.p.awaiting) != 0 || !strings.Contains(f.logs.String(), "reason=rekey_replay") {
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
	if prof == nil || !slices.Equal(prof.Features, Features) {
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
	c := relayclient.New("https://relay.example", nil)
	r := OneDepositAttempt(c).(oneDeposit)
	if r.dep.MaxAttempts != 1 || c.MaxAttempts == 1 || r.Client != c {
		t.Fatalf("deposit attempts %d, client %d", r.dep.MaxAttempts, c.MaxAttempts)
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

// hs.confirm does not count toward MaxOutboxPerConn.
func TestConfirmExemptFromOutboxBound(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	if !f.p.queueConfirm(c, f.clk.Now()) {
		t.Fatal("hs.confirm not queued")
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
