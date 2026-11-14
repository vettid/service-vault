package peer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func lostAlarms(f *fixture) int { return strings.Count(f.logs.String(), "alarm=relay_mailbox_lost") }

func issuedTo(m *peertest.Member) int { return len(m.Received(peerwire.TypeTokenIssued)) }

func setRelayReg(t *testing.T, f *fixture, r relayReg) {
	t.Helper()
	b, _ := json.Marshal(r)
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindRelayReg, ID: relayRegID, Data: b}}); err != nil {
		t.Fatal(err)
	}
}

// A mailbox lost while the service was down: the start's registration
// gets a 201 for a mailbox it had registered, raises the alarm once,
// waits FreshMailboxWait before anything mints a token, then mints every
// member's tokens again; the old token is refused, a sign-in works on the
// new ones, and a restart repeats nothing.
func TestLostMailboxReminted(t *testing.T) {
	f := newFixture(t)
	if lostAlarms(f) != 0 || f.slept != 0 {
		t.Fatal("a first registration taken for a loss")
	}
	m := f.member(10)
	cid := f.connect(m, "")
	before, old := issuedTo(m), m.SvcStand
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.start()
	if lostAlarms(f) != 1 || f.slept != FreshMailboxWait {
		t.Fatalf("%d alarms, waited %s", lostAlarms(f), f.slept)
	}
	if _, err := m.R.Deposit(context.Background(), f.keys.Mailbox(), old, []byte("x")); err == nil {
		t.Fatal("a token the lost mailbox issued was accepted")
	}
	f.pump()
	if got := issuedTo(m) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted, want standing and reconnect", got)
	}
	f.start()
	f.tick()
	f.pump()
	if lostAlarms(f) != 1 || issuedTo(m)-before != 2 {
		t.Fatalf("a restart repeated it: %d alarms, %d tokens", lostAlarms(f), issuedTo(m)-before)
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.RemintAfter.IsZero() || !r.Registered || r.Attempted {
		t.Fatalf("record %+v", r)
	}
}

// A start stopped during the wait (a crash after the 201): the owed mark
// is stored, so the next start (a plain 200) waits the rest and re-mints.
func TestLostMailboxStoppedDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := issuedTo(m)
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.stopSleep = true
	if err := f.startErr(); err == nil {
		t.Fatal("a stopped wait started")
	}
	f.stopSleep = false
	f.start()
	f.pump()
	if got := issuedTo(m) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted after the stop", got)
	}
}

// splitStore applies a write in transactions of at most 100 changes, as
// the table does. When failTokenApply is k, the k-th write that carries
// tokens commits its first transaction only, then fails.
type splitStore struct {
	*MemStore
	failTokenApply, tokenApplies int
}

func (s *splitStore) Apply(ctx context.Context, changes []Change) error {
	tokens := false
	for _, c := range changes {
		tokens = tokens || c.Kind == kindToken
	}
	if tokens {
		s.tokenApplies++
	}
	failing := tokens && s.tokenApplies == s.failTokenApply
	for len(changes) > 0 {
		n := min(100, len(changes))
		if err := s.MemStore.Apply(ctx, changes[:n]); err != nil {
			return err
		}
		if failing {
			return errors.New("store unavailable after one transaction")
		}
		changes = changes[n:]
	}
	return nil
}

// Many members, and a store write that fails partway through the
// re-mint: no member is left marked done without its tokens; the next
// start re-mints everyone who didn't get them, and the mark clears only
// then.
func TestLostMailboxRemintSplitWrites(t *testing.T) {
	f := newFixture(t)
	var ms []*peertest.Member
	for i := range 40 {
		m := f.member(byte(20 + i))
		f.connect(m, "")
		ms = append(ms, m)
	}
	before := make([]int, len(ms))
	for i, m := range ms {
		before[i] = issuedTo(m)
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	st := &splitStore{MemStore: f.store, failTokenApply: 2}
	f.storeWrap = st
	if err := f.startErr(); err == nil {
		t.Fatal("the failing write didn't fail the start")
	}
	st.failTokenApply = 0
	f.start()
	f.pump()
	for i, m := range ms {
		if got := issuedTo(m) - before[i]; got < 2 {
			t.Fatalf("member %d: %d tokens re-minted", i, got)
		}
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.RemintAfter.IsZero() {
		t.Fatalf("mark not cleared: %+v", r)
	}
}

// A member whose outbox is full at the re-mint is left for later: the
// mark stays until it gets its tokens.
func TestLostMailboxDeferredConnection(t *testing.T) {
	f := newFixture(t)
	a, b := f.member(10), f.member(11)
	ca := f.connect(a, "")
	cb := f.connect(b, "")
	beforeA, beforeB := issuedTo(a), issuedTo(b)
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	p, c := f.p, f.p.conns[cb]
	p.mu.Lock()
	for p.outboxFor(cb) < MaxOutboxPerConn {
		p.queueDeposit(&outboxEntry{ConnID: cb, Mailbox: c.Peer.Relay.Mailbox, Payload: []byte("x"), NotBefore: f.clk.Now().Add(1000 * time.Hour)},
			f.clk.Now())
	}
	p.mu.Unlock()
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	if r, _ := f.p.readRelayReg(context.Background()); r.RemintAfter.IsZero() {
		t.Fatal("mark cleared with a member not done")
	}
	p.mu.Lock()
	p.outbox = slices.DeleteFunc(p.outbox, func(e *outboxEntry) bool { return string(e.Payload) == "x" })
	p.mu.Unlock()
	f.tick()
	f.pump()
	if issuedTo(a)-beforeA != 2 || issuedTo(b)-beforeB != 2 {
		t.Fatalf("a %d, b %d tokens", issuedTo(a)-beforeA, issuedTo(b)-beforeB)
	}
	if !f.signIn(b, cb) || !f.signIn(a, ca) {
		t.Fatal("sign-in after the deferred re-mint")
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.RemintAfter.IsZero() {
		t.Fatalf("mark not cleared: %+v", r)
	}
}

// A second loss after the first was done re-mints again.
func TestLostMailboxTwice(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := issuedTo(m)
	for range 2 {
		f.w.DeleteMailbox(f.keys.Mailbox())
		f.start()
		f.pump()
	}
	if got := issuedTo(m) - before; got != 4 || lostAlarms(f) != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens, %d alarms", got, lostAlarms(f))
	}
}

// A registration whose answer was never recorded, then a 200: it may have
// made the mailbox afresh unseen, so it counts as lost.
func TestLostMailboxUnansweredThen200(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	setRelayReg(t, f, relayReg{Registered: true, Attempted: true})
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
}

// An unanswered registration, then one the relay refuses (a 429), then a
// 200: the refusal made nothing, but the first attempt may have, so the
// 200 still counts as a lost mailbox.
func TestLostMailboxRefusalKeepsEarlierAttempt(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	setRelayReg(t, f, relayReg{Registered: true, Attempted: true})
	f.failRegister = &relayclient.Error{Status: 429, Code: "rate_limited"}
	if err := f.startErr(); err == nil {
		t.Fatal("started without a registration")
	}
	f.failRegister = nil
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
}

// A table from before the record, with connections, whose mailbox was
// lost: the connections show it was registered before.
func TestLostMailboxOldTable(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindRelayReg, ID: relayRegID}}); err != nil {
		t.Fatal(err)
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
}

// A mailbox lost while running: the collect's mailbox_unknown registers it
// again in place, with the alarm; nothing mints during the wait (an
// invitation is refused), and the next tick after it re-mints.
func TestLostMailboxWhileRunning(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := issuedTo(m)
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("a collect from a deleted mailbox succeeded")
	}
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	if _, err := f.p.CreateInvite(context.Background(), ""); !errors.Is(err, ErrMailboxRenewing) {
		t.Fatalf("an invitation during the wait: %v", err)
	}
	f.tick()
	f.pump()
	if issuedTo(m) != before {
		t.Fatal("tokens minted during the wait")
	}
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	if got := issuedTo(m) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted", got)
	}
}

// During the wait no token is minted, and no reconnect starts (it would
// mint): a connection whose standing token ran out, with a message
// waiting, reconnects only after the wait.
func TestNothingMintedDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	p, c := f.p, f.p.conns[cid]
	p.mu.Lock()
	if _, err := p.mintStanding(cid, &c.Peer, f.clk.Now()); !errors.Is(err, errMintWait) {
		t.Errorf("minted during the wait: %v", err)
	}
	c.Standing.Exp = f.clk.Now().Add(-time.Minute) // no valid standing token
	p.sendTo(c, "vote.test", json.RawMessage(`{}`), f.clk.Now())
	p.mu.Unlock()
	f.clk.Advance(FreshMailboxWait / 2)
	f.tick()
	if c.Reconnecting || c.ReconnectTries != 0 || len(p.outgoing) != 0 {
		t.Fatalf("a reconnect during the wait: reconnecting %v, tries %d, %d outgoing", c.Reconnecting, c.ReconnectTries, len(p.outgoing))
	}
	if n := strings.Count(f.logs.String(), "reconnect: mint tokens"); n != 0 {
		t.Fatalf("%d reconnects tried to mint during the wait", n)
	}
}

// While running, a registration after a mailbox_unknown that gets no
// answer stays owed: the next step registers again before collecting,
// and its 200 counts as a lost mailbox.
func TestLostMailboxWhileRunningUnanswered(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.failRegister = errors.New("connection reset")
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no error")
	}
	f.failRegister = nil
	// The unanswered attempt did make the mailbox afresh.
	if _, err := f.sv.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lostAlarms(f) != 0 {
		t.Fatal("alarm without an answer")
	}
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatalf("step: %v", err)
	}
	if lostAlarms(f) != 1 || f.p.remintAt.IsZero() {
		t.Fatalf("%d alarms, re-mint %v", lostAlarms(f), f.p.remintAt)
	}
}

// A plain 200 changes nothing: no alarm, no wait, no tokens.
func TestRegisterPlain200(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	before := issuedTo(m)
	f.start()
	f.tick()
	f.pump()
	if lostAlarms(f) != 0 || f.slept != 0 || issuedTo(m) != before {
		t.Fatalf("%d alarms, %s, %d tokens", lostAlarms(f), f.slept, issuedTo(m)-before)
	}
}

// The relay's own refusal of a registration made nothing: the attempted
// mark goes back to what it was, so a later 200 is plain; an answer that
// never came leaves it, and the next 200 counts as a possible loss.
func TestRegisterRefusedClearsAttempt(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	f.failRegister = &relayclient.Error{Status: 429, Code: "rate_limited"}
	if err := f.startErr(); err == nil {
		t.Fatal("started without a registration")
	}
	f.failRegister = nil
	f.start()
	if lostAlarms(f) != 0 {
		t.Fatal("a refused registration was taken for a lost mailbox")
	}
	f.failRegister = errors.New("connection reset")
	if err := f.startErr(); err == nil {
		t.Fatal("started without a registration")
	}
	f.failRegister = nil
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms after an unanswered registration", lostAlarms(f))
	}
}

// A registration is one attempt (the client's retries could hide a 201
// behind a 200), and which failures certainly made nothing.
func TestRegisterOneAttempt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := relayclient.New(srv.URL, testKeys(t).Relay)
	if _, err := OneDepositAttempt(c).Register(context.Background()); err == nil || calls.Load() != 1 {
		t.Fatalf("%d attempts, %v", calls.Load(), err)
	}
	for _, tc := range []struct {
		err  error
		none bool
	}{
		{&relayclient.Error{Status: 429, Code: "rate_limited"}, true},
		{&relayclient.Error{Status: 401, Code: "timestamp_stale"}, true},
		{&relayclient.Error{Status: 401, Code: codeReplayDetected}, false},
		{&relayclient.Error{Status: 502}, false},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, true},
		{&net.DNSError{Err: "no such host"}, true},
		{&net.OpError{Op: "read", Err: errors.New("reset")}, false},
		{context.DeadlineExceeded, false},
	} {
		if got := registerMadeNothing(tc.err); got != tc.none {
			t.Errorf("%v: made nothing %v, want %v", tc.err, got, tc.none)
		}
	}
}
