package peer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

func lostAlarms(f *fixture) int { return strings.Count(f.logs.String(), "alarm=relay_mailbox_lost") }

// A mailbox lost while the service was down: the start's registration
// gets a 201 for a mailbox it had registered, raises the alarm once, and
// after FreshMailboxWait mints every member's tokens again; a sign-in
// works again on them. Members' tokens from before the loss are refused
// until then.
func TestLostMailboxReminted(t *testing.T) {
	f := newFixture(t)
	if lostAlarms(f) != 0 {
		t.Fatal("alarm at the first registration")
	}
	m := f.member(10)
	cid := f.connect(m, "")
	before := len(m.Received(peerwire.TypeTokenIssued))
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.start()
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	f.pump()
	// The member's token from before the loss is refused (RELAY-PROTOCOL
	// §6.10's tombstone).
	if _, err := m.R.Deposit(context.Background(), f.keys.Mailbox(), m.SvcStand, []byte("x")); err == nil {
		t.Fatal("a token the lost mailbox issued was accepted")
	}
	f.clk.Advance(FreshMailboxWait - time.Second)
	f.tick()
	f.pump()
	if got := len(m.Received(peerwire.TypeTokenIssued)); got != before {
		t.Fatalf("tokens re-minted before the wait: %d", got-before)
	}
	f.clk.Advance(time.Second)
	f.tick()
	f.pump()
	if got := len(m.Received(peerwire.TypeTokenIssued)); got-before != 2 {
		t.Fatalf("%d tokens re-minted, want standing and reconnect", got-before)
	}
	if !f.signIn(m, cid) {
		t.Fatal("no sign-in on the re-minted tokens")
	}
	f.start()
	f.tick()
	f.pump()
	if lostAlarms(f) != 1 || len(m.Received(peerwire.TypeTokenIssued))-before != 2 {
		t.Fatalf("a restart repeated it: %d alarms", lostAlarms(f))
	}
	if r, _ := f.p.readRelayReg(context.Background()); !r.RemintAfter.IsZero() || !r.Registered || r.Attempted {
		t.Fatalf("record %+v", r)
	}
}

// A crash after the 201, before the re-mint: the owed mark is stored, so
// the next start (a plain 200) still re-mints.
func TestLostMailboxCrashAfter201(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := len(m.Received(peerwire.TypeTokenIssued))
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.start() // the 201; then "crash": a new process
	f.start()
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	if got := len(m.Received(peerwire.TypeTokenIssued)) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted after the crash", got)
	}
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
}

// A registration whose answer was never recorded, then a 200: it may have
// made the mailbox afresh unseen, so it counts as lost.
func TestLostMailboxUnansweredThen200(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	b, _ := json.Marshal(relayReg{Registered: true, Attempted: true})
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindRelayReg, ID: relayRegID, Data: b}}); err != nil {
		t.Fatal(err)
	}
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

// A registration left unanswered, then one the relay refuses (a 429),
// then a 200: the refusal made nothing, but the first attempt may have,
// so the 200 still counts as a lost mailbox.
func TestLostMailboxRefusalKeepsEarlierAttempt(t *testing.T) {
	f := newFixture(t)
	f.member(10)
	f.connect(f.ms[0], "")
	b, _ := json.Marshal(relayReg{Registered: true, Attempted: true})
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindRelayReg, ID: relayRegID, Data: b}}); err != nil {
		t.Fatal(err)
	}
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

// A mailbox lost while the service runs: the collect's mailbox_unknown
// registers it again in place, with the alarm and the re-mint.
func TestLostMailboxWhileRunning(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := len(m.Received(peerwire.TypeTokenIssued))
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("a collect from a deleted mailbox succeeded")
	}
	if lostAlarms(f) != 1 {
		t.Fatalf("%d alarms", lostAlarms(f))
	}
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	if got := len(m.Received(peerwire.TypeTokenIssued)) - before; got != 2 || !f.signIn(m, cid) {
		t.Fatalf("%d tokens re-minted", got)
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

// A plain 200 changes nothing: no alarm, no tokens.
func TestRegisterPlain200(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	before := len(m.Received(peerwire.TypeTokenIssued))
	f.start()
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	if lostAlarms(f) != 0 || len(m.Received(peerwire.TypeTokenIssued)) != before {
		t.Fatalf("%d alarms, %d tokens", lostAlarms(f), len(m.Received(peerwire.TypeTokenIssued))-before)
	}
}

// The relay's own refusal of a registration (a 4xx, 429 included) made
// nothing: the attempted mark is cleared, so a later 200 is plain.
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
	// No answer at all (not a relayclient.Error): the mark stays, and the
	// next 200 counts as a possible fresh mailbox.
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
