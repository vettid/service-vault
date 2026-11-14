package peer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

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
	// (The test relay refuses the member's tokens from before the loss,
	// as RELAY-PROTOCOL §6.10's tombstone does: peertest.World.Deposit.)
	f.pump()
	if got := len(m.Received(peerwire.TypeTokenIssued)); got != before {
		t.Fatalf("tokens re-minted before the wait: %d", got-before)
	}
	f.clk.Advance(FreshMailboxWait)
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
