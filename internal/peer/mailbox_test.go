package peer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/vettid/vettid-vault/vms/handshake"
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
// is stored, so the next start (a plain 200) raises the alarm again (no
// connection was done yet), waits the rest and re-mints. A peer whose
// start hasn't finished changes nothing for the application's calls.
func TestLostMailboxStoppedDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	inv := f.invite("")
	before := issuedTo(m)
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.stopSleep = true
	if err := f.startErr(); err == nil {
		t.Fatal("a stopped wait started")
	}
	ctx, now := context.Background(), f.clk.Now()
	if err := f.p.Remove(ctx, cid); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Remove: %v", err)
	}
	if err := f.p.CancelInvite(ctx, inv.ID); !errors.Is(err, ErrNotStarted) {
		t.Errorf("CancelInvite: %v", err)
	}
	if _, err := f.p.PinGov(ctx, cid, nil, false); !errors.Is(err, ErrNotStarted) || !errors.Is(err, ErrNotFound) {
		t.Errorf("PinGov: %v", err)
	}
	if _, err := f.p.RepinGov(ctx, cid, []byte("k")); !errors.Is(err, ErrNotStarted) || !errors.Is(err, ErrNotFound) {
		t.Errorf("RepinGov: %v", err)
	}
	if _, _, err := f.p.Caught(ctx, now, now, now, now); !errors.Is(err, ErrNotStarted) {
		t.Errorf("Caught: %v", err)
	}
	nev := len(f.ev.evs)
	f.p.events = append(f.p.events, &Event{ID: "e-test", Type: "test"})
	f.p.DeliverEvents(ctx)
	if len(f.ev.evs) != nev {
		t.Error("events delivered before the start")
	}
	f.stopSleep = false
	f.start()
	if lostAlarms(f) != 2 {
		t.Fatalf("%d alarms; the restart found the re-mint owed and none done", lostAlarms(f))
	}
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

// More than 100 members (a write that took them all would split), and a
// store write that fails partway through the re-mint, at several points:
// no member is left marked done without its tokens; the next start
// re-mints everyone who didn't get them, raises the alarm again only if
// none was done, and the mark clears only then.
func TestLostMailboxRemintSplitWrites(t *testing.T) {
	for _, k := range []int{1, 2, 5, 8} {
		t.Run(fmt.Sprint(k), func(t *testing.T) { remintSplit(t, k) })
	}
}

func remintSplit(t *testing.T, k int) {
	f := newFixture(t)
	var ms []*peertest.Member
	for i := range 110 {
		m := f.member(byte(20 + i))
		f.connect(m, "")
		ms = append(ms, m)
	}
	before := make([]int, len(ms))
	for i, m := range ms {
		before[i] = issuedTo(m)
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	st := &splitStore{MemStore: f.store, failTokenApply: k}
	f.storeWrap = st
	if err := f.startErr(); err == nil {
		t.Fatal("the failing write didn't fail the start")
	}
	st.failTokenApply = 0
	f.start()
	want := 1
	if k == 1 {
		want = 2
	}
	if lostAlarms(f) != want {
		t.Fatalf("%d alarms, want %d", lostAlarms(f), want)
	}
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
	// The loss is proven: nothing mints until the registration is made.
	if _, err := f.p.CreateInvite(context.Background(), ""); !errors.Is(err, ErrMailboxRenewing) {
		t.Fatalf("an invitation with the registration owed: %v", err)
	}
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

// A deposit to a member refused token_revoked during the wait (the
// member's relay ended our standing token) starts a reconnect, which is
// held, not failed: the connection stays active and reconnects after the
// wait; the message goes once.
func TestLostMailboxDepositRefusedDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	c := f.p.conns[cid]
	revoked := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == revoked {
			return &relayclient.Error{Status: 403, Code: codeTokenRevoked}
		}
		return nil
	}
	f.p.mu.Lock()
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.p.mu.Unlock()
	f.step()
	f.tick()
	c = f.p.conns[cid]
	if c.State != StateActive || !c.Reconnecting || c.ReconnectTries != 0 || len(f.p.outgoing) != 0 {
		t.Fatalf("during the wait: state %s, reconnecting %v, tries %d, %d outgoing", c.State, c.Reconnecting, c.ReconnectTries, len(f.p.outgoing))
	}
	if strings.Contains(f.logs.String(), "reconnect_failed") {
		t.Fatal("reconnect_failed during the wait")
	}
	f.failDeposit = nil
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	c = f.p.conns[cid]
	if c.State != StateActive || c.Reconnecting || epochOf(c) != m.KR.Current().ID() {
		t.Fatalf("after the wait: state %s, reconnecting %v", c.State, c.Reconnecting)
	}
	if strings.Contains(f.logs.String(), "reconnect_slow") {
		t.Fatal("reconnect_slow for a held reconnect")
	}
	n := 0
	for _, g := range m.Got {
		if g.ID == id {
			n++
		}
	}
	if n != 1 || !f.signIn(m, cid) {
		t.Fatalf("the member got it %d times", n)
	}
}

// A rekey due during the wait starts only after it, and after the
// member's tokens are re-minted: the member's hs.resp would come on a
// token the relay refuses.
func TestLostMailboxNoRekeyDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	old := m.KR.Current().ID()
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatalf("%d rekeys started during the wait", len(f.p.outgoing))
	}
	f.clk.Advance(FreshMailboxWait)
	f.tick() // the re-mint
	f.pump()
	if m.KR.Current().ID() != old {
		t.Fatal("the rekey started before the member's tokens were re-minted")
	}
	f.clk.Advance(time.Minute)
	f.tick() // the rekey
	f.pump()
	if m.KR.Current().ID() == old || epochOf(f.p.conns[cid]) != m.KR.Current().ID() || !f.signIn(m, cid) {
		t.Fatal("the rekey after the wait did not complete")
	}
}

// A second loss while the first's re-mint is still owed moves the wait to
// the second answer: nothing is minted at the first's time.
func TestLostMailboxSecondDuringWait(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	before := issuedTo(m)
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	f.clk.Advance(200 * time.Second)
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no second loss seen")
	}
	f.clk.Advance(100 * time.Second) // past the first wait, not the second
	f.tick()
	f.pump()
	if issuedTo(m) != before {
		t.Fatal("minted inside the second loss's wait")
	}
	f.clk.Advance(FreshMailboxWait)
	f.tick()
	f.pump()
	if got := issuedTo(m) - before; got != 2 || !f.signIn(m, cid) || lostAlarms(f) != 2 {
		t.Fatalf("%d tokens, %d alarms", got, lostAlarms(f))
	}
}

// While a registration after a mailbox_unknown is owed, nothing that asks
// a member for an answer starts (here a rekey due): the loss is proven,
// though no re-mint time is set yet.
func TestLostMailboxNoRekeyWhileOwed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.w.DeleteMailbox(f.keys.Mailbox())
	f.failRegister = errors.New("connection reset")
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no error")
	}
	if err := f.p.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.p.outgoing) != 0 {
		t.Fatalf("%d rekeys started with the registration owed", len(f.p.outgoing))
	}
}

// A registration while running (under the peer's lock) is cut short
// sooner than one at a start.
func TestRegisterRunningTimeout(t *testing.T) {
	f := newFixture(t)
	if f.regDeadline != 0 {
		t.Fatalf("a start's registration bounded to %s", f.regDeadline)
	}
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	if f.regDeadline <= 0 || f.regDeadline > registerRunningTimeout {
		t.Fatalf("a running registration bounded to %s", f.regDeadline)
	}
}

// A deposit refused token_expired during the wait (our standing token
// still valid on our clock) asks for no refresh then: the member could
// only answer on a refused token. The refresh goes once its tokens are
// re-minted, and the message after it.
func TestLostMailboxRefreshAfterRemint(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	c := f.p.conns[cid]
	expired := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == expired {
			return &relayclient.Error{Status: 401, Code: codeTokenExpired}
		}
		return nil
	}
	f.p.mu.Lock()
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.p.mu.Unlock()
	f.step()
	f.tick()
	f.pump()
	if c.RefreshID != "" {
		t.Fatal("a refresh asked for during the wait")
	}
	f.clk.Advance(FreshMailboxWait)
	f.tick() // the re-mint
	if c.RefreshID != "" {
		t.Fatal("a refresh asked for before the member's re-mint")
	}
	f.pump()
	f.clk.Advance(time.Minute)
	f.tick() // the refresh
	if c.RefreshID == "" {
		t.Fatal("no refresh after the re-mint")
	}
	f.failDeposit = nil
	f.clk.Advance(time.Hour)
	f.tick()
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

// After the wait, before a member's re-mint (no tick has run since): a
// deposit refused token_expired asks for no refresh yet, since the member
// still holds only refused tokens. The refresh goes at the first
// housekeeping after its re-mint.
func TestLostMailboxRefreshBeforeMemberRemint(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.w.DeleteMailbox(f.keys.Mailbox())
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no loss seen")
	}
	f.clk.Advance(FreshMailboxWait)
	c := f.p.conns[cid]
	expired := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == expired {
			return &relayclient.Error{Status: 401, Code: codeTokenExpired}
		}
		return nil
	}
	f.p.mu.Lock()
	f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.p.mu.Unlock()
	// Only Tick re-mints (remintLost); Step drains the outbox, and its
	// housekeeping skips a member whose re-mint is owed: that is the window.
	f.step() // drains the outbox: token_expired, before any tick re-mints
	if c.MailboxRemint.Equal(f.p.remintAt) {
		t.Fatal("re-minted before the tick")
	}
	if c.RefreshID != "" || !f.p.refreshOwed[cid] {
		t.Fatalf("refresh %q, owed %v", c.RefreshID, f.p.refreshOwed[cid])
	}
	f.tick() // the re-mint
	if c.RefreshID != "" {
		t.Fatal("a refresh asked for before the member's re-mint")
	}
	f.pump()
	f.tick() // the refresh: the first housekeeping after the re-mint
	if c.RefreshID == "" || f.p.refreshOwed[cid] {
		t.Fatalf("refresh %q, owed %v after the re-mint", c.RefreshID, f.p.refreshOwed[cid])
	}
}
