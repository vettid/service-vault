package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
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

// ownRekeyPending has the service rekey a connection with a member that
// sends no hs.confirm: the service's new epoch is left pending. It returns
// the current and pending epochs.
func ownRekeyPending(t *testing.T, f *fixture, m *peertest.Member, cid string) (cur, pend [suite.EpochIDSize]byte) {
	t.Helper()
	m.NoConfirm = true
	cur = epochOf(f.p.conns[cid])
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick() // our rekey hs.init goes
	f.pump()
	c := f.p.conns[cid]
	if c.Pending == nil || epochOf(c) != cur {
		t.Fatalf("pending %v", c.Pending)
	}
	copy(pend[:], c.Pending.ID)
	if m.KR.Current().ID() != pend {
		t.Fatal("the member did not activate our epoch")
	}
	return cur, pend
}

func (f *fixture) audited(reason string) bool {
	return strings.Contains(f.logs.String(), "reason="+reason+" ")
}

// The service's own rekey epoch is pending until a message from the member
// opens under it: until then the service sends in the current epoch and
// starts no other rekey; the member's message makes it current and
// confirmed before anything else (§6.3.1 Initiator, R29-I1, R29-I2).
func TestOwnRekeyPendingUntilConfirmed(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	cur, pend := ownRekeyPending(t, f, m, cid)
	c := f.p.conns[cid]
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("a rekey started while our epoch is pending")
	}
	f.pump()
	got := false
	for _, g := range m.Got {
		got = got || g.ID == id
	}
	if !got {
		t.Fatal("the member did not get the message sent under the current epoch")
	}
	if c = f.p.conns[cid]; epochOf(c) != cur || c.Pending == nil {
		t.Fatal("confirmed by nothing")
	}
	m.Send("connection.note", []byte(`{}`))
	f.pump()
	c = f.p.conns[cid]
	if c.Pending != nil || epochOf(c) != pend || !bytes.Equal(c.Confirmed, pend[:]) || c.kr.Pending() != nil {
		t.Fatalf("not confirmed: pending %v", c.Pending)
	}
	if e := c.epochMeta(pend[:]); e == nil || !e.Mine || !e.Received {
		t.Fatalf("epoch record %+v", e)
	}
}

// B (§6.3.1) is judged only once this start's first short collect has
// been processed (RELEASE-29 §2): a pending rekey is then abandoned, and
// the service reconnects naming its current epoch (§3 item 1).
func TestPendingAbandonedAtB(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	cur, _ := ownRekeyPending(t, f, m, cid)
	f.p.conns[cid].Standing.Exp = f.clk.Now().Add(90 * 24 * time.Hour) // B, not the token, is tested
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(PendingLife + time.Minute)
	f.start() // the latch is clear at a start
	f.tick()
	if f.p.conns[cid].Pending == nil {
		t.Fatal("B judged before a short collect")
	}
	f.step() // an empty collect within the start's lease window does not count
	f.tick()
	if f.p.conns[cid].Pending == nil {
		t.Fatal("B judged while messages may still be leased")
	}
	f.clk.Advance(time.Hour) // past any lease
	f.step()                 // an empty collect sets the latch
	f.tick()
	c := f.p.conns[cid]
	if c.Pending != nil || !f.audited("pending_abandoned_b_passed") {
		t.Fatal("the pending epoch outlived B")
	}
	if !c.Reconnecting || len(f.p.outgoing) != 1 {
		t.Fatalf("no reconnect: reconnecting %v, %d outgoing", c.Reconnecting, len(f.p.outgoing))
	}
	for _, og := range f.p.outgoing {
		if !bytes.Equal(og.Named, cur[:]) {
			t.Fatal("the reconnect does not name the current epoch")
		}
	}
}

// A failed collect clears the latch.
func TestFailedCollectClearsLatch(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.clk.Advance(time.Hour) // past any lease
	f.step()
	if !f.p.drained {
		t.Fatal("an empty collect did not set the latch")
	}
	f.failCollect = errUnavailable
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no error")
	}
	f.failCollect = nil
	if f.p.drained {
		t.Fatal("a failed collect left the latch set")
	}
}

// A pending rekey is abandoned when the service holds no valid standing
// token for the member (R29-I6), and the service reconnects.
func TestPendingRekeyAbandonedWithoutToken(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ownRekeyPending(t, f, m, cid)
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	f.tick()
	c := f.p.conns[cid]
	if c.Pending != nil || !f.audited("pending_abandoned_no_token") || !c.Reconnecting {
		t.Fatalf("pending %v, reconnecting %v", c.Pending, c.Reconnecting)
	}
}

// A reconnect's pending epoch that reaches B makes the connection stale
// (§3.4.1 "The reconnect bound"); until its confirmation nothing but the
// handshake is sent.
func TestPendingReconnectStaleAtB(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true)
	m.NoConfirm = true
	f.pump()
	c := f.p.conns[cid]
	if !c.pendingReconnect() || !c.Reconnecting {
		t.Fatal("the reconnect's epoch is not pending")
	}
	n := len(m.Got)
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	f.pump()
	if len(m.Got) != n {
		t.Fatal("a message went while the reconnect is pending")
	}
	f.p.conns[cid].Standing.Exp = f.clk.Now().Add(90 * 24 * time.Hour)
	f.clk.Advance(PendingLife + time.Minute)
	f.step()
	f.tick()
	if c = f.p.conns[cid]; c.State != StateStale || c.Reconnecting || c.Pending != nil {
		t.Fatalf("state %s, reconnecting %v", c.State, c.Reconnecting)
	}
	if !strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatal("no reconnect_failed")
	}
}

// An abandoned pending epoch's hs.fin, still in the outbox, is dropped
// and never sent (§6.3.1, R29-T2).
func TestAbandonDropsUnsentFin(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	m.NoConfirm = true
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	m.Step() // the member answers
	mb := c.Peer.Relay.Mailbox
	f.failDeposit = func(mailbox, token string) error {
		if mailbox == mb && token != c.Reconnect.Token {
			return errUnavailable
		}
		return nil
	}
	f.step() // hs.resp: pending, its hs.fin waits
	if c.Pending == nil {
		t.Fatal("not pending")
	}
	pend := c.Pending.ID
	fins := 0
	for _, e := range f.p.outbox {
		if bytes.Equal(e.FinEpoch, pend) {
			fins++
		}
	}
	if fins != 1 {
		t.Fatalf("%d hs.fin waiting", fins)
	}
	c.Standing.Exp = f.clk.Now()
	f.tick() // abandoned for want of a token
	for _, e := range f.p.outbox {
		if bytes.Equal(e.FinEpoch, pend) {
			t.Fatal("the abandoned epoch's hs.fin is still queued")
		}
	}
}

// §6.3.1 "Crossing" (R29-X1): holding a pending epoch, the service drops a
// member's rekey whose ts is not later than the hs.resp's; a later one
// abandons the pending epoch and is answered.
func TestCrossingRekeyWithPending(t *testing.T) {
	for _, later := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		m.NoConfirm = true
		m.IgnoreStray = true
		f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
		f.tick()
		m.Step() // the member answers our hs.init
		if later {
			f.clk.Advance(time.Minute)
		}
		m.StartRekey() // made under the old epoch
		f.step()
		c := f.p.conns[cid]
		if !later {
			if c.Pending == nil || !f.audited("rekey_crossing_dropped") {
				t.Fatalf("earlier: pending %v", c.Pending)
			}
			continue
		}
		if c.Pending != nil || !f.audited("pending_abandoned_crossing") || len(f.p.awaiting) != 1 {
			t.Fatalf("later: pending %v, %d awaiting", c.Pending, len(f.p.awaiting))
		}
		f.pump()
		if c = f.p.conns[cid]; epochOf(c) != m.KR.Current().ID() {
			t.Fatal("the member's rekey was not established")
		}
	}
}

// Rule J (R29-X3): with no valid standing token the service does not
// answer a member's rekey, and reconnects (RELEASE-29 §3 item 6).
func TestRuleJ(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	m.StartRekey()
	f.step()
	c := f.p.conns[cid]
	if len(f.p.awaiting) != 0 || !f.audited("rekey_answer_undepositable") {
		t.Fatalf("%d awaiting", len(f.p.awaiting))
	}
	if !c.Reconnecting || len(f.p.outgoing) != 1 {
		t.Fatal("no reconnect")
	}
}

// token_revoked on the held standing token ends that token, not the
// connection: the entries wait, a reconnect starts, and they go under its
// epoch once it is confirmed, each once (RELEASE-29 §3 item 4).
func TestHeldTokenRevokedWaits(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	revoked := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == revoked {
			return &relayclient.Error{Status: 403, Code: codeTokenRevoked}
		}
		return nil
	}
	id := f.p.sendTo(c, "connection.note", []byte(`{"x":1}`), f.clk.Now())
	f.step()
	c = f.p.conns[cid]
	if c.State != StateActive || c.Standing.Token != "" || !c.Reconnecting || f.p.outboxFor(cid) == 0 {
		t.Fatalf("state %s, reconnecting %v, %d waiting", c.State, c.Reconnecting, f.p.outboxFor(cid))
	}
	f.pump()
	c = f.p.conns[cid]
	if c.Reconnecting || c.Pending != nil || epochOf(c) != m.KR.Current().ID() {
		t.Fatal("the reconnect did not complete")
	}
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

// The pending epoch's hs.fin refused token_revoked: the member dropped its
// answer; the epoch is abandoned and a reconnect starts at once (§6.3.1
// "A carried token refused").
func TestFinRevokedReconnects(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	m.Step()
	revoked := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == revoked {
			return &relayclient.Error{Status: 403, Code: codeTokenRevoked}
		}
		return nil
	}
	f.step()
	if c = f.p.conns[cid]; c.Pending != nil || !f.audited("pending_abandoned_fin_revoked") || !c.Reconnecting || len(f.p.outgoing) != 1 {
		t.Fatalf("pending %v, reconnecting %v, %d outgoing", c.Pending, c.Reconnecting, len(f.p.outgoing))
	}
}

// At a change of the member's ik the service's open reconnect starts again
// under the new ik, spending a deposit but not a try, once per change
// (§3.4.1 H5; RELEASE-29 §3 item 8).
func TestH5RestartsReconnect(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	m.StartRekey()
	f.step() // rule J: a reconnect starts
	c := f.p.conns[cid]
	var th1 []byte
	for _, og := range f.p.outgoing {
		th1 = og.Th1
	}
	if !c.Reconnecting || c.ReconnectTries != 1 || th1 == nil {
		t.Fatal("no reconnect")
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.RotateIdentity(40, false) // identity.rotate in the session (and a rekey, dropped)
	f.step()
	c = f.p.conns[cid]
	if !c.Reconnecting || c.ReconnectTries != 1 || len(f.p.outgoing) != 1 || !bytes.Equal(c.ReconnectRestartIK, m.IK.Public().(ed25519.PublicKey)) {
		t.Fatalf("reconnecting %v, tries %d, %d outgoing", c.Reconnecting, c.ReconnectTries, len(f.p.outgoing))
	}
	for _, og := range f.p.outgoing {
		if bytes.Equal(og.Th1, th1) {
			t.Fatal("the reconnect was not started again")
		}
	}
}

// A reconnect that is not a restore's waits 16 days per try for its
// hs.resp, not 7 (§6.3.1 Lifetimes, RELEASE-29 §4).
func TestReconnectTryLifetime(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	m.StartRekey()
	f.step()
	f.clk.Advance(ReconnectTimeout + time.Minute)
	f.tick()
	if c := f.p.conns[cid]; c.ReconnectTries != 1 {
		t.Fatalf("tries %d after 7 days", c.ReconnectTries)
	}
	f.clk.Advance(HandshakeTTL - ReconnectTimeout)
	f.tick()
	if c := f.p.conns[cid]; c.ReconnectTries != 2 || !f.audited("reconnect_try_expired") {
		t.Fatalf("tries %d after 16 days, state %s, reconnecting %v\n%s", c.ReconnectTries, c.State, c.Reconnecting, f.logs.String())
	}
}

// Activating the member's handshake as responder abandons the service's
// pending epoch (§6.3.1 Responder, R29-X2).
func TestResponderActivationAbandonsPending(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	cur, _ := ownRekeyPending(t, f, m, cid)
	m.ReconnectNaming(cur)
	f.pump()
	c := f.p.conns[cid]
	if c.Pending != nil || !f.audited("pending_abandoned_peer_activated") || epochOf(c) != m.KR.Current().ID() {
		t.Fatalf("pending %v", c.Pending)
	}
}

// At a start, a connection whose standing token has expired reconnects
// (§7.2 "On unlock" step 3; RELEASE-29 §3 item 2).
func TestStartWithoutTokenReconnects(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	if c := f.p.conns[cid]; !c.Reconnecting || len(f.p.outgoing) != 1 {
		t.Fatal("no reconnect at the start")
	}
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || !c.standingValid(f.clk.Now()) || !f.signIn(m, cid) {
		t.Fatal("the reconnect did not complete")
	}
}

// A try's hs.init refused quota_exceeded ends the reconnect: the
// connection is stale, with reconnect_failed (§3.4.1 "The reconnect
// bound").
func TestReconnectQuotaStale(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	rt := f.p.conns[cid].Reconnect.Token
	f.failDeposit = func(_, token string) error {
		if token == rt {
			return &relayclient.Error{Status: 429, Code: codeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	}
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	m.StartRekey()
	f.step()
	if c := f.p.conns[cid]; c.State != StateStale || c.Reconnecting || !strings.Contains(f.logs.String(), "alarm=reconnect_failed") {
		t.Fatalf("state %s, reconnecting %v", c.State, c.Reconnecting)
	}
}

// token_expired on the standing token: before its exp on our clock the
// service asks for a fresh one; after it, it reconnects (RELEASE-29 §3
// item 2). quota_exceeded on it after its exp, or on the refresh itself,
// reconnects too (item 5).
func TestStandingRefusalsReconnect(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      string
		expired   bool
		reconnect bool
	}{
		{"expired, valid on our clock", codeTokenExpired, false, false},
		{"expired, past exp", codeTokenExpired, true, true},
		{"quota, before exp", codeQuotaExceeded, false, false},
		{"quota, past exp", codeQuotaExceeded, true, true},
	} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		c := f.p.conns[cid]
		st := c.Standing.Token
		f.failDeposit = func(_, token string) error {
			if token == st {
				return &relayclient.Error{Status: 401, Code: tc.code, Quota: relayclient.QuotaToken}
			}
			return nil
		}
		if tc.expired {
			c.Standing.Exp = f.clk.Now().Add(time.Second)
		}
		f.clk.Advance(2 * time.Second)
		f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
		f.step()
		c = f.p.conns[cid]
		if c.Reconnecting != tc.reconnect {
			t.Fatalf("%s: reconnecting %v", tc.name, c.Reconnecting)
		}
		if !tc.reconnect {
			if c.RefreshID == "" {
				t.Fatalf("%s: no refresh asked", tc.name)
			}
			if tc.code != codeQuotaExceeded {
				continue
			}
			// The refresh, which passes the waiting entry, refused for the
			// token's quota: not sent again, and a reconnect.
			f.step()
			if c = f.p.conns[cid]; !c.Reconnecting || c.RefreshID != "" {
				t.Fatalf("%s: the refused refresh did not reconnect", tc.name)
			}
			for _, e := range f.p.outbox {
				if e.Refresh {
					t.Fatalf("%s: the refused refresh is still queued", tc.name)
				}
			}
		}
	}
}

// After a reconnect fails, what waited behind it stays in the outbox: the
// stale connection's entries are not deposited under the old epoch.
func TestStaleHoldsEntries(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	rt := f.p.conns[cid].Reconnect.Token
	f.failDeposit = func(_, token string) error {
		if token == rt {
			return &relayclient.Error{Status: 429, Code: codeQuotaExceeded, Quota: relayclient.QuotaToken}
		}
		return nil
	}
	c := f.p.conns[cid]
	c.Standing.Exp = f.clk.Now()
	id := f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	f.tick() // a reconnect starts, its hs.init refused for quota: stale
	f.clk.Advance(2 * time.Hour)
	f.tick()
	f.tick()
	if c = f.p.conns[cid]; c.State != StateStale || f.p.outboxFor(cid) != 1 {
		t.Fatalf("state %s, %d waiting", c.State, f.p.outboxFor(cid))
	}
	for _, g := range m.Got {
		if g.ID == id {
			t.Fatal("deposited under the old epoch")
		}
	}
	if n := strings.Count(f.logs.String(), "alarm=reconnect_failed"); n != 1 {
		t.Fatalf("reconnect_failed %d times", n)
	}
}

// A reconnect's hs.fin goes on the hs.resp's carried standing token. When
// it is refused token_revoked, the epoch is abandoned and the next try
// goes on the held reconnect token, not counted, and completes; the
// refused carried tokens are never adopted (§6.3.1 "A carried token
// refused").
func TestReconnectFinRevokedRetriesOnHeldToken(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	held := c.Reconnect.Token
	c.Standing.Exp = f.clk.Now()
	m.StartRekey()
	f.step() // rule J: our reconnect
	var refused, onHeld []string
	f.failDeposit = func(_, token string) error {
		cc := f.p.conns[cid]
		if cc.Pending != nil && token == cc.Pending.Standing.Token && len(refused) == 0 {
			refused = append(refused, token)
			return &relayclient.Error{Status: 403, Code: codeTokenRevoked}
		}
		if token == held {
			onHeld = append(onHeld, token)
		}
		return nil
	}
	m.IgnoreStray, m.IgnoreRevoked = true, true
	f.pump()
	c = f.p.conns[cid]
	if len(refused) != 1 || !f.audited("pending_abandoned_fin_revoked") || len(onHeld) != 1 {
		t.Fatalf("refused %d, tries on the held token %d", len(refused), len(onHeld))
	}
	if c.Reconnecting || c.State != StateActive || epochOf(c) != m.KR.Current().ID() || c.Standing.Token == refused[0] {
		t.Fatalf("reconnecting %v, state %s", c.Reconnecting, c.State)
	}
}

// beginReconnectNow starts a reconnect of the service's at once and
// deposits its hs.init.
func (f *fixture) beginReconnectNow(cid string) {
	f.t.Helper()
	f.p.mu.Lock()
	f.p.beginReconnect(f.p.conns[cid], f.clk.Now())
	f.p.mu.Unlock()
	if err := f.p.Tick(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

// answerBeforeReconnect has the service answer a member's rekey (with
// links when links is set) and then start a reconnect of its own, before
// the member collects anything.
func answerBeforeReconnect(t *testing.T, f *fixture, m *peertest.Member, cid string, links bool) {
	t.Helper()
	if links {
		m.RotateIdentity(40, true)
		m.StartRekeyWithLinks()
	} else {
		m.StartRekey()
	}
	f.step() // answered; its hs.resp is deposited
	f.beginReconnectNow(cid)
	if c := f.p.conns[cid]; !c.Reconnecting || len(f.p.outgoing) != 1 || len(f.p.awaiting) != 1 {
		t.Fatalf("reconnecting %v, %d outgoing, %d awaiting", c.Reconnecting, len(f.p.outgoing), len(f.p.awaiting))
	}
}

// A verified hs.fin comes first (R29-X2): the member's hs.fin for a rekey
// we answered ends our open reconnect try and settles the reconnect; the
// session goes on at the member's epoch, and what waited goes.
func TestMemberFinSettlesOurReconnect(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	answerBeforeReconnect(t, f, m, cid, false)
	id := f.p.sendTo(f.p.conns[cid], "connection.note", []byte(`{}`), f.clk.Now())
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Step() // our hs.resp: the member sends hs.fin; then it answers our reconnect
	f.step()
	c := f.p.conns[cid]
	if c.Reconnecting || len(f.p.outgoing) != 0 || c.Pending != nil || !f.audited("reconnect_settled_by_member") {
		t.Fatalf("reconnecting %v, %d outgoing, pending %v", c.Reconnecting, len(f.p.outgoing), c.Pending)
	}
	f.pump()
	got := false
	for _, g := range m.Got {
		got = got || g.ID == id
	}
	if c = f.p.conns[cid]; epochOf(c) != m.KR.Current().ID() || !got {
		t.Fatalf("epoch split or message not delivered (got %v)", got)
	}
}

// Our reconnect's hs.resp ends our open answers to the member's rekeys
// (§6.5): they no longer hold our rekeys back.
func TestOurReconnectEndsOurRekeyAnswers(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	st := f.p.conns[cid].Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == st {
			// Our hs.resp to the member's rekey waits for a token; deposits
			// on a token of their own pass it.
			return &relayclient.Error{Status: 401, Code: codeTokenExpired}
		}
		return nil
	}
	m.StartRekey()
	f.step()
	f.beginReconnectNow(cid)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.Step() // the member answers our reconnect
	f.step()
	if !f.audited("rekey_answer_ended_by_reconnect") {
		t.Fatal("our rekey answer was not ended")
	}
	for _, aw := range f.p.awaiting {
		if aw.Purpose == handshake.PurposeRekey {
			t.Fatal("our rekey answer still awaits its hs.fin")
		}
	}
}

// Links followed at a member's hs.fin do not restart our reconnect (only
// an identity.rotate does, H5): the hs.fin settles it instead.
func TestFollowAtFinDoesNotRestart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	answerBeforeReconnect(t, f, m, cid, true)
	m.IgnoreStray, m.IgnoreRevoked = true, true
	before := strings.Count(f.logs.String(), "reconnect started")
	m.Step()
	f.step()
	c := f.p.conns[cid]
	if c.ReconnectRestartIK != nil || strings.Count(f.logs.String(), "reconnect started") != before || c.Reconnecting {
		t.Fatalf("restarted: %v, reconnecting %v", c.ReconnectRestartIK != nil, c.Reconnecting)
	}
}

// At its confirmation, a message waiting under the old epoch is sealed
// again under the new one with the same inner id (§8.3).
func TestConfirmationResealsWaiting(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	old, pend := ownRekeyPending(t, f, m, cid)
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	f.failDeposit = func(mailbox, _ string) error {
		if mailbox == mb {
			return errUnavailable
		}
		return nil
	}
	c := f.p.conns[cid]
	id := f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	m.Send("connection.note", []byte(`{}`)) // under our pending epoch
	f.step()
	if c = f.p.conns[cid]; epochOf(c) != pend {
		t.Fatal("not confirmed")
	}
	found := false
	for _, e := range f.p.outbox {
		if in, ok := openUnder(e, c.kr.Current()); ok && in.ID == id {
			found = true
		}
		if _, ok := openUnder(e, c.kr.Find(old)); ok && !e.Handshake {
			t.Fatal("an entry is still sealed under the old epoch")
		}
	}
	if !found {
		t.Fatal("the waiting message was not sealed again under the new epoch")
	}
}

// Abandoning a pending reconnect revokes the tokens its hs.init carried.
func TestAbandonRevokesCarriedTokens(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	m.NoConfirm = true
	f.pump()
	c := f.p.conns[cid]
	if !c.pendingReconnect() || len(c.Pending.Issued) == 0 {
		t.Fatal("no pending reconnect")
	}
	issued := c.Pending.Issued
	f.p.mu.Lock()
	f.p.abandonPending(c, "test", false, f.clk.Now())
	f.p.mu.Unlock()
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s not revoked", j)
		}
	}
}

// With our reconnect pending, only its epoch is accepted as a member
// reconnect's ctx (R29-X5).
func TestPendingReconnectCtx(t *testing.T) {
	for _, namePending := range []bool{true, false} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		cur := epochOf(f.p.conns[cid])
		f.beginReconnectNow(cid)
		m.NoConfirm = true
		f.pump()
		c := f.p.conns[cid]
		var pend [suite.EpochIDSize]byte
		copy(pend[:], c.Pending.ID)
		if namePending {
			m.ReconnectNaming(pend)
		} else {
			m.ReconnectNaming(cur)
		}
		f.step()
		answered := len(f.p.awaiting) == 1
		if answered != namePending {
			t.Fatalf("naming the pending epoch %v: answered %v", namePending, answered)
		}
	}
}

// The H5 restart is spent once per change of the member's ik: with that
// change stored as spent, the try is not started again, and the next one
// counts.
func TestH5RestartOncePerChange(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	newIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{40}, 32))
	f.p.conns[cid].ReconnectRestartIK = newIK.Public().(ed25519.PublicKey) // spent before a restart
	m.IgnoreStray, m.IgnoreRevoked = true, true
	m.RotateIdentity(40, false)
	f.step()
	c := f.p.conns[cid]
	if len(f.p.outgoing) != 0 || c.ReconnectTries != 1 {
		t.Fatalf("%d outgoing, tries %d", len(f.p.outgoing), c.ReconnectTries)
	}
	f.tick()
	if c = f.p.conns[cid]; len(f.p.outgoing) != 1 || c.ReconnectTries != 2 {
		t.Fatalf("next try: %d outgoing, tries %d", len(f.p.outgoing), c.ReconnectTries)
	}
}

// failingStore lets *ok writes through, then fails every write while
// fail is set.
type failingStore struct {
	*MemStore
	fail *bool
	ok   *int
}

func (s failingStore) Apply(ctx context.Context, ch []Change) error {
	if *s.fail {
		if *s.ok == 0 {
			return errors.New("store down")
		}
		*s.ok--
	}
	return s.MemStore.Apply(ctx, ch)
}

// The start latch: clear at every start, cleared by a batch that comes
// back after a store error, and not set by a full batch.
func TestLatchRules(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	f.clk.Advance(time.Hour)
	f.step()
	if !f.p.drained {
		t.Fatal("not set")
	}
	if err := f.p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.p.drained {
		t.Fatal("a start left it set")
	}
	f.clk.Advance(time.Hour)
	f.step()
	fail, ok := true, 1 // the lease mark is written; the batch's write fails
	f.p.cfg.Store = failingStore{f.store, &fail, &ok}
	m.Send("connection.note", []byte(`{}`))
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("no store error")
	}
	if f.p.drained {
		t.Fatal("a failed batch left it set")
	}
	fail = false
	f.clk.Advance(time.Hour)
	f.step()
	for i := 0; i < MaxBatch; i++ {
		m.Send("connection.note", []byte(`{}`))
	}
	f.p.drained = false
	f.clk.Advance(time.Hour)
	if n, err := f.p.Step(context.Background(), 0); err != nil || n != MaxBatch {
		t.Fatalf("%d collected (%v)", n, err)
	}
	if f.p.drained {
		t.Fatal("a full batch set it")
	}
}

// B is 32 days: a pending epoch a minute short of it stays.
func TestPendingLifeIs32Days(t *testing.T) {
	if PendingLife != 32*24*time.Hour {
		t.Fatalf("B %v", PendingLife)
	}
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ownRekeyPending(t, f, m, cid)
	c := f.p.conns[cid]
	c.Standing.Exp = f.clk.Now().Add(90 * 24 * time.Hour)
	f.clk.Advance(PendingLife - time.Minute)
	f.step()
	f.tick()
	if f.p.conns[cid].Pending == nil {
		t.Fatal("abandoned before B")
	}
}

// Starting a reconnect abandons a pending rekey, and drops its unsent
// hs.fin (§6.6: a reconnect names the current epoch).
func TestReconnectAbandonsPendingRekey(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ownRekeyPending(t, f, m, cid)
	f.beginReconnectNow(cid)
	c := f.p.conns[cid]
	if c.Pending != nil || !f.audited("pending_abandoned_reconnect") || !c.Reconnecting {
		t.Fatalf("pending %v", c.Pending)
	}
}

// At confirmation a carried token replaces the held one only if its exp is
// later (§6.3.1).
func TestAdoptOnlyLaterExp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	m.NoConfirm = true
	f.pump()
	c := f.p.conns[cid]
	held := c.Standing
	held.Exp = c.Pending.Standing.Exp.Add(time.Hour)
	c.Standing = held
	m.Send("connection.note", []byte(`{}`))
	f.step()
	if c = f.p.conns[cid]; c.Pending != nil || c.Standing.Token != held.Token {
		t.Fatal("a carried token with an earlier exp replaced the held one")
	}
}

// With no standing token held, a deposit on it waits for one.
func TestNoStandingWaits(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	c.Standing = HeldToken{}
	f.p.mu.Lock()
	f.p.drainOutbox(context.Background())
	f.p.mu.Unlock()
	waiting := 0
	for _, e := range f.p.outbox {
		if e.ConnID == cid && e.Token == "" && e.AwaitToken && !e.NotBefore.IsZero() {
			waiting++
		}
	}
	if waiting != 1 {
		t.Fatalf("%d waiting", waiting)
	}
}

// A refresh is not asked while one is queued, nor while a reconnect is
// open.
func TestRefreshGuards(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	f.failDeposit = func(string, string) error { return errUnavailable }
	countRefresh := func() int {
		n := 0
		for _, e := range f.p.outbox {
			if e.Refresh {
				n++
			}
		}
		return n
	}
	f.p.mu.Lock()
	f.p.refreshHeld(c, f.clk.Now(), true)
	c.RefreshID, c.RefreshAfter = "", time.Time{}
	f.p.refreshHeld(c, f.clk.Now(), true) // one is queued: not again
	if n := countRefresh(); n != 1 {
		f.p.mu.Unlock()
		t.Fatalf("%d refreshes queued", n)
	}
	c.RefreshID, c.RefreshAfter = "", time.Time{}
	f.p.dropOutbox(func(e *outboxEntry) bool { return e.Refresh })
	c.Reconnecting = true
	f.p.refreshHeld(c, f.clk.Now(), true)
	c.Reconnecting = false
	f.p.mu.Unlock()
	n := 0
	for _, e := range f.p.outbox {
		if e.Refresh {
			n++
		}
	}
	if n != 0 || c.RefreshID != "" {
		t.Fatalf("%d refreshes queued while reconnecting", n)
	}
	f.p.mu.Lock()
	f.p.refreshHeld(c, f.clk.Now(), true)
	c.RefreshID, c.RefreshAfter = "", time.Time{}
	f.p.refreshHeld(c, f.clk.Now(), true)
	f.p.mu.Unlock()
	for _, e := range f.p.outbox {
		if e.Refresh {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d refreshes queued", n)
	}
}

// openUnder opens a waiting deposit under ep (nil: no).
func openUnder(e *outboxEntry, ep *handshake.Epoch) (*envelope.Inner, bool) {
	if ep == nil || len(e.Payload) == 0 {
		return nil, false
	}
	env, err := envelope.Parse(e.Payload)
	if err != nil {
		return nil, false
	}
	in, err := ep.OpenSent(env)
	return in, err == nil
}

// The no-standing reconnect waits for the batch: a member's message in it
// that confirms our pending rekey and brings a fresh standing token
// leaves the connection confirmed, with no reconnect.
func TestBatchConfirmsBeforeNoTokenReconnect(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, pend := ownRekeyPending(t, f, m, cid)
	c := f.p.conns[cid]
	st := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == st {
			return errUnavailable
		}
		return nil
	}
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	f.step() // the entry waits
	c.Standing.Exp = f.clk.Now()
	m.Send(peerwire.TypeTokenIssued, peerwire.TokenIssuedBody("standing", m.Mint(peerwire.StandingMax))) // under the pending epoch
	f.step()
	c = f.p.conns[cid]
	if c.Pending != nil || epochOf(c) != pend || c.Reconnecting || f.audited("pending_abandoned_reconnect") || !c.standingValid(f.clk.Now()) {
		t.Fatalf("pending %v, reconnecting %v", c.Pending, c.Reconnecting)
	}
}

// B is judged after the batch: a confirmation in it comes first.
func TestBatchConfirmsBeforeB(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	_, pend := ownRekeyPending(t, f, m, cid)
	f.p.conns[cid].Standing.Exp = f.clk.Now().Add(90 * 24 * time.Hour)
	f.clk.Advance(PendingLife + time.Minute)
	f.p.drained = true
	tok, err := f.p.mintStanding(cid, &f.p.conns[cid].Peer, f.clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	m.SvcStand = tok // the member's token for the service, refreshed meanwhile
	m.Send("connection.note", []byte(`{}`))
	f.step()
	if c := f.p.conns[cid]; c.Pending != nil || epochOf(c) != pend || f.audited("pending_abandoned_b_passed") {
		t.Fatal("B ended an epoch confirmed in the same batch")
	}
}

// Crossing rekeys (§6.5): the lower th1 wins, both ways round; the pair
// ends on the winner's epoch.
func TestCrossingRekeysBothWays(t *testing.T) {
	seen := map[bool]bool{}
	for seed := byte(10); seed < 60 && len(seen) < 2; seed++ {
		f := newFixture(t)
		m := f.member(seed)
		cid := f.connect(m, "")
		f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
		f.tick() // our hs.init
		var ours [32]byte
		for _, og := range f.p.outgoing {
			copy(ours[:], og.Th1)
		}
		m.StartRekey() // the member's, crossing ours
		theirs := handshake.Th1(m.LastRekeyInit())
		oursWins := handshake.SimultaneousRekeyWinner(ours, theirs)
		m.IgnoreStray, m.IgnoreRevoked = true, true
		f.pump()
		c := f.p.conns[cid]
		cur := epochOf(c)
		if cur != m.KR.Current().ID() {
			t.Fatalf("seed %d: two epochs", seed)
		}
		e := c.epochMeta(cur[:])
		if e == nil || e.Mine != oursWins {
			t.Fatalf("seed %d: ours wins %v, but the epoch is ours %v", seed, oursWins, e != nil && e.Mine)
		}
		seen[oursWins] = true
	}
	if len(seen) != 2 {
		t.Fatal("only one way round was tried")
	}
}

// The service's pending epoch is abandoned at a link (H5), at a
// suspension, and when a reconnect fails, its unsent hs.fin with it.
func TestPendingAbandonedAtLinkSuspensionAndStale(t *testing.T) {
	for _, why := range []string{"link", "suspended", "stale"} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		mb := f.p.conns[cid].Peer.Relay.Mailbox
		m.NoConfirm = true
		f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
		f.tick()
		m.Step()
		f.failDeposit = func(mailbox, _ string) error {
			if mailbox == mb {
				return errUnavailable // the hs.fin waits
			}
			return nil
		}
		f.step()
		c := f.p.conns[cid]
		if c.Pending == nil {
			t.Fatalf("%s: not pending", why)
		}
		pend := c.Pending.ID
		f.p.mu.Lock()
		now := f.clk.Now()
		switch why {
		case "link":
			newIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{40}, 32))
			newKEM, _ := suite.NewPrivateKey(bytes.Repeat([]byte{41}, 32))
			r, err := handshake.NewRotation(m.IK, newIK, newKEM.Public())
			if err != nil {
				t.Fatal(err)
			}
			f.p.followRotation(c, newIK.Public().(ed25519.PublicKey), newKEM.Public(), []*handshake.Rotation{r}, true)
		case "suspended":
			f.p.suspend(c, now)
		case "stale":
			c.Reconnecting = true
			f.p.reconnectFailed(c)
		}
		f.p.mu.Unlock()
		if c.Pending != nil || c.kr.Pending() != nil || !f.audited("pending_abandoned_"+why) {
			t.Fatalf("%s: pending %v", why, c.Pending)
		}
		for _, e := range f.p.outbox {
			if bytes.Equal(e.FinEpoch, pend) {
				t.Fatalf("%s: its hs.fin is still queued", why)
			}
		}
	}
}

// Entries held on a stale connection still end: at their NotAfter, at
// their exp (held_expired), and tried past the 16-day window
// (undelivered_window).
func TestHeldEntriesEnd(t *testing.T) {
	for _, tc := range []string{"not_after", "held_expired", "undelivered_window"} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		c := f.p.conns[cid]
		now := f.clk.Now()
		in := &envelope.Inner{ID: f.p.newID(now), Type: "connection.note", TS: now, Body: []byte(`{}`)}
		if tc == "held_expired" {
			in.Exp = now.Add(time.Hour)
		}
		e := f.p.sendEntry(c, in, now)
		switch tc {
		case "not_after":
			e.NotAfter = now.Add(time.Hour)
		case "undelivered_window":
			e.Tried = true
		}
		c.State = StateStale
		f.clk.Advance(time.Hour + time.Minute)
		if tc == "undelivered_window" {
			f.clk.Advance(DedupeRetention)
		}
		f.p.mu.Lock()
		f.p.drainOutbox(context.Background())
		f.p.mu.Unlock()
		if f.p.outboxFor(cid) != 0 {
			t.Fatalf("%s: still held", tc)
		}
		if tc != "not_after" && !strings.Contains(f.logs.String(), "reason="+tc+" ") {
			t.Fatalf("%s: not audited", tc)
		}
	}
}

// At a reconnect's confirmation the service re-mints a standing and a
// reconnect token for the member (§6.3.1 "The prompt to adopt").
func TestRemintAtReconnectConfirmation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	before := len(m.Received(peerwire.TypeTokenIssued))
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting || c.Pending != nil {
		t.Fatal("not confirmed")
	}
	if n := len(m.Received(peerwire.TypeTokenIssued)) - before; n != 2 {
		t.Fatalf("%d tokens issued at the confirmation", n)
	}
}

// A pending epoch stored under another identity key than the service's is
// abandoned at load, with its hs.fin and tokens (R29-I7).
func TestPendingUnderOtherIKAbandonedAtLoad(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	m.NoConfirm = true
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	m.Step()
	f.failDeposit = func(mailbox, _ string) error {
		if mailbox == mb {
			return errUnavailable // the hs.fin waits
		}
		return nil
	}
	f.step()
	c := f.p.conns[cid]
	if c.Pending == nil {
		t.Fatal("not pending")
	}
	issued, pend := c.Pending.Issued, c.Pending.ID
	c.Pending.OwnIK = bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	c = f.p.conns[cid]
	if c.Pending != nil || c.kr.Pending() != nil || !f.audited("pending_abandoned_ik") || !strings.Contains(f.logs.String(), "alarm=outgoing_identity_changed") {
		t.Fatalf("pending %v", c.Pending)
	}
	for _, e := range f.p.outbox {
		if bytes.Equal(e.FinEpoch, pend) {
			t.Fatal("its hs.fin is still queued")
		}
	}
	for _, j := range issued {
		if tk := f.p.issued[j]; tk == nil || !tk.Denied {
			t.Fatalf("token %s not revoked", j)
		}
	}
}

// An open answer of ours, a reconnect's too, holds our rekeys back (§6.5,
// S5).
func TestRekeyWaitsForAnyAnswer(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Reconnect()
	f.step() // answered; its hs.fin never comes
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("a rekey started while a reconnect answer is open")
	}
	_ = cid
}

// The reconnect-kind carried token is adopted only on a later exp.
func TestAdoptReconnectTokenOnlyLaterExp(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	m.NoConfirm = true
	f.pump()
	c := f.p.conns[cid]
	held := c.Reconnect
	held.Exp = c.Pending.Reconnect.Exp.Add(time.Hour)
	c.Reconnect = held
	m.Send("connection.note", []byte(`{}`))
	f.step()
	if c = f.p.conns[cid]; c.Pending != nil || c.Reconnect.Token != held.Token {
		t.Fatal("a carried reconnect token with an earlier exp replaced the held one")
	}
}

// A relay.address.update during our reconnect try is refused: the try,
// its hs.init and its mailbox stay as they were.
func TestAddressUpdateDuringTryRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	var th1 []byte
	for _, og := range f.p.outgoing {
		th1 = og.Th1
	}
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	m.SendAddressUpdateWithReconnect(f.w, 77, peertest.RelayURL)
	f.step()
	c := f.p.conns[cid]
	if !c.Reconnecting || c.ReconnectTries != 1 || len(f.p.outgoing) != 1 || c.Peer.Relay.Mailbox != mb {
		t.Fatalf("reconnecting %v, tries %d, %d outgoing, mailbox %s (was %s)", c.Reconnecting, c.ReconnectTries, len(f.p.outgoing), c.Peer.Relay.Mailbox, mb)
	}
	for _, og := range f.p.outgoing {
		if !bytes.Equal(og.Th1, th1) {
			t.Fatal("the try was started again")
		}
	}
}

// An expired standing token with nothing waiting starts no reconnect.
func TestExpiredTokenNothingWaiting(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].Standing.Exp = f.clk.Now()
	f.step()
	f.tick()
	if c := f.p.conns[cid]; c.Reconnecting || len(f.p.outgoing) != 0 {
		t.Fatal("a reconnect with nothing waiting")
	}
}

// A batch that confirms nothing: the no-token reconnect starts at the end
// of that same step, without a tick.
func TestNoTokenReconnectAtBatchEnd(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	st := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == st {
			return errUnavailable
		}
		return nil
	}
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	f.step() // the entry waits
	c.Standing.Exp = f.clk.Now()
	m.Send("connection.note", []byte(`{}`)) // under the current epoch: confirms nothing
	f.step()
	if c = f.p.conns[cid]; !c.Reconnecting || len(f.p.outgoing) != 1 {
		t.Fatal("no reconnect at the end of the batch")
	}
}

// At a start, a stale connection's pending rekey with no valid standing
// token is abandoned at once (R29-I6), not at the first tick.
func TestStartAbandonsStalePendingWithoutToken(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ownRekeyPending(t, f, m, cid)
	c := f.p.conns[cid]
	c.State = StateStale
	c.Standing.Exp = f.clk.Now()
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	if c = f.p.conns[cid]; c.Pending != nil || !f.audited("pending_abandoned_no_token") {
		t.Fatalf("pending %v", c.Pending)
	}
}

// A connection a relay.address.update moved before the update was refused
// is not honored at load: it becomes stale, with an alarm.
func TestLegacyRelayMoveAtLoad(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.p.conns[cid].LegacyPrevRelayPK = bytes.Repeat([]byte{9}, ed25519.PublicKeySize)
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	c := f.p.conns[cid]
	if c.State != StateStale || len(c.LegacyPrevRelayPK) != 0 || !strings.Contains(f.logs.String(), "alarm=relay_moved_unlinked") {
		t.Fatalf("state %s", c.State)
	}
	n := len(m.Got)
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	f.pump()
	if len(m.Got) != n {
		t.Fatal("deposited to the moved address")
	}
}

// A reconnect token issued to us replaces the held one only if it is
// valid and lasts longer.
func TestIssuedReconnectTokenOnlyLater(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	held := f.p.conns[cid].Reconnect
	m.Send(peerwire.TypeTokenIssued, peerwire.TokenIssuedBody("reconnect", m.Mint(10*24*time.Hour)))
	f.pump()
	if c := f.p.conns[cid]; c.Reconnect.Token != held.Token || !f.audited("issued_token_not_later") {
		t.Fatal("a shorter-lived reconnect token replaced the held one")
	}
	m.Send(peerwire.TypeTokenIssued, peerwire.TokenIssuedBody("reconnect", m.Mint(330*24*time.Hour)))
	f.pump()
	if c := f.p.conns[cid]; c.Reconnect.Token == held.Token {
		t.Fatal("a longer-lived reconnect token was not adopted")
	}
}

// A refresh after quota_exceeded revokes only what §6.3.1 lets the issuer
// revoke (RELEASE-29 §12): an older standing token goes; the newest one a
// reconnect carried, the newest re-minted at a confirmation and one newer
// than the token the refresh came under stay.
func TestRefreshRevocations(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	var first string
	for j, tk := range f.p.issued {
		if tk.ConnID == cid && tk.Kind == tokStanding {
			first = j
		}
	}
	m.Reconnect() // the member's: our hs.resp carries a standing token
	f.pump()
	f.beginReconnectNow(cid) // ours: re-minted at its confirmation
	f.pump()
	var carried, prompt string
	for j, tk := range f.p.issued {
		if tk.ConnID == cid && tk.Kind == tokStanding && tk.Carried {
			carried = j
		}
		if tk.ConnID == cid && tk.Kind == tokStanding && tk.Prompt {
			prompt = j
		}
	}
	if first == "" || carried == "" || prompt == "" {
		t.Fatalf("tokens: first %q carried %q prompt %q", first, carried, prompt)
	}
	f.clk.Advance(peerwire.QuotaRefreshEvery + time.Minute)
	m.Send(peerwire.TypeTokenRefresh, peerwire.TokenRefreshBody()) // under the member's held token
	m.IgnoreRevoked = true                                         // that token goes too: the answer carries a fresh one
	f.pump()
	if !f.p.issued[first].Denied {
		t.Fatal("the older standing token was not revoked")
	}
	if f.p.issued[prompt].Denied {
		t.Fatal("the re-minted standing token was revoked")
	}
	newest := ""
	for j, tk := range f.p.issued {
		if tk.ConnID == cid && tk.Kind == tokStanding && tk.Carried && (newest == "" || tk.Seq > f.p.issued[newest].Seq) {
			newest = j
		}
	}
	if f.p.issued[newest].Denied {
		t.Fatal("the newest carried standing token was revoked")
	}
}

// memberReconnected has the member reconnect, with tokens that outlast the
// held ones; the member sends nothing after, so they stay carried.
func memberReconnected(t *testing.T, f *fixture, m *peertest.Member, cid string) *CarriedTokens {
	t.Helper()
	f.clk.Advance(time.Hour)
	m.Reconnect()
	f.pump()
	c := f.p.conns[cid]
	r := c.carriedFor(c.LastEpochID)
	if r == nil || !c.carriedUsable(r, f.clk.Now()) || epochOf(c) != m.KR.Current().ID() {
		t.Fatal("no carried tokens after the member's reconnect")
	}
	return r
}

// Our hs.confirm for a member's reconnect goes on its carried standing
// token (§6.3.1 "What they are used for before").
func TestConfirmOnCarriedToken(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	var tokens []string
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	f.failDeposit = func(mailbox, token string) error {
		if mailbox == mb {
			tokens = append(tokens, token)
		}
		return nil
	}
	r := memberReconnected(t, f, m, cid)
	n := 0
	for _, tk := range tokens {
		if tk == r.Standing.Token {
			n++
		}
	}
	if n != 2 { // our hs.resp, and our hs.confirm
		t.Fatalf("%d deposits on the carried token", n)
	}
}

// While carried tokens wait, no reconnect starts for want of a valid
// standing token; past their bound they are discarded and it starts.
func TestCarriedWaitThenBound(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	r := memberReconnected(t, f, m, cid)
	c := f.p.conns[cid]
	st := c.Standing.Token
	f.failDeposit = func(_, token string) error {
		if token == st {
			return errUnavailable
		}
		return nil
	}
	f.p.sendTo(c, "connection.note", []byte(`{}`), f.clk.Now())
	c.Standing.Exp = f.clk.Now()
	f.tick()
	if c = f.p.conns[cid]; c.Reconnecting {
		t.Fatal("a reconnect while carried tokens wait")
	}
	f.clk.Advance(r.Standing.Exp.Sub(f.clk.Now()) + time.Minute)
	f.tick()
	if c = f.p.conns[cid]; !c.Reconnecting || !c.confirmStopped() || !f.audited("carried_discarded") {
		t.Fatalf("past the bound: reconnecting %v", c.Reconnecting)
	}
}

// token_revoked on our hs.confirm's carried token: the member dropped
// that handshake; the tokens are discarded and hs.confirm stops.
func TestCarriedConfirmRevoked(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	mb := f.p.conns[cid].Peer.Relay.Mailbox
	var carried string
	f.failDeposit = func(mailbox, token string) error {
		c := f.p.conns[cid]
		if r := c.carriedFor(c.LastEpochID); mailbox == mb && r != nil && token == r.Standing.Token {
			carried = token
			return &relayclient.Error{Status: 403, Code: codeTokenRevoked}
		}
		return nil
	}
	f.clk.Advance(time.Hour)
	m.Reconnect()
	m.IgnoreRevoked = true
	f.pump()
	c := f.p.conns[cid]
	if carried == "" || !c.confirmStopped() || !f.audited("carried_token_revoked") {
		t.Fatalf("revoked %q, stopped %v", carried, c.confirmStopped())
	}
	f.clk.Advance(ConfirmResend + time.Minute)
	f.tick()
	if f.p.confirmQueued(f.p.conns[cid]) {
		t.Fatal("hs.confirm again after the discard")
	}
}

// Our own reconnect supersedes a member's carried tokens.
func TestOwnReconnectSupersedesCarried(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	memberReconnected(t, f, m, cid)
	f.beginReconnectNow(cid)
	m.NoConfirm = true
	f.pump()
	c := f.p.conns[cid]
	if !c.pendingReconnect() {
		t.Fatal("not pending")
	}
	for _, r := range c.Carried {
		if !r.Discarded {
			t.Fatal("an earlier carried record is still waiting")
		}
	}
}

// sealedUnder seals a note under the member's current epoch now, to be
// deposited later (as a copy of the member's vault holding that epoch
// would).
func sealedUnder(t *testing.T, m *peertest.Member, now time.Time) []byte {
	t.Helper()
	raw, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: "connection.note", TS: now, Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Rule E (§6.3.1): a reconnect naming the confirmed epoch while it is not
// current destroys, at its hs.fin, the epochs after the confirmed one. A
// later message under a destroyed epoch is refused when its ts is not
// later than the hs.init's (superseded_epoch), and is fork evidence when
// it is: the connection is suspended, reason epoch.
func TestRuleEAndForkEvidence(t *testing.T) {
	for _, later := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		first, second := memberRekey(t, f, m, cid) // confirmed stays the first
		if c := f.p.conns[cid]; !bytes.Equal(c.Confirmed, first[:]) {
			t.Fatal("confirmed moved")
		}
		var held []byte
		if !later {
			held = sealedUnder(t, m, f.clk.Now())
		}
		f.clk.Advance(time.Second)
		m.ReconnectNaming(first)
		f.clk.Advance(time.Minute)
		if later {
			held = sealedUnder(t, m, f.clk.Now())
		}
		m.IgnoreStray = true
		f.pump()
		c := f.p.conns[cid]
		if e := c.epochMeta(second[:]); e == nil || !e.Destroyed || epochOf(c) != m.KR.Current().ID() {
			t.Fatalf("later %v: the epoch after the confirmed one was not destroyed", later)
		}
		m.DepositTo(m.SvcStand, held)
		f.pump()
		c = f.p.conns[cid]
		if later {
			if c.State != StateSuspended || !strings.Contains(f.logs.String(), "alarm=fork_suspected") {
				t.Fatalf("state %s", c.State)
			}
			evs := f.ev.of(EventConnectionSuspended)
			if len(evs) != 1 || evs[0].Reason != SuspendEpoch {
				t.Fatalf("events %v", evs)
			}
		} else if c.State == StateSuspended || !f.audited("superseded_epoch") {
			t.Fatalf("earlier ts: state %s", c.State)
		}
	}
}

// §3.4.1 "Fork by ctx": after the member's key moved on, a reconnect
// naming an epoch older than the confirmed one, whose successor was signed
// by the old key, is fork evidence: the connection is suspended at its
// hs.fin.
func TestForkByCtx(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	first, _ := memberRekey(t, f, m, cid)
	m.Send("connection.note", []byte(`{}`)) // the second epoch is confirmed
	f.pump()
	m.RotateIdentity(40, false) // identity.rotate under the second, then a rekey under the new key
	f.pump()
	m.IgnoreStray = true
	m.ReconnectNaming(first)
	f.pump()
	if c := f.p.conns[cid]; c.State != StateSuspended || !strings.Contains(f.logs.String(), "alarm=fork_suspected") {
		t.Fatalf("state %s", c.State)
	}
}

// An epoch of ours abandoned while pending is accepted as a member
// reconnect's ctx until a newer epoch is confirmed (§6.6).
func TestAbandonedEpochAsCtx(t *testing.T) {
	for _, newerConfirmed := range []bool{false, true} {
		f := newFixture(t)
		m := f.member(10)
		cid := f.connect(m, "")
		_, pend := ownRekeyPending(t, f, m, cid)
		c := f.p.conns[cid]
		c.RekeyNotBefore = f.clk.Now().Add(RekeyBackoffMax)
		f.p.mu.Lock()
		f.p.abandonPending(c, "test", false, f.clk.Now())
		f.p.mu.Unlock()
		if newerConfirmed {
			f.p.mu.Lock()
			c.Abandoned = nil // as setConfirmed does when a newer epoch is confirmed
			f.p.mu.Unlock()
		}
		m.ReconnectNaming(pend)
		f.step()
		if answered := len(f.p.awaiting) == 1; answered == newerConfirmed {
			t.Fatalf("newer confirmed %v: answered %v", newerConfirmed, answered)
		}
	}
}

// A newer confirmation forgets the abandoned epochs.
func TestConfirmationForgetsAbandoned(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ownRekeyPending(t, f, m, cid)
	c := f.p.conns[cid]
	f.p.mu.Lock()
	f.p.abandonPending(c, "test", false, f.clk.Now())
	f.p.mu.Unlock()
	if len(c.Abandoned) != 1 {
		t.Fatal("not kept")
	}
	c.RekeyNotBefore = f.clk.Now().Add(RekeyBackoffMax) // no rekey of ours meanwhile
	m.IgnoreStray = true
	m.ReconnectNaming(m.KR.Current().ID()) // the abandoned epoch, which the member holds
	f.pump()
	m.Send("connection.note", []byte(`{}`)) // confirms the reconnect's epoch
	f.pump()
	if c = f.p.conns[cid]; len(c.Abandoned) != 0 {
		t.Fatal("kept after a newer confirmation")
	}
}

// §6.3.1 "A stale reconnect answer ends at a later message" (0.88.9): a
// message under a newer epoch with a later ts ends our open answer to a
// reconnect that named an older one.
func TestStaleReconnectAnswerEnds(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	first, _ := memberRekey(t, f, m, cid)
	earlier := sealedUnder(t, m, f.clk.Now()) // under the newer epoch, before the hs.init
	f.clk.Advance(time.Second)
	m.ReconnectNaming(first)
	f.step() // answered; its hs.fin will not come
	if len(f.p.awaiting) != 1 {
		t.Fatal("not answered")
	}
	m.DepositTo(m.SvcStand, earlier)
	f.step()
	if len(f.p.awaiting) != 1 {
		t.Fatal("a message older than the hs.init ended the answer")
	}
	f.clk.Advance(time.Minute)
	m.Send("connection.note", []byte(`{}`)) // under the newer epoch, later
	f.step()
	if len(f.p.awaiting) != 0 || !f.audited("answer_ended_stale") {
		t.Fatal("the stale answer was kept")
	}
}
