package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/service-vault/internal/peer/peertest"

	"github.com/vettid/vettid-vault/vms/handshake"
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
