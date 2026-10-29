package peer

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// An invitation is redeemed only with its own open token: its id with
// another invitation's token is refused, and the other invitation stays
// usable.
func TestInviteNeedsItsOwnOpenToken(t *testing.T) {
	f := newFixture(t)
	a, b := f.invite("a"), f.invite("b")
	m := f.member(10)
	m.AcceptOnToken(a.Link, b.Link)
	f.pump()
	if len(f.ev.of(EventConnectionPending)) != 0 || m.SAS != "" {
		t.Fatal("an invitation was redeemed with another one's token")
	}
	if inv, _ := f.p.Invite(a.ID); inv.Used {
		t.Fatal("the invitation was used up")
	}
}

// An answer that arrives after the challenge's exp, before the
// housekeeping expired it, does not approve.
func TestLateAnswerRefused(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	if _, err := f.p.Authenticate(context.Background(), cid, "Sign in", "", time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(2 * time.Minute)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	f.p.DeliverEvents(context.Background())
	if len(f.ev.of(EventSignInApproved)) != 0 {
		t.Fatal("a late answer approved")
	}
}

// A copy of an hs.init already answered (the same bytes, an outbox
// retry) is not answered again, and the handshake completes; reconnects
// beyond MaxAwaitingPerConn are refused without touching the ones
// awaiting (no token is revoked: the member may be using one).
func TestReconnectCopiesAndBound(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Reconnect()
	m.ResendReconnect()
	f.pump()
	if c := f.p.conns[cid]; c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("the reconnect did not complete with its copy around")
	}

	m.IgnoreStray = true
	for range MaxAwaitingPerConn + 2 {
		m.Reconnect()
		if _, err := f.p.Step(context.Background(), 0); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, aw := range f.p.awaiting {
		if aw.ConnID == cid {
			n++
		}
	}
	if n != MaxAwaitingPerConn {
		t.Fatalf("%d reconnects awaiting hs.fin", n)
	}
	for jti, tok := range f.p.issued {
		if tok.ConnID == cid && (tok.Denied || f.w.Denied(jti)) {
			t.Fatal("a token was revoked")
		}
	}
}

// What waits for one connection is bounded: past MaxOutboxPerConn a new
// message is dropped, not queued.
func TestOutboxBoundedPerConnection(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	c := f.p.conns[cid]
	for i := 0; f.p.outboxFor(cid) < MaxOutboxPerConn; i++ {
		f.p.queueDeposit(&outboxEntry{ConnID: cid, Mailbox: c.Peer.Relay.Mailbox, Payload: []byte("x")}, f.clk.Now())
	}
	if id := f.p.sendTo(c, peerwire.TypeTokenRefresh, peerwire.TokenRefreshBody(), f.clk.Now()); id != "" {
		t.Fatal("queued past the bound")
	}
	if f.p.outboxFor(cid) != MaxOutboxPerConn {
		t.Fatalf("outbox %d", f.p.outboxFor(cid))
	}
}

// A dedupe marker put twice before a flush is one change (a transaction
// refuses two operations on one item).
func TestMarkOnce(t *testing.T) {
	f := newFixture(t)
	f.p.mark(kindMsg, "m1", []byte{1}, f.clk.Now().Add(time.Hour))
	f.p.mark(kindMsg, "m1", []byte{1}, f.clk.Now().Add(time.Hour))
	n := 0
	for _, c := range f.p.extra {
		if c.Kind == kindMsg && c.ID == "m1" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d changes for one marker", n)
	}
}
