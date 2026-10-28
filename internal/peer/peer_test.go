package peer

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

type sink struct {
	mu  sync.Mutex
	evs []*Event
}

func (s *sink) Deliver(_ context.Context, e *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, e)
	return nil
}

func (s *sink) of(typ string) []*Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Event
	for _, e := range s.evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

type fixture struct {
	t     *testing.T
	clk   *peertest.Clock
	w     *peertest.World
	keys  *Keys
	store *MemStore
	sv    *peertest.View
	p     *Peer
	ev    *sink
	ms    []*peertest.Member
	// afterRestore, when set, is the next start's Config.AfterRestore.
	afterRestore func(context.Context) error
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clk := peertest.NewClock(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	w := peertest.NewWorld(clk)
	f := &fixture{t: t, clk: clk, w: w, keys: testKeys(t), store: NewMemStore(), ev: &sink{}}
	f.store.Now = clk.Now
	f.sv = w.View(f.keys.Relay)
	f.start()
	return f
}

// start (re)creates the peer from the store, as a restart does.
func (f *fixture) start() {
	f.t.Helper()
	p, err := New(Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Keys: f.keys, Relay: f.sv, RelayURL: peertest.RelayURL, Store: f.store, Events: f.ev, Now: f.clk.Now,
		Profile: Profile{FirstName: "VettID", LastName: "Member Service"}, AfterRestore: f.afterRestore})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := p.Start(context.Background()); err != nil {
		f.t.Fatalf("Start: %v", err)
	}
	f.p = p
}

func (f *fixture) member(seed byte) *peertest.Member {
	m := peertest.NewMember(f.t, f.w, seed)
	f.ms = append(f.ms, m)
	return m
}

// pump runs the service and the members until nothing moves.
func (f *fixture) pump() {
	f.t.Helper()
	ctx := context.Background()
	for i := 0; i < 50; i++ {
		n, err := f.p.Step(ctx, 0)
		if err != nil {
			f.t.Fatalf("Step: %v", err)
		}
		for _, m := range f.ms {
			n += m.Step()
		}
		f.p.DeliverEvents(ctx)
		if n == 0 {
			return
		}
	}
}

func (f *fixture) tick() {
	f.t.Helper()
	if err := f.p.Tick(context.Background()); err != nil {
		f.t.Fatalf("Tick: %v", err)
	}
	f.p.DeliverEvents(context.Background())
}

func (f *fixture) invite(tag string) *InviteRecord {
	f.t.Helper()
	inv, err := f.p.CreateInvite(context.Background(), tag)
	if err != nil {
		f.t.Fatalf("CreateInvite: %v", err)
	}
	return inv
}

// connect runs §6.4 to activation and returns the connection id.
func (f *fixture) connect(m *peertest.Member, tag string) string {
	f.t.Helper()
	inv := f.invite(tag)
	m.Accept(inv.Link, "")
	f.pump()
	pend := f.ev.of(EventConnectionPending)
	if len(pend) == 0 {
		f.t.Fatal("no connection.pending")
	}
	e := pend[len(pend)-1]
	if e.SAS == "" || e.SAS != m.SAS {
		f.t.Fatalf("SAS: service %q, member %q", e.SAS, m.SAS)
	}
	m.Approve()
	f.pump()
	if !m.Active {
		f.t.Fatal("member not active")
	}
	return e.ConnectionID
}

func TestConnectFromInvitation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	inv := f.invite("email-key-1")
	if got, _ := f.p.Invite(inv.ID); got.Status != InviteWaiting {
		t.Fatalf("status %q", got.Status)
	}
	m.Accept(inv.Link, "")
	f.pump()

	// hs.fin checked out: SAS equal on both sides, the service approved
	// its side, the application learns the SAS.
	pend := f.ev.of(EventConnectionPending)
	if len(pend) != 1 || pend[0].SAS != m.SAS || len(m.SAS) != 6 || pend[0].InviteID != inv.ID || pend[0].Tag != "email-key-1" {
		t.Fatalf("pending %+v, member SAS %q", pend, m.SAS)
	}
	if pend[0].Name != "Nora Member" {
		t.Fatalf("name %q", pend[0].Name)
	}
	got, _ := f.p.Invite(inv.ID)
	if got.Status != InviteSAS || got.SAS != m.SAS || got.ConnID != pend[0].ConnectionID {
		t.Fatalf("invite %+v", got)
	}
	if !m.PeerOK || m.SvcStand == "" {
		t.Fatal("the service's connection.approved did not arrive")
	}
	if m.Active || len(f.ev.of(EventConnectionAdded)) != 0 {
		t.Fatal("active before the member approved")
	}

	m.Approve()
	f.pump()
	added := f.ev.of(EventConnectionAdded)
	if len(added) != 1 || added[0].ConnectionID != pend[0].ConnectionID || added[0].Tag != "email-key-1" {
		t.Fatalf("added %+v", added)
	}
	c, ok := f.p.Connection(added[0].ConnectionID)
	if !ok || c.State != StateActive || c.Name != "Nora Member" {
		t.Fatalf("connection %+v", c)
	}
	if got, _ := f.p.Invite(inv.ID); got.Status != InviteConnected {
		t.Fatalf("invite status %q", got.Status)
	}

	// The member's vault got the service's profile: its names and ik
	// (§10.8), which make the connection's title.
	pu := m.Received(peerwire.TypeProfileUpdate)
	if len(pu) != 1 {
		t.Fatalf("%d profile.update", len(pu))
	}
	u, err := peerwire.ParseProfileUpdate(pu[0].Body)
	if err != nil || u.Malformed || u.FirstName != "VettID" || u.LastName != "Member Service" ||
		!ed25519.PublicKey(u.IK).Equal(f.keys.IKPublic()) || len(u.Items) != 0 {
		t.Fatalf("profile.update %+v %v", u, err)
	}

	// The claim is gone: the invitation is single use.
	if _, err := m.R.GetClaim(inv.ClaimID); err == nil {
		t.Fatal("claim still there")
	}
}

func TestInviteSingleUse(t *testing.T) {
	f := newFixture(t)
	inv := f.invite("")
	m := f.member(10)
	m.Accept(inv.Link, "")
	f.pump()
	// A second hs.init for the same invite id is dropped (§6.4), even on a
	// fresh token: replay the first one's bundle by hand.
	if n := len(f.ev.of(EventConnectionPending)); n != 1 {
		t.Fatalf("%d pending", n)
	}
	got, _ := f.p.Invite(inv.ID)
	if !got.Used || !got.Withdrew {
		t.Fatalf("invite %+v", got)
	}
	if !f.w.Denied(got.OpenJTI) {
		t.Fatal("open jti not denylisted")
	}
	if f.w.HasClaim(got.ClaimID) {
		t.Fatal("claim not deleted")
	}
}

func TestProfileRequired(t *testing.T) {
	f := newFixture(t)
	inv := f.invite("")
	m := f.member(10)
	m.Accept(inv.Link, `{"name":"no core names"}`)
	f.pump()
	if len(f.ev.of(EventConnectionPending)) != 0 || m.SAS != "" {
		t.Fatal("hs.init without the core names was answered")
	}
	if got, _ := f.p.Invite(inv.ID); got.Used {
		t.Fatal("invitation used by a refused hs.init")
	}
}

func TestDecline(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	inv := f.invite("tag")
	m.Accept(inv.Link, "")
	f.pump()
	cid := f.ev.of(EventConnectionPending)[0].ConnectionID
	m.Decline()
	f.pump()
	d := f.ev.of(EventConnectionDeclined)
	if len(d) != 1 || d[0].ConnectionID != cid {
		t.Fatalf("declined %+v", d)
	}
	if got, _ := f.p.Invite(inv.ID); got.Status != InviteDeclined || got.SAS != "" {
		t.Fatalf("invite %+v", got)
	}
	// Every token issued to the member is denylisted (§7.4).
	for _, tk := range f.p.issued {
		if tk.ConnID == cid && !f.w.Denied(tk.JTI) {
			t.Fatalf("%s token not denylisted", tk.Kind)
		}
	}
	if _, ok := f.p.Connection(cid); ok {
		t.Fatal("declined connection exists")
	}
}

func TestRequestExpiry(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	inv := f.invite("")
	m.Accept(inv.Link, "")
	f.pump()
	cid := f.ev.of(EventConnectionPending)[0].ConnectionID
	// Approved by the service: kept 16 days after hs.init (§6.4).
	f.clk.Advance(ApprovedRetention - time.Minute)
	f.tick()
	if len(f.ev.of(EventConnectionExpired)) != 0 {
		t.Fatal("expired early")
	}
	f.clk.Advance(2 * time.Minute)
	f.tick()
	e := f.ev.of(EventConnectionExpired)
	if len(e) != 1 || e[0].ConnectionID != cid {
		t.Fatalf("expired %+v", e)
	}
	if got, _ := f.p.Invite(inv.ID); got.Status != InviteExpired {
		t.Fatalf("invite %q", got.Status)
	}
	// A late approval finds the request token denylisted (§7.4).
	raw, _ := m.ReqEp.Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeConnectionApproved, TS: f.clk.Now(),
		Body: peerwire.ConnectionApprovedBody(m.Mint(peerwire.StandingMax), m.Mint(peerwire.StandingMax))})
	if _, err := m.R.Deposit(context.Background(), f.keys.Mailbox(), m.SvcReq, raw); err == nil {
		t.Fatal("deposit on an expired request's token accepted")
	}
}

func TestUnusedInviteExpires(t *testing.T) {
	f := newFixture(t)
	inv := f.invite("")
	f.clk.Advance(InviteTTL)
	f.tick()
	got, _ := f.p.Invite(inv.ID)
	if got.Status != InviteExpired || !f.w.Denied(got.OpenJTI) {
		t.Fatalf("invite %+v", got)
	}
	f.clk.Advance(InviteRetention)
	f.tick()
	if _, ok := f.p.Invite(inv.ID); ok {
		t.Fatal("invite kept past its retention")
	}
}

func TestMemberRekeysAfterThreshold(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	// 24 h later the member's vault rekeys (§6.5); the service answers.
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge - time.Minute)
	f.tick()
	if len(f.p.outgoing) != 0 {
		t.Fatal("the service started a rekey early")
	}
	old := m.KR.Current().ID()
	m.StartRekey()
	f.pump()
	if m.KR.Current().ID() == old {
		t.Fatal("member epoch unchanged")
	}
	c := f.p.conns[cid]
	if c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("service epoch differs")
	}
	// Traffic in the new epoch both ways.
	m.Send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(2, "Nora", "Renamed", m.IK.Public().(ed25519.PublicKey), nil))
	f.pump()
	if got, _ := f.p.Connection(cid); got.Name != "Nora Renamed" {
		t.Fatalf("name %q", got.Name)
	}
}

func TestServiceRekeysAfterThreshold(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	old := m.KR.Current().ID()
	f.clk.Advance(handshake.PolicyVaultToVault.MaxAge + time.Second)
	f.tick()
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing rekeys", len(f.p.outgoing))
	}
	f.pump()
	if len(f.p.outgoing) != 0 || m.KR.Current().ID() == old || f.p.conns[cid].kr.Current().ID() != m.KR.Current().ID() {
		t.Fatal("rekey did not complete")
	}
	// The new epoch carries a challenge.
	if _, err := f.p.Authenticate(context.Background(), cid, "after rekey", time.Minute); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(m.Challenges) != 1 {
		t.Fatal("no challenge in the new epoch")
	}
}

func TestTokenRemintAndRefresh(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	// 21 days on, the standing token we issued has < 10 days left: a
	// fresh one goes out as relay.token.issued (§7.2).
	f.clk.Advance(21 * 24 * time.Hour)
	f.tick()
	f.pump()
	is := m.Received(peerwire.TypeTokenIssued)
	if len(is) == 0 {
		t.Fatal("no relay.token.issued")
	}
	kind, tok, err := peerwire.ParseTokenIssued(is[0].Body)
	if err != nil || kind != tokStanding {
		t.Fatalf("issued %q %v", kind, err)
	}
	if _, err := peerwire.VerifyHeldToken(tok, f.keys.RelayPublic(), f.keys.Mailbox(), peertest.RelayURL, m.Addr.PK); err != nil {
		t.Fatal(err)
	}
	m.SvcStand = tok

	// The member asks for a refresh while its token has 30 days left: a
	// refresh after quota_exceeded, one in 24 hours, the old tokens
	// denylisted (§7.2).
	in := &envelope.Inner{ID: m.NewID(), Type: peerwire.TypeTokenRefresh, TS: f.clk.Now(), Body: peerwire.TokenRefreshBody()}
	m.SendInner(in)
	f.pump()
	ans := responsesTo(m, in.ID)
	if len(ans) != 1 || ans[0].Status != envelope.StatusOK {
		t.Fatalf("refresh answer %+v", ans)
	}
	old := m.SvcStand
	if _, m.SvcStand, err = peerwire.ParseTokenIssued(ans[0].Body); err != nil {
		t.Fatal(err)
	}
	if _, err := m.R.Deposit(context.Background(), f.keys.Mailbox(), old, []byte("x")); err == nil {
		t.Fatal("the replaced token still works")
	}
	// A retransmission gets the cached answer, not a second token (§8.2).
	m.SendInner(&envelope.Inner{ID: in.ID, Type: in.Type, TS: f.clk.Now(), Body: in.Body})
	f.pump()
	if ans2 := responsesTo(m, in.ID); len(ans2) != 2 || string(ans2[1].Body) != string(ans[0].Body) {
		t.Fatalf("retransmission answered %+v", ans2)
	}
	// Another refresh within 24 hours: too_soon.
	in2 := &envelope.Inner{ID: m.NewID(), Type: peerwire.TypeTokenRefresh, TS: f.clk.Now(), Body: peerwire.TokenRefreshBody()}
	m.SendInner(in2)
	f.pump()
	if a := responsesTo(m, in2.ID); len(a) != 1 || a[0].Error == nil || a[0].Error.Code != peerwire.CodeTooSoon {
		t.Fatalf("second refresh %+v", a)
	}

	// The service holds the member's standing token (30 days); with
	// < 3 days left it asks for a refresh and stores the answer.
	c := f.p.conns[cid]
	before := c.Standing.Exp
	f.clk.Advance(6*24*time.Hour + time.Hour)
	f.tick()
	f.pump()
	var reqs []*envelope.Inner
	for _, in := range m.Received(peerwire.TypeTokenRefresh) {
		if in.Re == "" {
			reqs = append(reqs, in)
		}
	}
	if len(reqs) != 1 || c.RefreshID != reqs[0].ID {
		t.Fatalf("refresh requests %d", len(reqs))
	}
	fresh := m.Mint(peerwire.StandingMax)
	raw, _ := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeTokenRefresh, TS: f.clk.Now(),
		Re: reqs[0].ID, Status: envelope.StatusOK, Body: peerwire.TokenIssuedBody(tokStanding, fresh)})
	m.DepositTo(m.SvcStand, raw)
	f.pump()
	if c.Standing.Token != fresh || !c.Standing.Exp.After(before) || c.RefreshID != "" {
		t.Fatal("refreshed token not stored")
	}
}

func responsesTo(m *peertest.Member, id string) []*envelope.Inner {
	var out []*envelope.Inner
	for _, in := range m.Got {
		if in.Re == id {
			out = append(out, in)
		}
	}
	return out
}

func TestRemovalByMember(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	r := f.ev.of(EventConnectionRemoved)
	if len(r) != 1 || r[0].ConnectionID != cid || r[0].Direction != "in" || r[0].Tag != "tag" {
		t.Fatalf("removed %+v", r)
	}
	if _, ok := f.p.Connection(cid); ok {
		t.Fatal("connection kept")
	}
	for _, tk := range f.p.issued {
		if tk.ConnID == cid && !f.w.Denied(tk.JTI) {
			t.Fatalf("%s token not denylisted", tk.Kind)
		}
	}
	// A message on a revoked token does not reach the service.
	if _, err := m.R.Deposit(context.Background(), f.keys.Mailbox(), m.SvcStand, []byte("x")); err == nil {
		t.Fatal("deposit on a removed connection's token accepted")
	}
}

func TestRemovalByService(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(m.Received(peerwire.TypeConnectionRemoved)) != 1 {
		t.Fatal("member did not get connection.removed")
	}
	if r := f.ev.of(EventConnectionRemoved); len(r) != 1 || r[0].Direction != "out" {
		t.Fatalf("removed %+v", r)
	}
	if err := f.p.Remove(context.Background(), cid); err != ErrNotFound {
		t.Fatalf("second remove: %v", err)
	}
}

func TestReconnectAfterRemovalWithNewInvite(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.pump()
	m2 := peertest.NewMember(t, f.w, 10) // the same vault, connecting again
	f.ms = []*peertest.Member{m2}
	cid2 := f.connect(m2, "")
	if cid2 == cid {
		t.Fatal("same id")
	}
}

func TestKnownIdentityDropped(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "")
	inv := f.invite("")
	m2 := peertest.NewMember(t, f.w, 10) // same keys: an active connection's identity
	f.ms = []*peertest.Member{m2}
	m2.Accept(inv.Link, "")
	f.pump()
	if len(f.ev.of(EventConnectionPending)) != 1 {
		t.Fatal("hs.init from a connected identity answered")
	}
	if got, _ := f.p.Invite(inv.ID); got.Used {
		t.Fatal("invitation used")
	}
}

func TestSignIn(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()
	const ctxt = "Sign in to VettID Member Service — match code 42"

	// Signed: approved, key pinned.
	id, err := f.p.Authenticate(ctx, cid, ctxt, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(m.Challenges) != 1 || m.Challenges[0].RequestID != id || m.Challenges[0].Context != ctxt {
		t.Fatalf("challenge %+v", m.Challenges)
	}
	in := m.Received(peerwire.TypeConnAuthChallenge)[0]
	if want := f.clk.Now().Add(2 * time.Minute).Truncate(time.Millisecond); !in.Exp.Equal(want) {
		t.Fatalf("exp %v, want %v", in.Exp, want)
	}
	r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	ap := f.ev.of(EventSignInApproved)
	if len(ap) != 1 || ap[0].RequestID != id || ap[0].ConnectionID != cid || ap[0].KeyChanged || ap[0].Tag != "tag" {
		t.Fatalf("approved %+v", ap)
	}
	if !ed25519.PublicKey(f.p.conns[cid].AuthKey).Equal(m.Cred.Public()) {
		t.Fatal("key not pinned")
	}
	// A replay of the response matches no pending challenge.
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if len(f.ev.of(EventSignInApproved)) != 1 {
		t.Fatal("replayed response approved again")
	}

	// Denied.
	id2, _ := f.p.Authenticate(ctx, cid, ctxt, 2*time.Minute)
	f.pump()
	m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(id2).Marshal())
	f.pump()
	if d := f.ev.of(EventSignInDenied); len(d) != 1 || d[0].RequestID != id2 || d[0].Reason != "denied" {
		t.Fatalf("denied %+v", d)
	}

	// A signature over another context does not verify.
	id3, _ := f.p.Authenticate(ctx, cid, ctxt, 2*time.Minute)
	f.pump()
	forged := *m.Challenges[2]
	forged.Context = "something else"
	bad, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), &forged, f.clk.Now(), nil)
	bad.RequestID = id3
	m.Send(peerwire.TypeConnAuthResponse, bad.Marshal())
	f.pump()
	if d := f.ev.of(EventSignInDenied); len(d) != 2 || d[1].RequestID != id3 || d[1].Reason != "bad_signature" {
		t.Fatalf("bad signature %+v", d)
	}

	// A different key: approved and reported as a change.
	id4, _ := f.p.Authenticate(ctx, cid, ctxt, 2*time.Minute)
	f.pump()
	other := ed25519.NewKeyFromSeed(make([]byte, 32))
	r4, _ := peerwire.SignConnAuth(other, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[3], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r4.Marshal())
	f.pump()
	if ap := f.ev.of(EventSignInApproved); len(ap) != 2 || ap[1].RequestID != id4 || !ap[1].KeyChanged {
		t.Fatalf("changed key %+v", ap)
	}

	// Expired: no answer within the TTL.
	id5, _ := f.p.Authenticate(ctx, cid, ctxt, 2*time.Minute)
	f.pump()
	f.clk.Advance(2 * time.Minute)
	f.tick()
	if e := f.ev.of(EventSignInExpired); len(e) != 1 || e[0].RequestID != id5 {
		t.Fatalf("expired %+v", e)
	}
	// A late answer matches nothing.
	late, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[4], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, late.Marshal())
	f.pump()
	if len(f.ev.of(EventSignInApproved)) != 2 {
		t.Fatal("late answer approved")
	}

	if _, err := f.p.Authenticate(ctx, "nope", ctxt, time.Minute); err != ErrNotFound {
		t.Fatalf("unknown connection: %v", err)
	}
}

func TestRestartKeepsState(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	inv := f.invite("tag")
	m.Accept(inv.Link, "")
	f.pump()
	// Restart between the service's approval and the member's.
	f.start()
	m.Approve()
	f.pump()
	added := f.ev.of(EventConnectionAdded)
	if len(added) != 1 {
		t.Fatalf("added %+v", added)
	}
	cid := added[0].ConnectionID
	id, err := f.p.Authenticate(context.Background(), cid, "x", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	// Restart with a challenge pending.
	f.start()
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	if ap := f.ev.of(EventSignInApproved); len(ap) != 1 || ap[0].RequestID != id {
		t.Fatalf("approved %+v", ap)
	}
}

func TestDedupeByMsgID(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	id, _ := f.p.Authenticate(context.Background(), cid, "x", 5*time.Minute)
	f.pump()
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	// Collect without acking (a lost ack), then let the lease lapse.
	msgs, _ := f.sv.Collect(context.Background(), 0, 32)
	if len(msgs) != 1 {
		t.Fatal("no message")
	}
	f.clk.Advance(61 * time.Second)
	f.pump()
	f.w.Redeliver(f.keys.Mailbox(), msgs[0]) // redelivered under the same msg_id
	f.pump()
	if ap := f.ev.of(EventSignInApproved); len(ap) != 1 || ap[0].RequestID != id {
		t.Fatalf("approved %+v", ap)
	}
}

func TestStoreConflictStops(t *testing.T) {
	f := newFixture(t)
	inv := f.invite("")
	// Another writer changes the invitation behind the peer's back.
	recs, _ := f.store.Load(context.Background(), kindInvite)
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindInvite, ID: inv.ID, Data: recs[0].Data, IfVersion: recs[0].Version}}); err != nil {
		t.Fatal(err)
	}
	m := f.member(10)
	m.Accept(inv.Link, "")
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("flush over another writer's change succeeded")
	}
}

func TestCancelChallengeAndDenyEnds(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "tag")
	ctx := context.Background()

	// Cancelled: forgotten, a later signed answer is ignored, no event.
	id, err := f.p.Authenticate(ctx, cid, "x", 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	if ok, err := f.p.CancelChallenge(ctx, id); !ok || err != nil {
		t.Fatalf("cancel: %v %v", ok, err)
	}
	if ok, _ := f.p.CancelChallenge(ctx, id); ok {
		t.Fatal("cancelled twice")
	}
	r, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[0], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
	f.pump()
	f.clk.Advance(3 * time.Minute)
	f.tick()
	if n := len(f.ev.of(EventSignInApproved)) + len(f.ev.of(EventSignInExpired)) + len(f.ev.of(EventSignInDenied)); n != 0 {
		t.Fatalf("%d events for a cancelled challenge", n)
	}
	// It stays cancelled across a restart.
	f.start()
	if ok, _ := f.p.CancelChallenge(ctx, id); ok {
		t.Fatal("cancelled challenge came back")
	}

	// Denied on the phone: the challenge ends; a signed answer after the
	// denial is ignored.
	id2, _ := f.p.Authenticate(ctx, cid, "x", 2*time.Minute)
	f.pump()
	m.Send(peerwire.TypeConnAuthResponse, peerwire.DeniedConnAuth(id2).Marshal())
	f.pump()
	r2, _ := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[1], f.clk.Now(), nil)
	m.Send(peerwire.TypeConnAuthResponse, r2.Marshal())
	f.pump()
	if len(f.ev.of(EventSignInDenied)) != 1 || len(f.ev.of(EventSignInApproved)) != 0 {
		t.Fatal("answer after a denial counted")
	}
	if ok, _ := f.p.CancelChallenge(ctx, id2); ok {
		t.Fatal("denied challenge still pending")
	}
}
