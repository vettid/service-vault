package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

const testRelayURL = "https://relay.vettid.test"

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// world is an in-memory relay (RELAY-PROTOCOL §5, §6) shared by the
// service and fake members: it checks every deposit token's signature,
// issuer, subject, scope, expiry, single use and denylist as the relay
// does, and leases collected messages until they are acked.
type world struct {
	mu        sync.Mutex
	clk       *clock
	mailboxes map[string]*mailbox
	claims    map[string][]byte
	denied    map[string]bool
	usedOpen  map[string]bool
	nextID    int
	limits    relayclient.Limits
}

type mailbox struct {
	pk   ed25519.PublicKey
	msgs []*storedMsg
}

type storedMsg struct {
	m      relayclient.Message
	leased time.Time
}

func newWorld(clk *clock) *world {
	return &world{clk: clk, mailboxes: map[string]*mailbox{}, claims: map[string][]byte{}, denied: map[string]bool{},
		usedOpen: map[string]bool{},
		limits: relayclient.Limits{MaxTokenLifetimeSeconds: 365 * 24 * 3600, OpenTokenMaxLifetimeSeconds: 600,
			ClaimTTLSeconds: 600}}
}

func (w *world) id() string {
	w.nextID++
	s := fmt.Sprintf("%026d", w.nextID)
	b := []byte(s)
	for i := range b {
		b[i] = 'A' + (b[i] - '0')
	}
	return string(b)
}

// view is one principal's relay client.
type view struct {
	w  *world
	c  *relayclient.Client
	mb string
	// failDeposit, if set, answers every deposit with this error.
	failDeposit error
}

func (w *world) view(key ed25519.PrivateKey) *view {
	c := relayclient.New(testRelayURL, key)
	c.Now = w.clk.Now
	return &view{w: w, c: c, mb: c.MailboxID()}
}

func relayErr(status int, code string) error { return &relayclient.Error{Status: status, Code: code} }

func (v *view) Register(context.Context) (relayclient.Registration, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	if v.w.mailboxes[v.mb] == nil {
		v.w.mailboxes[v.mb] = &mailbox{pk: v.c.PublicKey()}
	}
	return relayclient.Registration{MailboxID: v.mb, Limits: v.w.limits}, nil
}

func (v *view) Collect(_ context.Context, _ time.Duration, max int) ([]relayclient.Message, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	now := v.w.clk.Now()
	var out []relayclient.Message
	for _, s := range v.w.mailboxes[v.mb].msgs {
		if len(out) == max {
			break
		}
		if now.Before(s.leased) {
			continue
		}
		s.leased = now.Add(60 * time.Second)
		out = append(out, s.m)
	}
	return out, nil
}

func (v *view) Ack(_ context.Context, id string) error {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	mb := v.w.mailboxes[v.mb]
	for i, s := range mb.msgs {
		if s.m.MsgID == id {
			mb.msgs = append(mb.msgs[:i:i], mb.msgs[i+1:]...)
			break
		}
	}
	return nil
}

func (v *view) Deposit(_ context.Context, mailboxID, token string, payload []byte) (string, error) {
	if v.failDeposit != nil {
		return "", v.failDeposit
	}
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	mb := v.w.mailboxes[mailboxID]
	if mb == nil {
		return "", relayErr(404, "mailbox_unknown")
	}
	cl, err := relayauth.ParseToken(token, mb.pk)
	if err != nil || cl.Iss != mailboxID || cl.Aud != testRelayURL {
		return "", relayErr(401, "token_invalid")
	}
	if v.w.denied[cl.Jti] {
		return "", relayErr(401, "token_revoked")
	}
	if !v.w.clk.Now().Before(cl.Exp) {
		return "", relayErr(401, "token_expired")
	}
	switch cl.Scope {
	case relayauth.ScopeDepositOpen:
		if v.w.usedOpen[cl.Jti] {
			return "", relayErr(409, "token_used")
		}
		v.w.usedOpen[cl.Jti] = true
	case relayauth.ScopeDeposit:
		if cl.Sub != v.c.PublicKeyB64() {
			return "", relayErr(403, "sender_mismatch")
		}
	default:
		return "", relayErr(401, "token_invalid")
	}
	id := v.w.id()
	mb.msgs = append(mb.msgs, &storedMsg{m: relayclient.Message{MsgID: id, Sender: v.c.PublicKeyB64(), JTI: cl.Jti,
		Payload: append([]byte(nil), payload...)}})
	return id, nil
}

func (v *view) MintToken(sub, aud string, o relayclient.TokenOptions) (string, error) {
	return v.c.MintToken(sub, aud, o)
}

func (v *view) MintOpenToken(aud string, ttl time.Duration, jti string) (string, error) {
	return v.c.MintOpenToken(aud, ttl, jti)
}

func (v *view) PutClaim(_ context.Context, data []byte, ttl time.Duration) (string, time.Time, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	id := relayauth.NewClaimID()
	v.w.claims[id] = append([]byte(nil), data...)
	return id, v.w.clk.Now().Add(ttl), nil
}

func (v *view) GetClaim(id string) ([]byte, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	b, ok := v.w.claims[id]
	if !ok {
		return nil, relayErr(404, "claim_unknown")
	}
	delete(v.w.claims, id)
	return b, nil
}

func (v *view) DeleteClaim(_ context.Context, id string) error {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	delete(v.w.claims, id)
	return nil
}

func (v *view) Revoke(_ context.Context, es ...relayclient.Revocation) error {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	for _, e := range es {
		if e.Kind == "jti" {
			v.w.denied[e.Value] = true
		}
	}
	return nil
}

// member is a fake member vault: the accepting side of §6.4 built from
// vms/handshake, vms/invite and vms/peerwire, as the member vault runs
// it (vault/handshakes.go acceptInvite, requests.go).
type member struct {
	t    *testing.T
	clk  *clock
	ik   ed25519.PrivateKey
	kem  *suite.PrivateKey
	rk   ed25519.PrivateKey
	r    *view
	addr handshake.RelayAddr
	cred ed25519.PrivateKey // the member's credential key (§3.5.1)

	svc handshake.Principal // the service, from the bundle

	ini      *handshake.Initiator
	reqEp    *handshake.Epoch
	kr       *handshake.Keyring
	sas      string
	svcReq   string // the service's request token (hs.resp)
	svcStand string // the service's standing token (connection.approved)
	svcRecon string
	approved bool // our member approved
	peerOK   bool // the service's connection.approved arrived
	active   bool

	rekey    *handshake.Initiator
	awaitFin *handshake.Responder

	got        []*envelope.Inner // messages received in the session
	challenges []*peerwire.ConnAuthChallenge
}

func newMember(t *testing.T, w *world, seed byte) *member {
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 2}, 32))
	m := &member{t: t, clk: w.clk, ik: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)), kem: kem, rk: rk,
		cred: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 3}, 32))}
	m.r = w.view(rk)
	if _, err := m.r.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	pk := rk.Public().(ed25519.PublicKey)
	m.addr = handshake.RelayAddr{URL: testRelayURL, Mailbox: relayauth.MailboxID(pk), PK: pk}
	return m
}

func (m *member) mint(ttl time.Duration) string {
	m.t.Helper()
	tok, err := m.r.MintToken(relayauth.EncodeKey(m.svc.Relay.PK), testRelayURL, relayclient.TokenOptions{TTL: ttl})
	if err != nil {
		m.t.Fatal(err)
	}
	return tok
}

// accept follows an invitation link (§6.4 "Accepting"): fetch the claim,
// check the commitment, open the bundle, and send hs.init on the open
// token with a request token for the inviter.
func (m *member) accept(link string, profile string) {
	m.t.Helper()
	q, err := invite.ParseLink(link)
	if err != nil {
		m.t.Fatalf("ParseLink: %v", err)
	}
	blob, err := m.r.GetClaim(q.ClaimID)
	if err != nil {
		m.t.Fatalf("GetClaim: %v", err)
	}
	if sha256.Sum256(blob) != q.Hash {
		m.t.Fatal("claim hash")
	}
	b, err := invite.OpenBundle(blob, q, m.clk.Now())
	if err != nil {
		m.t.Fatalf("OpenBundle: %v", err)
	}
	if b.Remote {
		m.t.Fatal("remote invitation")
	}
	m.svc = b.Vault
	if profile == "" {
		profile = `{"first_name":"Nora","last_name":"Member"}`
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeConnection, Ctx: b.InviteID,
		Identity: m.ik, StaticKEM: m.kem.Public(), Relay: m.addr,
		ResponderIK: b.Vault.IK, ResponderEK: b.Vault.KEM, ResponderRelayKey: b.Vault.Relay.PK,
		Policy: handshake.PolicyVaultToVault, Now: m.clk.Now(), Profile: json.RawMessage(profile),
		Token: m.mint(peerwire.RequestTokenConnection),
	})
	if err != nil {
		m.t.Fatalf("NewInitiator: %v", err)
	}
	m.ini = ini
	if _, err := m.r.Deposit(context.Background(), b.Vault.Relay.Mailbox, b.Token, ini.Envelope()); err != nil {
		m.t.Fatalf("deposit hs.init: %v", err)
	}
}

func (m *member) deposit(tok string, payload []byte) {
	m.t.Helper()
	if _, err := m.r.Deposit(context.Background(), m.svc.Relay.Mailbox, tok, payload); err != nil {
		m.t.Fatalf("member deposit: %v", err)
	}
}

// step collects the member's mailbox and handles what is there.
func (m *member) step() int {
	m.t.Helper()
	msgs, _ := m.r.Collect(context.Background(), 0, 32)
	for _, msg := range msgs {
		if m.handle(msg) {
			_ = m.r.Ack(context.Background(), msg.MsgID)
		}
	}
	return len(msgs)
}

func (m *member) handle(msg relayclient.Message) bool {
	m.t.Helper()
	env, err := envelope.Parse(msg.Payload)
	if err != nil {
		m.t.Fatalf("member: envelope: %v", err)
	}
	now := m.clk.Now()
	sender, _ := relayauth.DecodeKey(msg.Sender)
	if env.Mode() == envelope.ModeSealed {
		switch {
		case m.ini != nil && env.RecipientKid().Equal(m.ini.EphKid()):
			res, err := m.ini.HandleResp(msg.Payload, sender, now)
			if err != nil {
				m.t.Fatalf("member: hs.resp: %v", err)
			}
			if _, err := peerwire.VerifyHeldToken(res.Resp.Token, m.svc.Relay.PK, m.svc.Relay.Mailbox, m.svc.Relay.URL,
				m.addr.PK); err != nil {
				m.t.Fatalf("member: request token: %v", err)
			}
			m.svcReq, m.sas, m.reqEp, m.ini = res.Resp.Token, res.SAS, res.Epoch, nil
			m.deposit(m.svcReq, res.Fin)
		case m.rekey != nil && env.RecipientKid().Equal(m.rekey.EphKid()):
			res, err := m.rekey.HandleResp(msg.Payload, sender, now)
			if err != nil {
				m.t.Fatalf("member: rekey hs.resp: %v", err)
			}
			m.rekey = nil
			m.deposit(m.svcStand, res.Fin)
			m.kr.Activate(res.Epoch, now)
		default:
			m.t.Fatal("member: unexpected sealed message")
		}
		return true
	}
	if m.kr != nil {
		in, ep, err := m.kr.Open(env, now)
		if err == nil {
			if in.Type == handshake.TypeInit {
				m.answerRekey(msg.Payload, in, ep, sender)
				return true
			}
			m.got = append(m.got, in)
			if in.Type == peerwire.TypeConnAuthChallenge {
				c, err := peerwire.ParseConnAuthChallenge(in.Body)
				if err != nil {
					m.t.Fatalf("member: challenge: %v", err)
				}
				m.challenges = append(m.challenges, c)
			}
			return true
		}
		if m.awaitFin != nil {
			fr, err := m.awaitFin.HandleFin(msg.Payload, sender, now)
			if err == nil {
				m.awaitFin = nil
				m.kr.Activate(fr.Epoch, now)
				return true
			}
		}
	}
	if m.reqEp != nil {
		in, err := m.reqEp.Open(env)
		if err != nil {
			return false // not yet
		}
		switch in.Type {
		case peerwire.TypeConnectionApproved:
			tok, rt, err := peerwire.ParseConnectionApproved(in.Body)
			if err != nil {
				m.t.Fatalf("member: approved: %v", err)
			}
			for _, x := range []string{tok, rt} {
				if _, err := peerwire.VerifyHeldToken(x, m.svc.Relay.PK, m.svc.Relay.Mailbox, m.svc.Relay.URL, m.addr.PK); err != nil {
					m.t.Fatalf("member: token in connection.approved: %v", err)
				}
			}
			m.svcStand, m.svcRecon, m.peerOK = tok, rt, true
			m.maybeActivate()
		default:
			if !m.approved {
				m.t.Fatalf("member: %s before activation", in.Type)
			}
			return false
		}
		return true
	}
	return false
}

// approve is the member's approval after comparing the SAS (§6.4).
func (m *member) approve() {
	m.t.Helper()
	raw, err := m.reqEp.Seal(&envelope.Inner{ID: m.newID(), Type: peerwire.TypeConnectionApproved, TS: m.clk.Now(),
		Body: peerwire.ConnectionApprovedBody(m.mint(peerwire.StandingMax), m.mint(300*24*time.Hour))})
	if err != nil {
		m.t.Fatal(err)
	}
	m.deposit(m.svcReq, raw)
	m.approved = true
	m.maybeActivate()
}

// decline is the member's decline (§6.4, 0.10.5).
func (m *member) decline() {
	m.t.Helper()
	raw, err := m.reqEp.Seal(&envelope.Inner{ID: m.newID(), Type: peerwire.TypeConnectionDeclined, TS: m.clk.Now(),
		Body: peerwire.ConnectionDeclinedBody()})
	if err != nil {
		m.t.Fatal(err)
	}
	m.deposit(m.svcReq, raw)
	m.reqEp = nil
}

func (m *member) maybeActivate() {
	if !m.approved || !m.peerOK || m.active {
		return
	}
	now := m.clk.Now()
	m.reqEp.MarkActivated(now)
	m.kr = &handshake.Keyring{}
	m.kr.Activate(m.reqEp, now)
	m.reqEp, m.active = nil, true
	// The member vault's profile at activation (§10.8).
	m.send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(1, "Nora", "Member", m.ik.Public().(ed25519.PublicKey), nil))
}

func (m *member) newID() string {
	id, err := envelope.NewULID(m.clk.Now())
	if err != nil {
		m.t.Fatal(err)
	}
	return id
}

// send seals a message in the current epoch on the service's standing token.
func (m *member) send(typ string, body []byte) string {
	m.t.Helper()
	return m.sendInner(&envelope.Inner{ID: m.newID(), Type: typ, TS: m.clk.Now(), Body: body})
}

func (m *member) sendInner(in *envelope.Inner) string {
	m.t.Helper()
	raw, err := m.kr.Current().Seal(in)
	if err != nil {
		m.t.Fatal(err)
	}
	m.deposit(m.svcStand, raw)
	return in.ID
}

// startRekey initiates a rekey (§6.5), as a member vault does after 24 h.
func (m *member) startRekey() {
	m.t.Helper()
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: m.ik, StaticKEM: m.kem.Public(), Relay: m.addr,
		ResponderIK: m.svc.IK, ResponderRelayKey: m.svc.Relay.PK, Current: m.kr.Current(),
		Policy: handshake.PolicyVaultToVault, Now: m.clk.Now(),
	})
	if err != nil {
		m.t.Fatal(err)
	}
	m.rekey = ini
	m.deposit(m.svcStand, ini.Envelope())
}

// answerRekey answers the service's rekey hs.init (§6.5).
func (m *member) answerRekey(raw []byte, in *envelope.Inner, ep *handshake.Epoch, sender ed25519.PublicKey) {
	m.t.Helper()
	now := m.clk.Now()
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		m.t.Fatalf("member: accept rekey: %v", err)
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{Identity: m.ik, Policy: handshake.PolicyVaultToVault,
		CollectSender: sender, RecordRelayKey: m.svc.Relay.PK, KnownInitiatorIK: m.svc.IK, Now: now})
	if err != nil {
		m.t.Fatalf("member: respond rekey: %v", err)
	}
	m.awaitFin = resp
	m.deposit(m.svcStand, env)
}

// received returns the session messages of a type the member received.
func (m *member) received(typ string) []*envelope.Inner {
	var out []*envelope.Inner
	for _, in := range m.got {
		if in.Type == typ {
			out = append(out, in)
		}
	}
	return out
}
