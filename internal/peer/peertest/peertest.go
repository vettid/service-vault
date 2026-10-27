// Package peertest is a TEST-ONLY in-memory relay and fake Member vault
// for exercising the service vault's peer (VAULT-MESSAGING §6.4).
package peertest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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

const RelayURL = "https://relay.vettid.test"

// Clock is a settable test Clock.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// World is an in-memory relay (RELAY-PROTOCOL §5, §6) shared by the
// service and fake members: it checks every deposit token's signature,
// issuer, subject, scope, expiry, single use and denylist as the relay
// does, and leases collected messages until they are acked.
type World struct {
	mu        sync.Mutex
	clk       *Clock
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

// NewClock returns a clock at t.
func NewClock(t time.Time) *Clock { return &Clock{t: t} }

// NewWorld returns an empty relay on clk.
func NewWorld(clk *Clock) *World {
	return &World{clk: clk, mailboxes: map[string]*mailbox{}, claims: map[string][]byte{}, denied: map[string]bool{},
		usedOpen: map[string]bool{},
		limits: relayclient.Limits{MaxTokenLifetimeSeconds: 365 * 24 * 3600, OpenTokenMaxLifetimeSeconds: 600,
			ClaimTTLSeconds: 600}}
}

func (w *World) id() string {
	w.nextID++
	s := fmt.Sprintf("%026d", w.nextID)
	b := []byte(s)
	for i := range b {
		b[i] = 'A' + (b[i] - '0')
	}
	return string(b)
}

// Denied reports whether a jti is on the relay's denylist.
func (w *World) Denied(jti string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.denied[jti]
}

// HasClaim reports whether a claim is still there.
func (w *World) HasClaim(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.claims[id]
	return ok
}

// Redeliver puts a collected message back into a mailbox under its
// msg_id, as a lost ack does.
func (w *World) Redeliver(mailboxID string, m relayclient.Message) {
	w.mu.Lock()
	defer w.mu.Unlock()
	mb := w.mailboxes[mailboxID]
	mb.msgs = append(mb.msgs, &storedMsg{m: m})
}

// View is one principal's relay client.
type View struct {
	w  *World
	c  *relayclient.Client
	mb string
}

func (w *World) View(key ed25519.PrivateKey) *View {
	c := relayclient.New(RelayURL, key)
	c.Now = w.clk.Now
	return &View{w: w, c: c, mb: c.MailboxID()}
}

func relayErr(status int, code string) error { return &relayclient.Error{Status: status, Code: code} }

func (v *View) Register(context.Context) (relayclient.Registration, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	if v.w.mailboxes[v.mb] == nil {
		v.w.mailboxes[v.mb] = &mailbox{pk: v.c.PublicKey()}
	}
	return relayclient.Registration{MailboxID: v.mb, Limits: v.w.limits}, nil
}

func (v *View) Collect(_ context.Context, _ time.Duration, max int) ([]relayclient.Message, error) {
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

func (v *View) Ack(_ context.Context, id string) error {
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

func (v *View) Deposit(_ context.Context, mailboxID, token string, payload []byte) (string, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	mb := v.w.mailboxes[mailboxID]
	if mb == nil {
		return "", relayErr(404, "mailbox_unknown")
	}
	cl, err := relayauth.ParseToken(token, mb.pk)
	if err != nil || cl.Iss != mailboxID || cl.Aud != RelayURL {
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

func (v *View) MintToken(sub, aud string, o relayclient.TokenOptions) (string, error) {
	return v.c.MintToken(sub, aud, o)
}

func (v *View) MintOpenToken(aud string, ttl time.Duration, jti string) (string, error) {
	return v.c.MintOpenToken(aud, ttl, jti)
}

func (v *View) PutClaim(_ context.Context, data []byte, ttl time.Duration) (string, time.Time, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	id := relayauth.NewClaimID()
	v.w.claims[id] = append([]byte(nil), data...)
	return id, v.w.clk.Now().Add(ttl), nil
}

func (v *View) GetClaim(id string) ([]byte, error) {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	b, ok := v.w.claims[id]
	if !ok {
		return nil, relayErr(404, "claim_unknown")
	}
	delete(v.w.claims, id)
	return b, nil
}

func (v *View) DeleteClaim(_ context.Context, id string) error {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	delete(v.w.claims, id)
	return nil
}

func (v *View) Revoke(_ context.Context, es ...relayclient.Revocation) error {
	v.w.mu.Lock()
	defer v.w.mu.Unlock()
	for _, e := range es {
		if e.Kind == "jti" {
			v.w.denied[e.Value] = true
		}
	}
	return nil
}

// Member is a fake Member vault: the accepting side of §6.4 built from
// vms/handshake, vms/invite and vms/peerwire, as the Member vault runs
// it (vault/handshakes.go acceptInvite, requests.go).
type Member struct {
	t    testing.TB
	clk  *Clock
	IK   ed25519.PrivateKey
	kem  *suite.PrivateKey
	rk   ed25519.PrivateKey
	R    *View
	Addr handshake.RelayAddr
	Cred ed25519.PrivateKey // the member's credential key (§3.5.1)

	svc handshake.Principal // the service, from the bundle

	ini       *handshake.Initiator
	ReqEp     *handshake.Epoch // the handshake's epoch before activation
	KR        *handshake.Keyring
	SAS       string
	SvcReq    string // the service's request token (hs.resp)
	SvcStand  string // the service's standing token (connection.approved)
	SvcRecon  string
	Approved  bool // our member approved
	PeerOK    bool // the service's connection.approved arrived
	Active    bool
	FirstName string
	LastName  string

	rekey    *handshake.Initiator
	recon    *handshake.Initiator
	awaitFin *handshake.Responder
	// Rotations are the identity.rotate links since the session's epoch
	// (for a reconnect, §6.6).
	Rotations []*handshake.Rotation

	Got        []*envelope.Inner // messages received in the session
	Challenges []*peerwire.ConnAuthChallenge
}

func NewMember(t testing.TB, w *World, seed byte) *Member {
	kem, err := suite.NewPrivateKey(bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 2}, 32))
	m := &Member{t: t, clk: w.clk, IK: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)), kem: kem, rk: rk,
		Cred: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 3}, 32)), FirstName: "Nora", LastName: "Member"}
	m.R = w.View(rk)
	if _, err := m.R.Register(context.Background()); err != nil {
		t.Fatal(err)
	}
	pk := rk.Public().(ed25519.PublicKey)
	m.Addr = handshake.RelayAddr{URL: RelayURL, Mailbox: relayauth.MailboxID(pk), PK: pk}
	return m
}

func (m *Member) Mint(ttl time.Duration) string {
	m.t.Helper()
	tok, err := m.R.MintToken(relayauth.EncodeKey(m.svc.Relay.PK), RelayURL, relayclient.TokenOptions{TTL: ttl})
	if err != nil {
		m.t.Fatal(err)
	}
	return tok
}

// accept follows an invitation link (§6.4 "Accepting"): fetch the claim,
// check the commitment, open the bundle, and send hs.init on the open
// token with a request token for the inviter.
func (m *Member) Accept(link string, profile string) {
	m.t.Helper()
	q, err := invite.ParseLink(link)
	if err != nil {
		m.t.Fatalf("ParseLink: %v", err)
	}
	blob, err := m.R.GetClaim(q.ClaimID)
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
		b, _ := json.Marshal(map[string]string{"first_name": m.FirstName, "last_name": m.LastName})
		profile = string(b)
	}
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeConnection, Ctx: b.InviteID,
		Identity: m.IK, StaticKEM: m.kem.Public(), Relay: m.Addr,
		ResponderIK: b.Vault.IK, ResponderEK: b.Vault.KEM, ResponderRelayKey: b.Vault.Relay.PK,
		Policy: handshake.PolicyVaultToVault, Now: m.clk.Now(), Profile: json.RawMessage(profile),
		Token: m.Mint(peerwire.RequestTokenConnection),
	})
	if err != nil {
		m.t.Fatalf("NewInitiator: %v", err)
	}
	m.ini = ini
	if _, err := m.R.Deposit(context.Background(), b.Vault.Relay.Mailbox, b.Token, ini.Envelope()); err != nil {
		m.t.Fatalf("deposit hs.init: %v", err)
	}
}

func (m *Member) DepositTo(tok string, payload []byte) {
	m.t.Helper()
	if _, err := m.R.Deposit(context.Background(), m.svc.Relay.Mailbox, tok, payload); err != nil {
		m.t.Fatalf("Member deposit: %v", err)
	}
}

// step collects the Member's mailbox and handles what is there.
func (m *Member) Step() int {
	m.t.Helper()
	msgs, _ := m.R.Collect(context.Background(), 0, 32)
	for _, msg := range msgs {
		if m.handle(msg) {
			_ = m.R.Ack(context.Background(), msg.MsgID)
		}
	}
	return len(msgs)
}

func (m *Member) handle(msg relayclient.Message) bool {
	m.t.Helper()
	env, err := envelope.Parse(msg.Payload)
	if err != nil {
		m.t.Fatalf("Member: envelope: %v", err)
	}
	now := m.clk.Now()
	sender, _ := relayauth.DecodeKey(msg.Sender)
	if env.Mode() == envelope.ModeSealed {
		switch {
		case m.ini != nil && env.RecipientKid().Equal(m.ini.EphKid()):
			res, err := m.ini.HandleResp(msg.Payload, sender, now)
			if err != nil {
				m.t.Fatalf("Member: hs.resp: %v", err)
			}
			if _, err := peerwire.VerifyHeldToken(res.Resp.Token, m.svc.Relay.PK, m.svc.Relay.Mailbox, m.svc.Relay.URL,
				m.Addr.PK); err != nil {
				m.t.Fatalf("Member: request token: %v", err)
			}
			m.SvcReq, m.SAS, m.ReqEp, m.ini = res.Resp.Token, res.SAS, res.Epoch, nil
			m.DepositTo(m.SvcReq, res.Fin)
		case m.recon != nil && env.RecipientKid().Equal(m.recon.EphKid()):
			res, err := m.recon.HandleResp(msg.Payload, sender, now)
			if err != nil {
				m.t.Fatalf("Member: reconnect hs.resp: %v", err)
			}
			m.recon = nil
			m.SvcStand, m.SvcRecon = res.Resp.Token, res.Resp.ReconnectToken
			m.DepositTo(m.SvcStand, res.Fin)
			m.KR.Activate(res.Epoch, now)
			m.Rotations = nil
		case m.rekey != nil && env.RecipientKid().Equal(m.rekey.EphKid()):
			res, err := m.rekey.HandleResp(msg.Payload, sender, now)
			if err != nil {
				m.t.Fatalf("Member: rekey hs.resp: %v", err)
			}
			m.rekey = nil
			m.DepositTo(m.SvcStand, res.Fin)
			m.KR.Activate(res.Epoch, now)
		default:
			m.t.Fatal("Member: unexpected sealed message")
		}
		return true
	}
	if m.KR != nil {
		in, ep, err := m.KR.Open(env, now)
		if err == nil {
			if in.Type == handshake.TypeInit {
				m.answerRekey(msg.Payload, in, ep, sender)
				return true
			}
			m.Got = append(m.Got, in)
			if in.Type == peerwire.TypeTokenIssued {
				kind, tok, err := peerwire.ParseTokenIssued(in.Body)
				if err != nil {
					m.t.Fatalf("Member: token issued: %v", err)
				}
				if _, err := peerwire.VerifyHeldToken(tok, m.svc.Relay.PK, m.svc.Relay.Mailbox, m.svc.Relay.URL, m.Addr.PK); err == nil {
					if kind == "reconnect" {
						m.SvcRecon = tok
					} else {
						m.SvcStand = tok
					}
				}
			}
			if in.Type == peerwire.TypeConnAuthChallenge {
				c, err := peerwire.ParseConnAuthChallenge(in.Body)
				if err != nil {
					m.t.Fatalf("Member: challenge: %v", err)
				}
				m.Challenges = append(m.Challenges, c)
			}
			return true
		}
		if m.awaitFin != nil {
			fr, err := m.awaitFin.HandleFin(msg.Payload, sender, now)
			if err == nil {
				m.awaitFin = nil
				m.KR.Activate(fr.Epoch, now)
				return true
			}
		}
	}
	if m.ReqEp != nil {
		in, err := m.ReqEp.Open(env)
		if err != nil {
			return false // not yet
		}
		switch in.Type {
		case peerwire.TypeConnectionApproved:
			tok, rt, err := peerwire.ParseConnectionApproved(in.Body)
			if err != nil {
				m.t.Fatalf("Member: approved: %v", err)
			}
			for _, x := range []string{tok, rt} {
				if _, err := peerwire.VerifyHeldToken(x, m.svc.Relay.PK, m.svc.Relay.Mailbox, m.svc.Relay.URL, m.Addr.PK); err != nil {
					m.t.Fatalf("Member: token in connection.approved: %v", err)
				}
			}
			m.SvcStand, m.SvcRecon, m.PeerOK = tok, rt, true
			m.maybeActivate()
		default:
			if !m.Approved {
				m.t.Fatalf("Member: %s before activation", in.Type)
			}
			return false
		}
		return true
	}
	return false
}

// approve is the Member's approval after comparing the SAS (§6.4).
func (m *Member) Approve() {
	m.t.Helper()
	raw, err := m.ReqEp.Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeConnectionApproved, TS: m.clk.Now(),
		Body: peerwire.ConnectionApprovedBody(m.Mint(peerwire.StandingMax), m.Mint(300*24*time.Hour))})
	if err != nil {
		m.t.Fatal(err)
	}
	m.DepositTo(m.SvcReq, raw)
	m.Approved = true
	m.maybeActivate()
}

// decline is the Member's decline (§6.4, 0.10.5).
func (m *Member) Decline() {
	m.t.Helper()
	raw, err := m.ReqEp.Seal(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeConnectionDeclined, TS: m.clk.Now(),
		Body: peerwire.ConnectionDeclinedBody()})
	if err != nil {
		m.t.Fatal(err)
	}
	m.DepositTo(m.SvcReq, raw)
	m.ReqEp = nil
}

func (m *Member) maybeActivate() {
	if !m.Approved || !m.PeerOK || m.Active {
		return
	}
	now := m.clk.Now()
	m.ReqEp.MarkActivated(now)
	m.KR = &handshake.Keyring{}
	m.KR.Activate(m.ReqEp, now)
	m.ReqEp, m.Active = nil, true
	// The Member vault's profile at activation (§10.8).
	m.Send(peerwire.TypeProfileUpdate, peerwire.ProfileUpdateBody(1, m.FirstName, m.LastName, m.IK.Public().(ed25519.PublicKey), nil))
}

func (m *Member) NewID() string {
	id, err := envelope.NewULID(m.clk.Now())
	if err != nil {
		m.t.Fatal(err)
	}
	return id
}

// send seals a message in the current epoch on the service's standing token.
func (m *Member) Send(typ string, body []byte) string {
	m.t.Helper()
	return m.SendInner(&envelope.Inner{ID: m.NewID(), Type: typ, TS: m.clk.Now(), Body: body})
}

func (m *Member) SendInner(in *envelope.Inner) string {
	m.t.Helper()
	raw, err := m.KR.Current().Seal(in)
	if err != nil {
		m.t.Fatal(err)
	}
	m.DepositTo(m.SvcStand, raw)
	return in.ID
}

// startRekey initiates a rekey (§6.5), as a Member vault does after 24 h.
func (m *Member) StartRekey() {
	m.t.Helper()
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeRekey, Identity: m.IK, StaticKEM: m.kem.Public(), Relay: m.Addr,
		ResponderIK: m.svc.IK, ResponderRelayKey: m.svc.Relay.PK, Current: m.KR.Current(),
		Policy: handshake.PolicyVaultToVault, Now: m.clk.Now(),
	})
	if err != nil {
		m.t.Fatal(err)
	}
	m.rekey = ini
	m.DepositTo(m.SvcStand, ini.Envelope())
}

// answerRekey answers the service's rekey hs.init (§6.5).
func (m *Member) answerRekey(raw []byte, in *envelope.Inner, ep *handshake.Epoch, sender ed25519.PublicKey) {
	m.t.Helper()
	now := m.clk.Now()
	pi, err := handshake.AcceptRekey(raw, in, ep, now)
	if err != nil {
		m.t.Fatalf("Member: accept rekey: %v", err)
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{Identity: m.IK, Policy: handshake.PolicyVaultToVault,
		CollectSender: sender, RecordRelayKey: m.svc.Relay.PK, KnownInitiatorIK: m.svc.IK, Now: now})
	if err != nil {
		m.t.Fatalf("Member: respond rekey: %v", err)
	}
	m.awaitFin = resp
	m.DepositTo(m.SvcStand, env)
}

// received returns the session messages of a type the Member received.
func (m *Member) Received(typ string) []*envelope.Inner {
	var out []*envelope.Inner
	for _, in := range m.Got {
		if in.Type == typ {
			out = append(out, in)
		}
	}
	return out
}

// RotateIdentity rotates the Member vault's identity and KEM keys (§3.4):
// identity.rotate signed by both keys in the session, then a rekey under
// the new key, unless later is set (the session is down: the link waits
// for a reconnect, §6.6).
func (m *Member) RotateIdentity(seed byte, later bool) *handshake.Rotation {
	m.t.Helper()
	newIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	newKEM, err := suite.NewPrivateKey(bytes.Repeat([]byte{seed + 1}, 32))
	if err != nil {
		m.t.Fatal(err)
	}
	r, err := handshake.NewRotation(m.IK, newIK, newKEM.Public())
	if err != nil {
		m.t.Fatal(err)
	}
	if later {
		m.Rotations = append(m.Rotations, r)
	} else {
		m.SendRotation(r)
	}
	m.IK, m.kem = newIK, newKEM
	if !later {
		m.StartRekey()
	}
	return r
}

// SendRotation sends one identity.rotate statement in the session.
func (m *Member) SendRotation(r *handshake.Rotation) {
	m.t.Helper()
	body, _ := json.Marshal(map[string]json.RawMessage{"rotation": r.Marshal()})
	m.Send("identity.rotate", body)
}

// RotateRelay rotates the Member vault's relay key (§3.4): the new
// mailbox and tokens for it go out as relay.address.update, deposited with
// the old key; the service's tokens for the new key then arrive there.
// The old view is returned (it can still deposit).
func (m *Member) RotateRelay(w *World, seed byte) *View {
	m.t.Helper()
	old := m.R
	rk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	nv := w.View(rk)
	if _, err := nv.Register(context.Background()); err != nil {
		m.t.Fatal(err)
	}
	pk := rk.Public().(ed25519.PublicKey)
	addr := handshake.RelayAddr{URL: RelayURL, Mailbox: relayauth.MailboxID(pk), PK: pk}
	mint := func(ttl time.Duration) string {
		tok, err := nv.MintToken(relayauth.EncodeKey(m.svc.Relay.PK), RelayURL, relayclient.TokenOptions{TTL: ttl})
		if err != nil {
			m.t.Fatal(err)
		}
		return tok
	}
	body, _ := json.Marshal(map[string]any{
		"relay":           map[string]string{"url": addr.URL, "mailbox": addr.Mailbox, "pk": base64.StdEncoding.EncodeToString(pk)},
		"token":           mint(peerwire.StandingMax),
		"reconnect_token": mint(300 * 24 * time.Hour),
	})
	m.Send("relay.address.update", body) // with the old key
	m.R, m.rk, m.Addr = nv, rk, addr
	return old
}

// Reconnect sends a reconnect hs.init (§6.6) on the service's reconnect
// token, carrying the rotations since the last epoch.
func (m *Member) Reconnect() {
	m.t.Helper()
	ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
		Purpose: handshake.PurposeReconnect, Ctx: handshake.EpochCtx(m.KR.Current().ID()),
		Identity: m.IK, StaticKEM: m.kem.Public(), Relay: m.Addr,
		Token: m.Mint(peerwire.StandingMax), ReconnectToken: m.Mint(300 * 24 * time.Hour), Rotations: m.Rotations,
		ResponderIK: m.svc.IK, ResponderEK: m.svc.KEM, ResponderRelayKey: m.svc.Relay.PK,
		Policy: handshake.PolicyVaultToVault, Now: m.clk.Now(),
	})
	if err != nil {
		m.t.Fatal(err)
	}
	m.recon = ini
	m.DepositTo(m.SvcRecon, ini.Envelope())
}
