package peer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Relay is the part of relayclient.Client the peer uses: the service's
// own mailbox on its relay, and deposits into members' mailboxes on the
// same relay.
type Relay interface {
	ClaimRelay
	Register(ctx context.Context) (relayclient.Registration, error)
	Collect(ctx context.Context, wait time.Duration, max int) ([]relayclient.Message, error)
	Ack(ctx context.Context, msgID string) error
	Deposit(ctx context.Context, mailboxID, token string, payload []byte) (string, error)
	MintToken(senderB64, audience string, o relayclient.TokenOptions) (string, error)
	DeleteClaim(ctx context.Context, claimID string) error
	Revoke(ctx context.Context, entries ...relayclient.Revocation) error
}

var _ Relay = (*relayclient.Client)(nil)

// Profile is the service's account names, which members see as the
// connection's title (§6.2, §10.8): the core of its profile.update.
type Profile struct {
	FirstName string
	LastName  string
}

// Name is the display name: the names joined by a space.
func (pr Profile) Name() string { return joinName(pr.FirstName, pr.LastName) }

// Config configures a Peer.
type Config struct {
	Keys     *Keys
	Relay    Relay
	RelayURL string // the service's relay (RELAY-PROTOCOL §3), as in its invitations
	Profile  Profile
	Store    Store
	Events   Events
	Now      func() time.Time
	Log      *slog.Logger
	// PollWait is the collect long-poll wait (default 25 s; at most 25 s).
	PollWait time.Duration
}

// Peer is the service's side of VMS v2 connections (VAULT-MESSAGING §6,
// §7, §8): it owns the service's mailbox, answers members' handshakes on
// its invitations, approves its own side, keeps the sessions and tokens
// of active connections, and challenges members to sign in (§10.4).
//
// It mirrors the member vault's behaviour as a connection's inviter. It
// never initiates a connection (it only invites), never answers
// challenges (it has no credential) and never rotates its identity.
type Peer struct {
	cfg    Config
	limits relayclient.Limits

	mu         sync.Mutex
	conns      map[string]*Connection
	invites    map[string]*InviteRecord
	awaiting   map[string]*awaiting
	requests   map[string]*request
	outgoing   map[string]*outgoing
	issued     map[string]*IssuedToken
	outbox     []*outboxEntry
	challenges map[string]*challenge
	events     []*Event
	seq        uint64
	rates      map[string]*rateWindow

	dirty    map[key]struct{}
	extra    []Change
	versions map[key]uint64

	started bool
	evWake  chan struct{}
}

// New returns a peer; Start loads its state.
func New(cfg Config) (*Peer, error) {
	if cfg.Keys == nil || cfg.Relay == nil || cfg.Store == nil || cfg.RelayURL == "" {
		return nil, errors.New("peer: incomplete config")
	}
	if !peerwire.ValidAccountName(cfg.Profile.FirstName) || !peerwire.ValidAccountName(cfg.Profile.LastName) {
		return nil, errors.New("peer: the profile needs a first and a last name (§10.8)")
	}
	if err := handshake.ValidateRelayURL(cfg.RelayURL); err != nil {
		return nil, fmt.Errorf("peer: relay url: %w", err)
	}
	cfg.RelayURL = strings.TrimRight(cfg.RelayURL, "/")
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PollWait <= 0 || cfg.PollWait > 25*time.Second {
		cfg.PollWait = 25 * time.Second
	}
	return &Peer{cfg: cfg,
		conns: map[string]*Connection{}, invites: map[string]*InviteRecord{}, awaiting: map[string]*awaiting{},
		requests: map[string]*request{}, outgoing: map[string]*outgoing{}, issued: map[string]*IssuedToken{},
		challenges: map[string]*challenge{}, rates: map[string]*rateWindow{},
		dirty: map[key]struct{}{}, versions: map[key]uint64{}, evWake: make(chan struct{}, 1)}, nil
}

func (p *Peer) log() *slog.Logger {
	if p.cfg.Log != nil {
		return p.cfg.Log
	}
	return slog.Default()
}

func (p *Peer) now() time.Time { return p.cfg.Now() }

func (p *Peer) newID(now time.Time) string {
	id, err := envelope.NewULID(now)
	if err != nil {
		panic("peer: randomness unavailable")
	}
	return id
}

func (p *Peer) ownAddr() handshake.RelayAddr { return p.cfg.Keys.Principal(p.cfg.RelayURL).Relay }

// audit logs a dropped or refused message by its reason, with ids only.
func (p *Peer) audit(event, connID string) {
	p.log().Warn("drop", "reason", event, "connection_id", connID)
}

// Start registers the mailbox (RELAY-PROTOCOL §6.1), loads the state and
// runs the start-up housekeeping (§7.2 "On unlock" steps 1–2) and the
// outbox.
func (p *Peer) Start(ctx context.Context) error {
	reg, err := p.cfg.Relay.Register(ctx)
	if err != nil {
		return fmt.Errorf("peer: register: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.limits = reg.Limits
	if !p.started {
		if err := p.load(ctx); err != nil {
			return err
		}
		p.started = true
	}
	p.housekeeping(p.now())
	if err := p.flush(ctx); err != nil {
		return err
	}
	p.drainOutbox(ctx)
	return p.flush(ctx)
}

// Run collects and processes messages until ctx ends, runs the
// housekeeping every minute and delivers events. It calls Start first.
func (p *Peer) Run(ctx context.Context) error {
	if err := p.Start(ctx); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(2)
	go func() { defer wg.Done(); p.eventLoop(ctx) }()
	go func() { defer wg.Done(); p.tickLoop(ctx) }()
	p.kickEvents()
	fails := 0
	for ctx.Err() == nil {
		if _, err := p.Step(ctx, p.cfg.PollWait); err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, ErrConflict) {
				return err // another writer: stop rather than overwrite
			}
			fails++
			p.log().Warn("collect", "err", errCode(err), "fails", fails)
			if !sleep(ctx, min(time.Second<<min(fails, 4), 15*time.Second)) {
				break
			}
			continue
		}
		fails = 0
	}
	return ctx.Err()
}

func errCode(err error) string {
	var e *relayclient.Error
	if errors.As(err, &e) {
		return fmt.Sprintf("relay %d %s", e.Status, e.Code)
	}
	if errors.Is(err, ErrConflict) {
		return "store_conflict"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	return "error"
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *Peer) tickLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.Tick(ctx); err != nil {
				p.log().Warn("housekeeping", "err", errCode(err))
			}
		}
	}
}

// Tick runs the housekeeping: expiries, rekeys, token re-mints and
// refreshes (§6.4, §6.5, §7.2), then the outbox.
func (p *Peer) Tick(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.housekeeping(p.now())
	return p.flushAndDrain(ctx)
}

func (p *Peer) flushAndDrain(ctx context.Context) error {
	if err := p.flush(ctx); err != nil {
		return err
	}
	p.drainOutbox(ctx)
	err := p.flush(ctx)
	p.kickEvents()
	return err
}

// MaxBatch is the most messages collected at once (§8.3).
const MaxBatch = 32

// Step collects one batch (waiting up to wait) and processes it: each
// message is handled and its changes written before it is acked (§8.3);
// the outbox is drained after the batch. It returns the number of
// messages collected.
func (p *Peer) Step(ctx context.Context, wait time.Duration) (int, error) {
	msgs, err := p.cfg.Relay.Collect(ctx, wait, MaxBatch)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(msgs) == 0 {
		if len(p.outbox) == 0 {
			return 0, nil
		}
		return 0, p.flushAndDrain(ctx) // retries that came due
	}
	now := p.now()
	p.housekeeping(now)
	var acks []string
	for _, m := range msgs {
		d, err := p.handleMessage(ctx, m, now)
		if err != nil {
			p.discard()
			return 0, err
		}
		if d == ackAfterFlush {
			p.mark(kindMsg, m.MsgID, []byte{1}, now.Add(DedupeRetention))
		}
		if err := p.flush(ctx); err != nil {
			return 0, err
		}
		if d != noAck {
			acks = append(acks, m.MsgID)
		}
	}
	for _, id := range acks {
		_ = p.cfg.Relay.Ack(ctx, id) // a lost ack means a redelivery, which dedupe absorbs
	}
	p.drainOutbox(ctx)
	err = p.flush(ctx)
	p.kickEvents()
	return len(msgs), err
}

// discard forgets unflushed changes after a store error; the process
// restarts from the stored state.
func (p *Peer) discard() {
	clear(p.dirty)
	p.extra = p.extra[:0]
}

type disposition int

const (
	ackAfterFlush disposition = iota
	ackSeen                   // a msg_id seen before: acked again, nothing else
	noAck                     // left for redelivery (an epoch not yet established, §6.3)
)

// handleMessage classifies one message only by its collect sender, its
// collect jti, its recipient_kid and the session that decrypts it (§13.6),
// as the member vault does.
func (p *Peer) handleMessage(ctx context.Context, m relayclient.Message, now time.Time) (disposition, error) {
	_, seen, err := p.cfg.Store.Get(ctx, kindMsg, m.MsgID)
	if err != nil {
		return 0, err
	}
	if seen {
		return ackSeen, nil // §8.2 layer 1
	}
	sender, ok := relayauth.DecodeKey(m.Sender)
	if !ok {
		p.audit("bad_sender", "")
		return ackAfterFlush, nil
	}
	env, err := envelope.Parse(m.Payload)
	if err != nil {
		p.audit("bad_envelope", "")
		return ackAfterFlush, nil
	}
	c := p.connByRelayKey(sender, now)
	// §7.1 (0.10.3): a request token covers only the rest of a handshake
	// awaiting approval and connection.approved / declined.
	if t := p.issued[m.JTI]; m.JTI != "" && t != nil && t.Kind == tokRequest {
		return p.handleOnRequestToken(env, m.Payload, sender, c, now), nil
	}
	// §6.6: a connection's deposit on its reconnect token (or without a
	// jti) may only be a sealed hs.init with purpose reconnect.
	if c != nil && p.reconnectClass(m.JTI) {
		if env.Mode() != envelope.ModeSealed || !env.RecipientKid().Equal(p.cfg.Keys.KEM.Public().Kid()) {
			p.audit("reconnect_token_misuse", c.ID)
			return ackAfterFlush, nil
		}
		return p.handleInit(m.Payload, sender, c, true, now), nil
	}
	if env.Mode() == envelope.ModeSealed {
		return p.handleSealed(env, m.Payload, sender, c, now), nil
	}
	if c != nil && c.kr != nil {
		in, ep, err := c.kr.Open(env, now)
		if err == nil {
			return p.dispatch(ctx, c, in, ep, m.Payload, sender, now)
		}
		if !errors.Is(err, envelope.ErrKid) {
			p.audit("decrypt_failed", c.ID)
			return ackAfterFlush, nil
		}
	}
	// Not an active epoch: hs.fin for a handshake awaiting it, or a
	// message under a request's epoch before activation (0.10.3).
	if id := p.awaitingByKids(env, sender); id != "" {
		return p.handleFin(id, m.Payload, sender, now), nil
	}
	if id := p.requestByKids(env, sender); id != "" {
		return p.handleRequestMessage(id, env, now), nil
	}
	p.audit("unknown_kid", connID(c))
	return ackAfterFlush, nil
}

func connID(c *Connection) string {
	if c == nil {
		return ""
	}
	return c.ID
}

func (p *Peer) handleSealed(env *envelope.Envelope, raw []byte, sender ed25519.PublicKey, c *Connection, now time.Time) disposition {
	rk := env.RecipientKid()
	if rk.Equal(p.cfg.Keys.KEM.Public().Kid()) {
		return p.handleInit(raw, sender, c, false, now)
	}
	for id, og := range p.outgoing {
		if kidEqual(og.EphKid, rk) {
			return p.handleResp(id, raw, sender, now)
		}
	}
	p.audit("unknown_kid", connID(c))
	return ackAfterFlush
}

func kidEqual(b []byte, k suite.Kid) bool {
	var x suite.Kid
	if len(b) != len(x) {
		return false
	}
	copy(x[:], b)
	return x.Equal(k)
}

// connByRelayKey finds a connection by its member's relay key, or the
// previous one within PrevRelayGrace (rotation.go).
func (p *Peer) connByRelayKey(pk ed25519.PublicKey, now time.Time) *Connection {
	for _, c := range p.conns {
		if suite.EqualPublic(c.Peer.Relay.PK, pk) {
			return c
		}
	}
	for _, c := range p.conns {
		if c.relayKeyIs(pk, now) {
			return c
		}
	}
	return nil
}

// reconnectClass reports whether a deposit was made on a reconnect token
// we issued, by its collect jti (§6.6); a message without a jti counts as
// one.
func (p *Peer) reconnectClass(jti string) bool {
	if jti == "" {
		return true
	}
	t := p.issued[jti]
	return t != nil && t.Kind == tokReconnect
}

// rateWindow counts durable messages per connection per minute (§7.3).
type rateWindow struct {
	start time.Time
	n     int
}

// PeerRateLimit is the durable-message limit per connection per minute
// (§7.3).
const PeerRateLimit = 60

func (p *Peer) rateAllow(id string, now time.Time) bool {
	w := p.rates[id]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &rateWindow{start: now}
		p.rates[id] = w
	}
	w.n++
	return w.n <= PeerRateLimit
}
