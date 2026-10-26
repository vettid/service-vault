package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// Record kinds in the Store.
const (
	kindConn     = "conn"     // an active (or stale) connection
	kindInvite   = "invite"   // an invitation and what became of it
	kindAwait    = "await"    // a handshake we answered, awaiting hs.fin
	kindRequest  = "request"  // a connection after hs.fin, before activation
	kindOutgoing = "outgoing" // a rekey we started, awaiting hs.resp
	kindToken    = "token"    // a token we issued, by jti (§6.6, §7.1)
	kindOutbox   = "outbox"   // a relay operation to perform
	kindAuth     = "auth"     // a connauth challenge we sent (§10.4)
	kindEvent    = "event"    // an event for the application
	kindMsg      = "msg"      // relay msg_id dedupe (§8.2 layer 1)
	kindInner    = "inner"    // inner id dedupe, per connection (§8.2 layer 2)
	kindResp     = "resp"     // cached responses (§8.2)
)

// Retention (VAULT-MESSAGING §8.2, §6.4).
const (
	DedupeRetention   = 16 * 24 * time.Hour
	ResponseRetention = 24 * time.Hour
	// InviteRetention keeps an invitation's outcome readable this long
	// after it ends (chosen; not in the spec).
	InviteRetention = 24 * time.Hour
)

// Connection states.
const (
	StateActive = "active"
	StateStale  = "stale" // the relay refused its token or mailbox (§8.6)
)

// RelayRef is a principal's relay address as stored.
type RelayRef struct {
	URL     string            `json:"url"`
	Mailbox string            `json:"mailbox"`
	PK      ed25519.PublicKey `json:"pk"`
}

// HeldToken is a token a peer issued to us.
type HeldToken struct {
	Token string    `json:"token,omitempty"`
	Exp   time.Time `json:"exp,omitzero"`
}

// peerInfo is who the other side of a handshake is.
type peerInfo struct {
	IK        ed25519.PublicKey `json:"ik"`
	KEM       []byte            `json:"kem"`
	Relay     RelayRef          `json:"relay"`
	FirstName string            `json:"first_name,omitempty"`
	LastName  string            `json:"last_name,omitempty"`
}

// Connection is an active connection with a member's vault.
type Connection struct {
	ID       string   `json:"id"`
	State    string   `json:"state"`
	Peer     peerInfo `json:"peer"`
	Suite    uint8    `json:"suite"`
	InviteID string   `json:"invite_id,omitempty"`
	Tag      string   `json:"tag,omitempty"` // the application's tag of the invitation

	// ProfileVersion is the last profile.update version kept (§10.8).
	ProfileVersion uint64 `json:"profile_version,omitempty"`

	Standing  HeldToken `json:"standing"`
	Reconnect HeldToken `json:"reconnect"`

	Keyring     handshake.KeyringState `json:"keyring"`
	LastEpochID []byte                 `json:"last_epoch_id,omitempty"`

	Created   time.Time `json:"created"`
	Activated time.Time `json:"activated"`

	// The member's credential key pinned at the first signed
	// connection.authenticate.response (§10.4).
	AuthKey []byte    `json:"auth_key,omitempty"`
	AuthAt  time.Time `json:"auth_at,omitzero"`

	// relay.token.refresh bounds (§7.2): when this peer last got a fresh
	// token near its token's end, and after quota_exceeded.
	Renewed   time.Time `json:"renewed,omitzero"`
	Refreshed time.Time `json:"refreshed,omitzero"`
	// RefreshID is the inner id of our relay.token.refresh awaiting its
	// answer; RefreshAfter defers the next one (a too_soon answer).
	RefreshID    string    `json:"refresh_id,omitempty"`
	RefreshAfter time.Time `json:"refresh_after,omitzero"`

	kr *handshake.Keyring
}

// Name is the member's account name from the shared profile (§10.8).
func (c *Connection) Name() string { return joinName(c.Peer.FirstName, c.Peer.LastName) }

func joinName(first, last string) string {
	switch {
	case first == "":
		return last
	case last == "":
		return first
	}
	return first + " " + last
}

// Invitation statuses, as the application sees them.
const (
	InviteWaiting   = "waiting"   // not accepted yet, or the handshake runs
	InviteSAS       = "sas"       // hs.fin checked out: the SAS is known
	InviteConnected = "connected" // the member approved: the connection is active
	InviteDeclined  = "declined"  // the member declined
	InviteExpired   = "expired"   // nobody accepted it, or the request ended unapproved
)

// InviteRecord is an invitation the service made and what became of it.
type InviteRecord struct {
	ID       string    `json:"id"`
	OpenJTI  string    `json:"open_jti"`
	ClaimID  string    `json:"claim_id"`
	Exp      time.Time `json:"exp"`
	URL      string    `json:"url"`
	Link     string    `json:"link"`
	Tag      string    `json:"tag,omitempty"`
	Used     bool      `json:"used,omitempty"`
	Status   string    `json:"status"`
	SAS      string    `json:"sas,omitempty"`
	ConnID   string    `json:"connection_id,omitempty"`
	Ended    time.Time `json:"ended,omitzero"`
	Withdrew bool      `json:"withdrew,omitempty"` // the open jti and claim were revoked
}

// awaiting is a handshake we answered with hs.resp, awaiting hs.fin.
type awaiting struct {
	ID       string                   `json:"id"`
	ConnID   string                   `json:"conn_id"` // the connection it is for (new or existing)
	New      *peerInfo                `json:"new,omitempty"`
	Purpose  handshake.Purpose        `json:"purpose"`
	InviteID string                   `json:"invite_id,omitempty"`
	Held     HeldToken                `json:"held"` // the peer's token from hs.init
	Resp     handshake.ResponderState `json:"resp"`
	Created  time.Time                `json:"created"`
	Expires  time.Time                `json:"expires"`

	r *handshake.Responder
}

// request is a first-contact connection after hs.fin, before activation
// (§6.4, 0.10.3).
type request struct {
	ID           string               `json:"id"` // the connection's id
	InviteID     string               `json:"invite_id"`
	Peer         peerInfo             `json:"peer"`
	SAS          string               `json:"sas"`
	Epoch        handshake.EpochState `json:"epoch"`
	Approved     bool                 `json:"approved"`
	PeerApproved bool                 `json:"peer_approved"`
	HeldRequest  HeldToken            `json:"held_request"`
	Standing     HeldToken            `json:"standing"`
	Reconnect    HeldToken            `json:"reconnect"`
	Created      time.Time            `json:"created"`
	Expires      time.Time            `json:"expires"`

	ep *handshake.Epoch
}

// outgoing is a rekey we initiated, awaiting hs.resp (§6.5).
type outgoing struct {
	ID      string                   `json:"id"`
	ConnID  string                   `json:"conn_id"`
	EphKid  []byte                   `json:"eph_kid"`
	Th1     []byte                   `json:"th1"`
	Init    handshake.InitiatorState `json:"init"`
	Created time.Time                `json:"created"`

	ini *handshake.Initiator
}

// Token kinds we issue (§7.1).
const (
	tokStanding  = "standing"
	tokReconnect = "reconnect"
	tokRequest   = "request"
	tokOpen      = "open"
)

// IssuedToken is a token the service issued, recorded by jti (§6.6).
type IssuedToken struct {
	JTI    string    `json:"jti"`
	Kind   string    `json:"kind"`
	Sub    string    `json:"sub"`
	ConnID string    `json:"conn_id,omitempty"`
	Exp    time.Time `json:"exp"`
	Denied bool      `json:"denied,omitempty"`
}

// Outbox operations.
const (
	opDeposit     = "deposit"
	opRevoke      = "revoke"
	opDeleteClaim = "delete_claim"
)

// outboxEntry is one relay operation, performed after the flush that
// queued it (§8.3 step 5).
type outboxEntry struct {
	ID         string    `json:"id"`
	Seq        uint64    `json:"seq"` // entries run in queue order
	Op         string    `json:"op"`
	ConnID     string    `json:"conn_id,omitempty"`
	Mailbox    string    `json:"mailbox,omitempty"`
	Token      string    `json:"token,omitempty"` // "" for a deposit: the connection's standing token
	Payload    []byte    `json:"payload,omitempty"`
	Value      string    `json:"value,omitempty"` // revoke: the jti; delete_claim: the claim id
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	Attempts   int       `json:"attempts,omitempty"`
	AwaitToken bool      `json:"await_token,omitempty"`
	BestEffort bool      `json:"best_effort,omitempty"`
}

// challenge is a connection.authenticate.challenge we sent (§10.4).
type challenge struct {
	ID      string    `json:"id"`
	ConnID  string    `json:"conn_id"`
	Nonce   []byte    `json:"nonce"`
	Context string    `json:"context,omitempty"`
	Exp     time.Time `json:"exp"`
}

type cachedResponse struct {
	Inner []byte `json:"inner"`
}

// key names one record.
type key struct{ kind, id string }

// markDirty records that a record changed and must be written (or
// deleted, if it no longer exists in memory) at the next flush.
func (p *Peer) markDirty(kind, id string) { p.dirty[key{kind, id}] = struct{}{} }

// mark adds a write-once record (a dedupe marker, a cached response).
func (p *Peer) mark(kind, id string, data []byte, exp time.Time) {
	p.extra = append(p.extra, Change{Kind: kind, ID: id, Data: data, Expires: exp, IfAbsent: true})
}

// recordData returns the current encoding of a record, or nil when it
// no longer exists, with its expiry.
func (p *Peer) recordData(k key) ([]byte, time.Time, error) {
	var v any
	var exp time.Time
	switch k.kind {
	case kindConn:
		c := p.conns[k.id]
		if c == nil {
			return nil, exp, nil
		}
		if c.kr != nil {
			c.Keyring = c.kr.Export()
		}
		v = c
	case kindInvite:
		inv := p.invites[k.id]
		if inv == nil {
			return nil, exp, nil
		}
		v, exp = inv, inviteExpiry(inv)
	case kindAwait:
		aw := p.awaiting[k.id]
		if aw == nil {
			return nil, exp, nil
		}
		if aw.r != nil {
			s, err := aw.r.Export()
			if err != nil {
				return nil, exp, err
			}
			aw.Resp = s
		}
		v = aw
	case kindRequest:
		r := p.requests[k.id]
		if r == nil {
			return nil, exp, nil
		}
		if r.ep != nil {
			r.Epoch = r.ep.Export()
		}
		v = r
	case kindOutgoing:
		og := p.outgoing[k.id]
		if og == nil {
			return nil, exp, nil
		}
		v = og
	case kindToken:
		t := p.issued[k.id]
		if t == nil {
			return nil, exp, nil
		}
		v, exp = t, t.Exp.Add(tokenRetention+storeMargin)
	case kindOutbox:
		e := p.outboxByID(k.id)
		if e == nil {
			return nil, exp, nil
		}
		v = e
	case kindAuth:
		c := p.challenges[k.id]
		if c == nil {
			return nil, exp, nil
		}
		v = c
	case kindEvent:
		e := p.eventByID(k.id)
		if e == nil {
			return nil, exp, nil
		}
		v = e
	default:
		return nil, exp, fmt.Errorf("peer: unknown record kind %q", k.kind)
	}
	b, err := json.Marshal(v)
	return b, exp, err
}

func inviteExpiry(inv *InviteRecord) time.Time {
	if !inv.Ended.IsZero() {
		return inv.Ended.Add(InviteRetention + storeMargin)
	}
	return time.Time{}
}

// storeMargin is how long the store keeps a record past the time the
// peer deletes it, so that a delete never finds it expired.
const storeMargin = 7 * 24 * time.Hour

// tokenRetention is how long the registry keeps a token past its expiry.
const tokenRetention = 30 * 24 * time.Hour

// flush writes every changed record (§8.3 step 3). Each record is
// written on the version it was read at, so that a second writer on the
// same table is detected rather than overwritten.
func (p *Peer) flush(ctx context.Context) error {
	if len(p.dirty) == 0 && len(p.extra) == 0 {
		return nil
	}
	keys := make([]key, 0, len(p.dirty))
	for k := range p.dirty {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].id < keys[j].id
	})
	changes := make([]Change, 0, len(keys)+len(p.extra))
	for _, k := range keys {
		data, exp, err := p.recordData(k)
		if err != nil {
			return err
		}
		v := p.versions[k]
		if data == nil && v == 0 {
			continue // created and deleted before any flush
		}
		c := Change{Kind: k.kind, ID: k.id, Data: data, Expires: exp, IfVersion: v, IfAbsent: v == 0}
		changes = append(changes, c)
	}
	changes = append(changes, p.extra...)
	if err := p.cfg.Store.Apply(ctx, changes); err != nil {
		return fmt.Errorf("peer: flush: %w", err)
	}
	for _, c := range changes {
		k := key{c.Kind, c.ID}
		if _, tracked := p.dirty[k]; !tracked {
			continue
		}
		if c.Data == nil {
			delete(p.versions, k)
		} else {
			p.versions[k]++
		}
	}
	clear(p.dirty)
	p.extra = p.extra[:0]
	return nil
}

// load reads every record into memory at start.
func (p *Peer) load(ctx context.Context) error {
	type target struct {
		kind string
		put  func([]byte) (string, error)
	}
	ts := []target{
		{kindConn, func(b []byte) (string, error) {
			c := &Connection{}
			if err := json.Unmarshal(b, c); err != nil {
				return "", err
			}
			kr, err := handshake.ImportKeyring(c.Keyring)
			if err != nil {
				return "", err
			}
			c.kr = kr
			p.conns[c.ID] = c
			return c.ID, nil
		}},
		{kindInvite, func(b []byte) (string, error) {
			inv := &InviteRecord{}
			if err := json.Unmarshal(b, inv); err != nil {
				return "", err
			}
			p.invites[inv.ID] = inv
			return inv.ID, nil
		}},
		{kindAwait, func(b []byte) (string, error) {
			aw := &awaiting{}
			if err := json.Unmarshal(b, aw); err != nil {
				return "", err
			}
			r, err := handshake.RestoreResponder(aw.Resp)
			if err != nil {
				return "", err
			}
			aw.r = r
			p.awaiting[aw.ID] = aw
			return aw.ID, nil
		}},
		{kindRequest, func(b []byte) (string, error) {
			r := &request{}
			if err := json.Unmarshal(b, r); err != nil {
				return "", err
			}
			ep, err := handshake.ImportEpoch(r.Epoch)
			if err != nil {
				return "", err
			}
			r.ep = ep
			p.requests[r.ID] = r
			return r.ID, nil
		}},
		{kindOutgoing, func(b []byte) (string, error) {
			og := &outgoing{}
			if err := json.Unmarshal(b, og); err != nil {
				return "", err
			}
			ini, err := handshake.RestoreInitiator(og.Init, p.cfg.Keys.IK)
			if err != nil {
				return "", err
			}
			og.ini = ini
			p.outgoing[og.ID] = og
			return og.ID, nil
		}},
		{kindToken, func(b []byte) (string, error) {
			t := &IssuedToken{}
			if err := json.Unmarshal(b, t); err != nil {
				return "", err
			}
			p.issued[t.JTI] = t
			return t.JTI, nil
		}},
		{kindOutbox, func(b []byte) (string, error) {
			e := &outboxEntry{}
			if err := json.Unmarshal(b, e); err != nil {
				return "", err
			}
			p.outbox = append(p.outbox, e)
			return e.ID, nil
		}},
		{kindAuth, func(b []byte) (string, error) {
			c := &challenge{}
			if err := json.Unmarshal(b, c); err != nil {
				return "", err
			}
			p.challenges[c.ID] = c
			return c.ID, nil
		}},
		{kindEvent, func(b []byte) (string, error) {
			e := &Event{}
			if err := json.Unmarshal(b, e); err != nil {
				return "", err
			}
			p.events = append(p.events, e)
			return e.ID, nil
		}},
	}
	for _, t := range ts {
		recs, err := p.cfg.Store.Load(ctx, t.kind)
		if err != nil {
			return fmt.Errorf("peer: load %s: %w", t.kind, err)
		}
		for _, r := range recs {
			id, err := t.put(r.Data)
			if err != nil {
				return fmt.Errorf("peer: load %s %s: %w", t.kind, r.ID, err)
			}
			p.versions[key{t.kind, id}] = r.Version
		}
	}
	sort.Slice(p.outbox, func(i, j int) bool { return p.outbox[i].Seq < p.outbox[j].Seq })
	sort.Slice(p.events, func(i, j int) bool { return p.events[i].Seq < p.events[j].Seq })
	for _, e := range p.outbox {
		p.seq = max(p.seq, e.Seq)
	}
	for _, e := range p.events {
		p.seq = max(p.seq, e.Seq)
	}
	return nil
}
