package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Record kinds in the Store.
const (
	kindConn     = "conn"     // an active (or stale) connection
	kindInvite   = "invite"   // an invitation and what became of it
	kindAwait    = "await"    // a handshake we answered, awaiting hs.fin
	kindRequest  = "request"  // a connection after hs.fin, before activation
	kindOutgoing = "outgoing" // a rekey or reconnect we started, awaiting hs.resp
	kindToken    = "token"    // a token we issued, by jti (§6.6, §7.1)
	kindOutbox   = "outbox"   // a relay operation to perform
	kindAuth     = "auth"     // a connauth challenge we sent (§10.4)
	kindEvent    = "event"    // an event for the application
	kindMsg      = "msg"      // relay msg_id dedupe (§8.2 layer 1)
	kindInner    = "inner"    // inner id dedupe, per connection (§8.2 layer 2)
	kindResp     = "resp"     // cached responses (§8.2)
	kindLease    = "lease"    // the latest collect that leased messages, by process (Caught)
	kindUnacked  = "unacked"  // a message left unacked, by msg_id: its times only (Caught)
	kindOnce     = "once"     // a one-shot operator action that ran (EndAllConnections)
)

// Kinds lists every record kind the peer stores, for a migration that
// must touch them all (internal/sealstore).
func Kinds() []string {
	return []string{kindConn, kindInvite, kindAwait, kindRequest, kindOutgoing, kindToken, kindOutbox, kindAuth, kindEvent,
		kindMsg, kindInner, kindResp, kindLease, kindUnacked, kindOnce}
}

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
	// StateSuspended (rotation.go): a rotation conflict.
)

// RelayRef is a principal's relay address as stored.
type RelayRef struct {
	URL     string            `json:"url"`
	Mailbox string            `json:"mailbox"`
	PK      ed25519.PublicKey `json:"pk"`
}

// HeldToken is a token a peer issued to us.
type HeldToken struct {
	// JTI is the token's jti, kept to refuse it if offered again after the
	// relay revoked it (RevokedHeld); empty on older records.
	JTI   string    `json:"jti,omitempty"`
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
	// Features are the optional features the member's vault advertised in
	// that profile.update (§10.8, 0.81.0), such as "vote".
	Features []string `json:"features,omitempty"`
	// PeerContract is the contract the member's vault last claimed: the
	// `contract` of the last profile.update kept, "" when it had none or
	// one of another form (§10.8, 0.90.10). Informational only; it may be
	// stale after the vault's rollback.
	PeerContract string `json:"peer_contract,omitempty"`
	// SentProfileVersion and SentContract are the version and the contract
	// of the last profile.update the service queued to the member (§10.8
	// "Sending"); zero on records from before contract, which were sent
	// version 1 at activation.
	SentProfileVersion uint64 `json:"sent_profile_version,omitempty"`
	SentContract       string `json:"sent_contract,omitempty"`

	Standing  HeldToken `json:"standing"`
	Reconnect HeldToken `json:"reconnect"`

	Keyring     handshake.KeyringState `json:"keyring"`
	LastEpochID []byte                 `json:"last_epoch_id,omitempty"`
	// Reconnecting is set while a reconnect we started is open, from its
	// first hs.init until its epoch is confirmed or it ends: nothing but
	// the handshake is sent (RELEASE-29 §3). ReconnectTries counts the
	// tries (each spends one of the member's reconnect token's 4
	// deposits).
	Reconnecting   bool `json:"reconnecting,omitempty"`
	ReconnectTries int  `json:"reconnect_tries,omitempty"`
	// ReconnectTriesFor is the epoch ReconnectTries counts tries for: a
	// reconnect naming another epoch starts its count afresh (§3.4.1 "The
	// reconnect bound": the third failed try for one named epoch).
	ReconnectTriesFor []byte `json:"reconnect_tries_for,omitempty"`
	// ReconnectSince is when the reconnect's first try started;
	// ReconnectSlow is set once the reconnect_slow alarm was raised.
	ReconnectSince time.Time `json:"reconnect_since,omitzero"`
	ReconnectSlow  bool      `json:"reconnect_slow,omitempty"`
	// ReconnectRestore marks a restore's reconnect: each try waits
	// ReconnectTimeout for its hs.resp instead of HandshakeTTL
	// (RELEASE-29 §4).
	ReconnectRestore bool `json:"reconnect_restore,omitempty"`
	// ReconnectRestartIK is the member's ik a restarted reconnect last
	// spent a deposit for (§3.4.1 H5: at most once per change).
	ReconnectRestartIK ed25519.PublicKey `json:"reconnect_restart_ik,omitempty"`
	// Pending is the service's own rekey or reconnect epoch awaiting
	// confirmation (§6.3.1 Initiator; initiator.go).
	Pending *PendingEpoch `json:"pending,omitempty"`
	// Abandoned are the ids of pending epochs of ours abandoned since the
	// last confirmation: a member's reconnect may name one (§6.6).
	Abandoned [][]byte `json:"abandoned,omitempty"`
	// AbandonedMeta records every pending epoch of ours abandoned, while
	// its receive keys are kept (16 days): what §3.4.1 judges a message
	// under it by (K2, K9).
	AbandonedMeta []AbandonedEpoch `json:"abandoned_meta,omitempty"`
	// ReconnectNamed is the epoch the open reconnect of ours names when it
	// is not the current one (strict F1's E, R29-K7); see reconnectTarget.
	ReconnectNamed []byte `json:"reconnect_named,omitempty"`
	// Carried are the tokens a member's reconnect carried, kept with the
	// epoch it established until the confirmed epoch reaches it
	// (carried.go).
	Carried []CarriedTokens `json:"carried,omitempty"`
	// RekeyFailures counts the rekeys of ours that ended without an
	// epoch since the last epoch installed; none starts before
	// RekeyNotBefore (rekeyFailed).
	RekeyFailures  int       `json:"rekey_failures,omitempty"`
	RekeyNotBefore time.Time `json:"rekey_not_before,omitzero"`
	// Epochs are the connection's epochs in the order they became
	// current, pruned; Confirmed is the confirmed epoch, and ConfirmAt
	// when the last hs.confirm was queued (§6.3.1 Responder; confirm.go).
	Epochs    []EpochMeta `json:"epochs,omitempty"`
	Confirmed []byte      `json:"confirmed,omitempty"`
	// MessagingRelease is the marker every connection record is written
	// with (RELEASE-29 §11): a record without it, or with a value below
	// MessagingRelease, is ended at the next start (endPre29).
	MessagingRelease int       `json:"messaging_release,omitempty"`
	ConfirmAt        time.Time `json:"confirm_at,omitzero"`

	Created   time.Time `json:"created"`
	Activated time.Time `json:"activated"`

	// Chain is the member's identity.rotate links followed (§3.4), for
	// "one successor per key"; every link is kept.
	Chain []json.RawMessage `json:"chain,omitempty"`
	// Seen are the member's valid identity links that passed rule C but
	// were not followed (one in an identity.rotate then refused, in a
	// handshake that did not complete; a rekey's only once it passed
	// rekeyPrecheck): at most one per old key, only from the current key,
	// an ancestor or a key a seen link reaches, and at most MaxSeen
	// (§3.4.1 rule C, R29-K8). A later different successor of that key is
	// a second successor.
	Seen []json.RawMessage `json:"seen_links,omitempty"`
	// RevokedHeld are the jtis of tokens we held that the relay answered
	// token_revoked, each kept until its exp: one offered again is refused
	// (as vettid-vault #244).
	RevokedHeld []RevokedJTI `json:"revoked_held,omitempty"`
	// LegacyPrevRelayPK is read only to find a connection a
	// relay.address.update moved before the update was refused: no honest
	// member sent one, so such a connection is marked stale at load
	// (legacyRelayMove).
	LegacyPrevRelayPK ed25519.PublicKey `json:"prev_relay_pk,omitempty"`

	// The member's credential key pinned at the first signed
	// connection.authenticate.response (§10.4).
	AuthKey []byte    `json:"auth_key,omitempty"`
	AuthAt  time.Time `json:"auth_at,omitzero"`
	// GovKey is the credential key an admin's governance approvals must be
	// signed with. AuthKey moves with every signed sign-in; GovKey follows
	// only a verified rotation chain, and otherwise moves only by PinGov (the
	// connection becomes an admin) and RepinGov (the other admins approved
	// admin.repin). Empty: not pinned, no governance approval counts.
	GovKey []byte `json:"gov_key,omitempty"`
	// AuthKeyChangedAt is when AuthKey last moved to a key that no rotation
	// chain reached (the first sign-in with the new key); zero if never.
	AuthKeyChangedAt time.Time `json:"auth_key_changed_at,omitzero"`

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
	ID string `json:"id"`
	// MessagingRelease: the marker (RELEASE-29 §11), as on a connection: a
	// first contact's awaiting without it is ended at start.
	MessagingRelease int               `json:"messaging_release,omitempty"`
	ConnID           string            `json:"conn_id"` // the connection it is for (new or existing)
	New              *peerInfo         `json:"new,omitempty"`
	Purpose          handshake.Purpose `json:"purpose"`
	InviteID         string            `json:"invite_id,omitempty"`
	Held             HeldToken         `json:"held"` // the peer's token from hs.init
	// Th1 identifies the hs.init answered, so that a copy of it (an
	// outbox retry re-deposits the same bytes) is not answered twice.
	Th1     []byte                   `json:"th1,omitempty"`
	Resp    handshake.ResponderState `json:"resp"`
	Created time.Time                `json:"created"`
	Expires time.Time                `json:"expires"`
	// A member's reconnect changes nothing until sig_I verifies at hs.fin
	// (VAULT-MESSAGING §6.6, 0.72.0): what it brings waits here.
	Reconnect *pendingReconnect `json:"reconnect,omitempty"`
	// Follow is what a member's rekey named (S8): its signer and links,
	// checked again and followed at its hs.fin (checkSigner).
	Follow *pendingFollow `json:"follow,omitempty"`
	// RespEntry is the outbox entry of a rekey answer's hs.resp, dropped
	// with the answer if not yet deposited.
	RespEntry string `json:"resp_entry,omitempty"`
	// NamedConf: its hs.init named the confirmed epoch while not current
	// (rule E at hs.fin); ForkEp: it named an older epoch that is fork
	// evidence (suspend at hs.fin); InitTS: the hs.init's inner ts.
	NamedConf bool      `json:"named_conf,omitempty"`
	ForkEp    bool      `json:"fork_ep,omitempty"`
	InitTS    time.Time `json:"init_ts,omitzero"`
	// InitEpoch is the epoch a rekey's hs.init traveled under: strict F1's
	// E for the links applied at its hs.fin (VAULT-MESSAGING 0.90.4). An
	// answer recorded before change 4b has none and runs no strict F1.
	InitEpoch []byte `json:"init_epoch,omitempty"`

	r *handshake.Responder
}

// pendingReconnect is what a member's reconnect hs.init carried, applied
// at its hs.fin: the tokens it issued us, the rotation links we had not
// followed (with the key and KEM they lead to), and the jtis of the
// tokens our hs.resp carried (revoked if it never completes).
type pendingReconnect struct {
	Standing  HeldToken         `json:"standing"`
	Reconnect HeldToken         `json:"reconnect"`
	IK        ed25519.PublicKey `json:"ik,omitempty"`
	KEM       []byte            `json:"kem,omitempty"`
	Links     []json.RawMessage `json:"links,omitempty"`
	Issued    []string          `json:"issued,omitempty"`
	// Signer is the hs.init's signer and whole chain, checked again at
	// hs.fin (checkSigner); IK, KEM and Links are kept for a record from
	// before it.
	Signer *pendingFollow `json:"signer,omitempty"`
	// Named is the epoch its ctx named.
	Named []byte `json:"named,omitempty"`
}

// pendingFollow is what a member's rekey or reconnect hs.init named: the
// key it was signed with (from.ik) and its kem, and every identity link
// it carried, checked again and followed at its hs.fin (checkSigner).
type pendingFollow struct {
	IK    ed25519.PublicKey `json:"ik"`
	KEM   []byte            `json:"kem"`
	Links []json.RawMessage `json:"links"`
}

func (f *pendingFollow) parse() (ed25519.PublicKey, *suite.PublicKey, []*handshake.Rotation, error) {
	kem, err := suite.ParsePublicKey(f.KEM)
	if err != nil {
		return nil, nil, nil, err
	}
	var links []*handshake.Rotation
	for _, raw := range f.Links {
		r, err := handshake.ParseRotation(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		links = append(links, r)
	}
	if len(f.IK) != ed25519.PublicKeySize {
		return nil, nil, nil, errors.New("peer: bad pending follow")
	}
	return f.IK, kem, links, nil
}

// request is a first-contact connection after hs.fin, before activation
// (§6.4, 0.10.3).
type request struct {
	ID string `json:"id"` // the connection's id
	// MessagingRelease: the marker (RELEASE-29 §11), as on a connection: a
	// request without it is ended at start.
	MessagingRelease int                  `json:"messaging_release,omitempty"`
	InviteID         string               `json:"invite_id"`
	Peer             peerInfo             `json:"peer"`
	SAS              string               `json:"sas"`
	Epoch            handshake.EpochState `json:"epoch"`
	Approved         bool                 `json:"approved"`
	PeerApproved     bool                 `json:"peer_approved"`
	HeldRequest      HeldToken            `json:"held_request"`
	Standing         HeldToken            `json:"standing"`
	Reconnect        HeldToken            `json:"reconnect"`
	Created          time.Time            `json:"created"`
	Expires          time.Time            `json:"expires"`

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
	// Issued are the jtis of the tokens a reconnect's hs.init carries,
	// revoked if it is abandoned.
	Issued []string `json:"issued,omitempty"`
	// Named is the epoch a reconnect's ctx names.
	Named []byte `json:"named,omitempty"`
	// InitEntry is the outbox entry of its hs.init, dropped unsent when
	// the handshake is abandoned.
	InitEntry string `json:"init_entry,omitempty"`

	ini *handshake.Initiator
}

// Token kinds we issue (§7.1).
const (
	tokStanding  = "standing"
	tokReconnect = "reconnect"
	tokRequest   = "request"
	tokOpen      = "open"
)

// RevokedJTI is a held token's jti the relay revoked, until its exp.
type RevokedJTI struct {
	JTI string    `json:"jti"`
	Exp time.Time `json:"exp"`
}

// IssuedToken is a token the service issued, recorded by jti (§6.6).
type IssuedToken struct {
	JTI    string    `json:"jti"`
	Kind   string    `json:"kind"`
	Sub    string    `json:"sub"`
	ConnID string    `json:"conn_id,omitempty"`
	Exp    time.Time `json:"exp"`
	Denied bool      `json:"denied,omitempty"`
	// Carried: minted for a reconnect's hs.init or hs.resp, and that
	// reconnect activated (markCarried). Prompt:
	// re-minted at our reconnect's confirmation ("The prompt to adopt").
	// A refresh after quota_exceeded keeps the newest of each (§6.3.1
	// "Revocation by the issuer"; RELEASE-29 §12).
	Carried bool `json:"carried,omitempty"`
	Prompt  bool `json:"prompt,omitempty"`
	// Seq orders tokens by minting (the outbox's sequence): two minted
	// in one millisecond have jtis in no particular order.
	Seq uint64 `json:"seq,omitempty"`
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
	// Confirm marks an hs.confirm (§6.3.1): at most one waits per
	// connection, exempt from MaxOutboxPerConn.
	Confirm bool `json:"confirm,omitempty"`
	// Tried: an attempt to deposit it may have reached the relay (§8.3;
	// RELEASE-29 §13). Every waiting deposit is marked at load.
	Tried bool `json:"tried,omitempty"`
	// Late: the entry was noted as deposited more than RestampAfter after
	// its ts (unconfirmed_late), once.
	Late bool `json:"late,omitempty"`
	// Handshake marks a handshake message (hs.init, hs.resp, hs.fin):
	// never sealed again, exempt from MaxOutboxPerConn, and sent while a
	// reconnect is open.
	Handshake bool `json:"handshake,omitempty"`
	// FinEpoch marks the service's hs.fin for its pending epoch with that
	// epoch's id: dropped unsent when the epoch is abandoned (§6.3.1).
	FinEpoch []byte `json:"fin_epoch,omitempty"`
	// Refresh marks our relay.token.refresh: it passes the deposits that
	// wait for a fresh standing token (§8.4, §8.6).
	Refresh bool `json:"refresh,omitempty"`
	// CarriedTok: Token is a handshake's carried token (an hs.resp or an
	// hs.confirm), whose token_revoked ends that handshake's tokens.
	CarriedTok bool `json:"carried_tok,omitempty"`
	// StaleTS counts the relay's timestamp_stale refusals of it.
	StaleTS int `json:"stale_ts,omitempty"`
	// Vote is a deposit SendMessage queued: only these count toward
	// MaxSendOutbox and MaxSendOutboxBytes.
	Vote bool `json:"vote,omitempty"`

	dropped bool // removed by dropOutbox: a drain in progress skips it
}

// challenge is a connection.authenticate.challenge we sent (§10.4).
type challenge struct {
	ID      string `json:"id"`
	ConnID  string `json:"conn_id"`
	Nonce   []byte `json:"nonce"`
	Context string `json:"context,omitempty"`
	// Purpose is the challenge's purpose (VAULT-MESSAGING 0.65.0 §10.4),
	// or "" for none.
	Purpose string `json:"purpose,omitempty"`
	// MatchCode is a sign-in challenge's match code (VAULT-MESSAGING
	// 0.79.0 §10.4), or "".
	MatchCode string    `json:"match_code,omitempty"`
	Exp       time.Time `json:"exp"`
	// Gone marks a challenge that is over for us (cancelled with its withdraw
	// not queued, or expired) but may still hold a place at the member
	// vault: forgotten for every purpose but that count, until Exp plus
	// ClockSkew.
	Gone bool `json:"gone,omitempty"`
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
	for i := range p.extra {
		if p.extra[i].Kind == kind && p.extra[i].ID == id {
			// One change per item: a message redelivered before a flush
			// must not put its marker in twice (a transaction refuses two
			// operations on one item).
			p.extra[i] = Change{Kind: kind, ID: id, Data: data, Expires: exp, IfAbsent: true}
			return
		}
	}
	p.extra = append(p.extra, Change{Kind: kind, ID: id, Data: data, Expires: exp, IfAbsent: true})
}

// unmark drops a pending marker (one not yet flushed), so a request left
// unanswered is handled again if it is sent again with the same id.
func (p *Peer) unmark(kind, id string) {
	p.extra = slices.DeleteFunc(p.extra, func(c Change) bool { return c.Kind == kind && c.ID == id })
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
		c.MessagingRelease = MessagingRelease // on every connection record written (RELEASE-29 §11)
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
		aw.MessagingRelease = MessagingRelease // RELEASE-29 §11
		v = aw
	case kindRequest:
		r := p.requests[k.id]
		if r == nil {
			return nil, exp, nil
		}
		if r.ep != nil {
			r.Epoch = r.ep.Export()
		}
		r.MessagingRelease = MessagingRelease // RELEASE-29 §11
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
// legacyRelayMove suspends a connection that a relay.address.update moved
// before the update was refused (#152). No honest member ever sent one,
// so the move came from whoever held the session's keys: the stored
// relay address may be that copy's. It is not honored: the connection is
// suspended (nothing is sent or accepted, and no reconnect revives it),
// with an alarm; the member connects again from a new invitation.
func (p *Peer) legacyRelayMove(c *Connection) {
	c.LegacyPrevRelayPK = nil
	p.markDirty(kindConn, c.ID)
	// Suspended, not stale: a stale connection comes back at its next
	// epoch, which whoever holds the moved address could establish.
	p.suspendFor(c, SuspendRelayMoved, p.now())
}

// orphan is a pending epoch whose record and keys were not stored together.
type orphan struct {
	c      *Connection
	id     []byte
	issued []string
	why    string // "ik": made under another identity key; "load": stored incompletely
}

func (p *Peer) load(ctx context.Context) error {
	var stale []*outgoing
	var orphans []orphan
	var moved []*Connection
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
			c.initEpochs()
			if len(c.LegacyPrevRelayPK) > 0 {
				moved = append(moved, c)
			}
			// The pending epoch's record and its keys are written together;
			// one without the other is abandoned, after the load
			// (orphanPending), with its hs.fin and tokens.
			if c.Pending != nil && len(c.Pending.OwnIK) > 0 && !bytes.Equal(c.Pending.OwnIK, p.cfg.Keys.IKPublic()) {
				// Made under another identity key than the service's: never
				// confirmable (R29-I7, RELEASE-29 §1).
				p.log().Error("a stored pending epoch names another identity key than this service's: abandoned; check the service's keys and secrets",
					"alarm", "outgoing_identity_changed", "connection_id", c.ID)
				orphans = append(orphans, orphan{c, c.Pending.ID, c.Pending.Issued, "ik"})
				c.Pending = nil
				kr.AbandonPending(p.now())
			} else if c.Pending != nil && kr.Pending() == nil {
				orphans = append(orphans, orphan{c, c.Pending.ID, c.Pending.Issued, "load"})
				c.Pending = nil
			} else if c.Pending == nil && kr.Pending() != nil {
				id := kr.Pending().ID()
				orphans = append(orphans, orphan{c, bytes.Clone(id[:]), nil, "load"})
				kr.AbandonPending(p.now())
			}
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
			if errors.Is(err, handshake.ErrIdentity) {
				// Its hs.init names another identity key than this
				// service's: it can never finish. Dropped after the load
				// (dropStale), not a reason to refuse to start.
				stale = append(stale, og)
				return og.ID, nil
			}
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
	for _, e := range p.outbox {
		// A service has no clean end (§8.3 "A clean end"): a write that
		// would have stored the mark after an accepted deposit may be lost.
		if e.Op == opDeposit {
			e.Tried = true
		}
	}
	sort.Slice(p.events, func(i, j int) bool { return p.events[i].Seq < p.events[j].Seq })
	for _, e := range p.outbox {
		p.seq = max(p.seq, e.Seq)
	}
	for _, e := range p.events {
		p.seq = max(p.seq, e.Seq)
	}
	for _, t := range p.issued {
		p.seq = max(p.seq, t.Seq)
	}
	p.dropStale(stale)
	// RELEASE-29 §11, before anything else uses the connections: records
	// from before release 29's rules were complete are ended.
	if err := p.endPre29(ctx, p.now()); err != nil {
		return err
	}
	for _, c := range moved {
		if p.conns[c.ID] != c {
			continue // ended above
		}
		p.legacyRelayMove(c)
	}
	for _, o := range orphans {
		if p.conns[o.c.ID] != o.c {
			continue // ended above
		}
		p.dropOutbox(func(e *outboxEntry) bool { return e.ConnID == o.c.ID && bytes.Equal(e.FinEpoch, o.id) })
		for _, j := range o.issued {
			p.denyJTI(j, p.now())
		}
		p.markDirty(kindConn, o.c.ID)
		p.audit("pending_abandoned_"+o.why, o.c.ID)
		if o.why == "load" {
			p.log().Warn("a pending epoch stored incompletely was abandoned", "connection_id", o.c.ID)
		}
	}

	return nil
}

// dropStale drops, once everything is loaded, the outgoing handshakes
// whose hs.init names another identity key than this service's. The
// service never rotates its identity key, so this means its keys or
// secrets are wrong, or the table is another service's: an alarm, not an
// audit. The tokens the hs.init carries are revoked, as dropOutgoing
// does, but a reconnect is not ended: the connection stays reconnecting,
// so resumeReconnects starts a fresh try at this start, under the current
// key. Starts under that same key keep that try; the start after the keys
// are put right drops it in turn and spends another. Each key change thus
// costs one try (MaxReconnectTries).
func (p *Peer) dropStale(stale []*outgoing) {
	for _, og := range stale {
		p.log().Error("a stored hs.init names another identity key than this service's: dropped; check the service's keys and secrets",
			"alarm", "outgoing_identity_changed", "connection_id", og.ConnID, "purpose", string(og.Init.Purpose))
		for _, j := range og.Issued {
			p.denyJTI(j, p.now())
		}
		p.markDirty(kindOutgoing, og.ID)
	}
}
