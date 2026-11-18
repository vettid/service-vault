package peer

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Leaving and votes (BALLOT-PROTOCOL 0.14.2 §6): a member's membership is
// judged at the relay's time of each vote.cast. When a connection leaves
// (removed in either direction, replaced, or suspended), the peer records
// when, and keeps a receive-only record of a removed connection, so that a
// vote.cast the relay received before the removal, and the service handles
// after it (an outage backlog), is still decrypted and judged.

const kindKept = "kept" // a removed connection's receive-only record, or its tombstone

// Leave kinds.
const (
	LeftRemovedIn  = "removed_in"  // the member's vault removed the connection
	LeftRemovedOut = "removed_out" // the service removed it (the operator)
	LeftReplaced   = "replaced"    // a new connection with the same identity or relay key took its place
	LeftSuspended  = "suspended"   // suspended (fork evidence, a rotation conflict, an unlinked relay move)
)

// unackedHold is how long the count waits for a message left unacked
// (BALLOT-PROTOCOL §7): a cast can be handled that long after the close.
const unackedHold = 24 * time.Hour

// delayedCount is the slack for a count held up after that (the
// timestamp authority or Rekor down, §7, §10.1).
const delayedCount = 6 * 24 * time.Hour

// KeptKeysFor is how long a removed connection's receive-only keys are
// kept after the removal: a vote open at the removal closes at most
// vote.MaxWindow plus vote.MaxExtension after it, and is counted within
// unackedHold and delayedCount after its close. It is below
// envelope.MaxDurableAge, so the inner ts check never refuses a cast the
// keys are kept for.
const KeptKeysFor = vote.MaxWindow*time.Second + vote.MaxExtension*time.Second + unackedHold + delayedCount

// KeptRecordFor is how long a leave's keyless tombstone is kept: what
// counts.removed is computed from (§7). A count run later than this after
// a removal finds no record for that member and raises an alarm.
const KeptRecordFor = 60 * 24 * time.Hour

// typeVoteCast is the only message a kept record lets through.
const typeVoteCast = "vote.cast"

// keptConn is a removed connection's receive-only record: what judging a
// queued vote.cast needs, and no more. Keyring is nil once the keys are
// destroyed (a tombstone), and always for a suspended connection.
type keptConn struct {
	ID      string            `json:"id"`
	RelayPK ed25519.PublicKey `json:"relay_pk"`
	PeerIK  ed25519.PublicKey `json:"peer_ik"`
	// CredentialKey is the member's credential key at the removal, frozen:
	// no later rotation reaches it.
	CredentialKey []byte `json:"credential_key,omitempty"`
	// JTIs are the standing tokens issued to the connection, frozen at the
	// removal: a deposit made under another token is refused.
	JTIs    []string                `json:"jtis,omitempty"`
	Keyring *handshake.KeyringState `json:"keyring,omitempty"`
	// LeftAtMS is when the connection left, in Unix milliseconds, on the
	// relay's clock when a message caused it (§6), else the service's.
	LeftAtMS uint64 `json:"left_at_ms"`
	Kind     string `json:"kind"`
	// At is the service's time of the leave: the bounds count from it.
	At time.Time `json:"at"`

	kr *handshake.Keyring
}

// leaveMS is the time of a leave happening now: the relay's time of the
// message being handled when there is one (the clock the casts are judged
// on, in msg_id order), else the service's.
func (p *Peer) leaveMS(now time.Time) uint64 {
	if p.msgID != "" {
		if ms, err := ulidMS(p.msgID); err == nil {
			return ms
		}
	}
	return uint64(now.UnixMilli())
}

// leaveKind is the kind of a removal in direction dir.
func leaveKind(dir string) string {
	switch dir {
	case "in":
		return LeftRemovedIn
	case "replaced":
		return LeftReplaced
	}
	return LeftRemovedOut
}

// keep records c's leave as it is removed, before its keys are destroyed:
// a receive-only record, or a tombstone when c is suspended (nothing is
// accepted once suspended, and the suspension's time stays first). Only a
// service with a ballot box keeps anything.
func (p *Peer) keep(c *Connection, dir string, now time.Time) {
	if p.cfg.Votes == nil {
		return
	}
	k := &keptConn{ID: c.ID, RelayPK: c.Peer.Relay.PK, PeerIK: c.Peer.IK, Kind: leaveKind(dir), LeftAtMS: p.leaveMS(now), At: now}
	// A suspended connection replaced by a new one is set stale first
	// (replaceOlderConnections): its suspension time still marks it.
	if c.State == StateSuspended || c.SuspendedAtMS != 0 {
		k.Kind = LeftSuspended
		if c.SuspendedAtMS != 0 {
			k.LeftAtMS = c.SuspendedAtMS
		}
		p.kept[k.ID] = k
		p.markDirty(kindKept, k.ID)
		return
	}
	k.CredentialKey = slices.Clone(c.AuthKey)
	for jti, t := range p.issued {
		if t.ConnID == c.ID && t.Kind == tokStanding {
			k.JTIs = append(k.JTIs, jti)
		}
	}
	sort.Strings(k.JTIs)
	if c.kr != nil {
		kr, err := receiveOnly(c.kr.Export(), now.Add(KeptKeysFor))
		if err != nil {
			p.log().Error("a removed connection's receive keys could not be kept: a vote it cast before the removal and not yet handled is lost",
				"alarm", "kept_keys_failed", "connection_id", c.ID, "err", err)
		} else {
			k.kr = kr
		}
	}
	p.kept[k.ID] = k
	p.markDirty(kindKept, k.ID)
}

// receiveOnly makes a keyring that can only open: every epoch of s
// (current, pending and superseded) becomes a superseded one, without its
// send key or rekey secret, kept until until. The keys of s are wiped.
func receiveOnly(s handshake.KeyringState, until time.Time) (*handshake.Keyring, error) {
	var ro handshake.KeyringState
	add := func(e handshake.EpochState) {
		suite.Wipe(e.SendKey)
		suite.Wipe(e.RK)
		e.SendKey, e.RK = nil, nil
		ro.Retired = append(ro.Retired, handshake.RetiredState{Epoch: e, Until: until})
	}
	if s.Current != nil {
		add(*s.Current)
	}
	if s.Pending != nil {
		add(*s.Pending)
	}
	for _, r := range s.Retired {
		add(r.Epoch)
	}
	kr, err := handshake.ImportKeyring(ro)
	for _, r := range ro.Retired {
		suite.Wipe(r.Epoch.RecvKey) // ImportKeyring copied them
	}
	return kr, err
}

// keptMessage tries the kept records of the sender's relay key for a
// session-mode envelope no live connection opened. ok is false when none
// holds its key.
func (p *Peer) keptMessage(ctx context.Context, env *envelope.Envelope, msgID, jti string, sender ed25519.PublicKey, now time.Time) (d disposition, ok bool, err error) {
	ids := make([]string, 0, len(p.kept))
	for id := range p.kept {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		k := p.kept[id]
		if k.kr == nil || !suite.EqualPublic(k.RelayPK, sender) {
			continue
		}
		in, _, err := k.kr.Open(env, now)
		if errors.Is(err, envelope.ErrKid) {
			continue
		}
		p.markDirty(kindKept, k.ID) // the epoch's receive count moved
		if err != nil {
			p.audit("decrypt_failed", k.ID)
			return ackAfterFlush, true, nil
		}
		return ackAfterFlush, true, p.keptCast(ctx, k, in, msgID, jti, now)
	}
	return 0, false, nil
}

// keptCast is the gate of a kept record: a vote.cast, deposited under one
// of the connection's standing tokens, fresh, within the rate, and not
// seen before, goes to the ballot box, which judges it against the
// connection's leave. Nothing else passes (no evidence, no rekey, no
// response, no identity change), and nothing is answered: the connection
// is gone.
func (p *Peer) keptCast(ctx context.Context, k *keptConn, in *envelope.Inner, msgID, jti string, now time.Time) error {
	switch {
	case jti == "" || !slices.Contains(k.JTIs, jti):
		p.audit("kept_token_refused", k.ID)
		return nil
	case in.Type != typeVoteCast || in.Re != "":
		p.audit("kept_type_refused", k.ID)
		return nil
	case in.CheckTime(now, true) != nil:
		p.audit("stale_or_future", k.ID)
		return nil
	case !p.rateAllow(k.ID, now):
		p.audit("rate_limited", k.ID)
		return nil
	case p.cfg.Votes == nil:
		return nil
	}
	ms, err := ulidMS(msgID)
	if err != nil {
		p.audit("bad_msg_id", k.ID)
		return nil
	}
	ikey := k.ID + "|" + in.ID
	_, seen, err := p.cfg.Store.Get(ctx, kindInner, ikey)
	if err != nil {
		return err
	}
	if seen {
		return nil // handled before; there is nothing to send again
	}
	p.mark(kindInner, ikey, []byte{1}, now.Add(DedupeRetention))
	p.log().Info("message", "connection_id", k.ID, "type", in.Type, "kept", true)
	_, err = p.cfg.Votes.Vote(ctx, &VoteRequest{ConnectionID: k.ID, PeerIK: k.PeerIK, CredentialKey: k.CredentialKey,
		LeftAtMS: k.LeftAtMS, Left: k.Kind, Type: in.Type, Body: in.Body, MsgMS: ms})
	if errors.Is(err, ErrNoAnswer) {
		p.unmark(kindInner, ikey)
		return nil
	}
	return err
}

// pruneKept destroys kept keys at KeptKeysFor and forgets tombstones at
// KeptRecordFor.
func (p *Peer) pruneKept(now time.Time) {
	for id, k := range p.kept {
		if !now.Before(k.At.Add(KeptRecordFor)) {
			if k.kr != nil {
				k.kr.Destroy()
			}
			delete(p.kept, id)
			p.markDirty(kindKept, id)
			continue
		}
		if k.kr != nil && !now.Before(k.At.Add(KeptKeysFor)) {
			k.kr.Destroy()
			k.kr, k.Keyring = nil, nil
			p.markDirty(kindKept, id)
			p.log().Info("a removed connection's kept receive keys destroyed at their bound", "connection_id", id)
		}
	}
}

// Leave is when a member's connection left: AtMS on the relay's clock
// when a message caused it, else the service's; Known is false when no
// record of the connection is left (removed before leave times were
// recorded, or its tombstone forgotten after KeptRecordFor).
type Leave struct {
	AtMS  uint64
	Kind  string
	Known bool
}

// Left reports, for each of ids that has left, when (ballot.Roster): a
// suspended connection by its suspension, a removed or replaced one by its
// kept record. An active or stale connection hasn't left and isn't listed.
func (p *Peer) Left(ids []string) map[string]Leave {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]Leave{}
	for _, id := range ids {
		if c := p.conns[id]; c != nil {
			if c.State == StateSuspended {
				out[id] = Leave{AtMS: c.SuspendedAtMS, Kind: LeftSuspended, Known: c.SuspendedAtMS != 0}
			}
			continue
		}
		if k := p.kept[id]; k != nil {
			out[id] = Leave{AtMS: k.LeftAtMS, Kind: k.Kind, Known: true}
			continue
		}
		out[id] = Leave{}
	}
	return out
}
