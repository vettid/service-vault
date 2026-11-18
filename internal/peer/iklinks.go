package peer

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The identity-key parts of VAULT-MESSAGING §3.4.1 that release 29 adds for
// the service as Q (RELEASE-29 §14, the fourth change): identity.rotate
// with the whole chain (S8, R29-K1) and rule C with seen links (R29-K8),
// as vettid-vault vault/iklinks.go and vault/rotateconflict.go do.

// MaxSeen bounds Connection.Seen: a link past it is not recorded.
const MaxSeen = handshake.MaxRotations

// errBadRotate: an identity.rotate body that is not one (rotateLinks).
var errBadRotate = errors.New("peer: malformed identity.rotate")

// rotateLinks reads an identity.rotate body (S8, 0.86.0): `rotations`, the
// whole chain since the signer of the epoch it travels in, when present
// and not empty, else `rotation` alone. `rotation` is always present and
// is the chain's last link.
func rotateLinks(body []byte) ([]*handshake.Rotation, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBadRotate
	}
	raw, ok := o["rotation"]
	if !ok {
		return nil, errBadRotate
	}
	last, err := handshake.ParseRotation(raw)
	if err != nil {
		return nil, errBadRotate
	}
	arr, present, err := o.OptArray("rotations")
	if err != nil || len(arr) > handshake.MaxRotations {
		return nil, errBadRotate
	}
	if !present || len(arr) == 0 {
		return []*handshake.Rotation{last}, nil
	}
	links := make([]*handshake.Rotation, 0, len(arr))
	for _, x := range arr {
		r, err := handshake.ParseRotation(x)
		if err != nil {
			return nil, errBadRotate
		}
		links = append(links, r)
	}
	if string(links[len(links)-1].Marshal()) != string(last.Marshal()) {
		return nil, errBadRotate // `rotation` is the chain's last link
	}
	return links, nil
}

// isAncestor reports whether ik is an ancestor of the member's current
// key: the old key of a followed link (§3.4.1 "Terms").
func isAncestor(c *Connection, ik ed25519.PublicKey) bool {
	if len(ik) == 0 || suite.EqualPublic(ik, c.Peer.IK) {
		return false
	}
	for _, r := range chainOf(c) {
		if suite.EqualPublic(r.OldIK, ik) {
			return true
		}
	}
	return false
}

// rotationConflictRec applies rule C (§3.4.1, R29-K8) to one link: a valid
// link whose old key already has a different successor, followed or seen,
// suspends the connection (§3.4 "One successor per key"; it reports true).
// When record is set, a valid link neither followed nor seen is kept as
// seen if it is relevant and there is room (not for a rekey hs.init until
// it has passed rekeyPrecheck).
func (p *Peer) rotationConflictRec(c *Connection, r *handshake.Rotation, record bool, now time.Time) bool {
	if r.Verify() != nil {
		return false // only a valid link is evidence
	}
	known := false
	prior := append(append([]json.RawMessage(nil), c.Chain...), c.Seen...)
	for _, raw := range prior {
		prev, err := handshake.ParseRotation(raw)
		if err != nil || !suite.EqualPublic(prev.OldIK, r.OldIK) {
			continue
		}
		if suite.EqualPublic(prev.NewIK, r.NewIK) {
			known = true // the same statement again (followed or seen)
			continue
		}
		p.suspend(c, now)
		return true
	}
	if record && !known && seenRelevant(c, r.OldIK) && len(c.Seen) < MaxSeen {
		c.Seen = append(c.Seen, r.Marshal())
		p.markDirty(kindConn, c.ID)
	}
	return false
}

// seenRelevant reports whether a link from old is kept as seen: old is the
// member's current key, an ancestor, or reached through seen links.
func seenRelevant(c *Connection, old ed25519.PublicKey) bool {
	if suite.EqualPublic(old, c.Peer.IK) || isAncestor(c, old) {
		return true
	}
	for _, raw := range c.Seen {
		if s, err := handshake.ParseRotation(raw); err == nil && suite.EqualPublic(s.NewIK, old) {
			return true
		}
	}
	return false
}

// pruneSeen keeps the seen links that are still relevant and not followed.
func pruneSeen(c *Connection) {
	kept := c.Seen[:0]
	for _, raw := range c.Seen {
		if s, err := handshake.ParseRotation(raw); err == nil && handshake.KnownPrefix(chainOf(c), []*handshake.Rotation{s}) == 0 &&
			seenRelevant(c, s.OldIK) {
			kept = append(kept, raw)
		}
	}
	if len(kept) == 0 {
		kept = nil
	}
	c.Seen = kept
}

// evidenceFirst is §3.4.1 acceptFrom step 3: every identity link a message
// carries is checked by rule C before anything refuses the message (a
// destroyed or demoted epoch, the ts window, the rate limit, dedupe,
// Table B), so that a second successor is found whatever epoch it travels
// under. An identity.rotate's links are recorded as seen; a rekey
// hs.init's only once it passes rekeyPrecheck (handleRekeyInit). It
// reports whether the connection is now suspended.
func (p *Peer) evidenceFirst(c *Connection, in *envelope.Inner, now time.Time) bool {
	var links []*handshake.Rotation
	record := true
	switch in.Type {
	case TypeIdentityRotate:
		links, _ = rotateLinks(in.Body)
	case handshake.TypeInit:
		if b, err := handshake.ParseInit(in.Body); err == nil {
			links, record = b.Rotations, false
		}
	}
	for _, r := range links {
		if p.rotationConflictRec(c, r, record, now) {
			return c.State == StateSuspended
		}
	}
	return false
}
