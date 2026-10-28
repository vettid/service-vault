package peer

import (
	"context"
	"time"
)

// Event types the peer reports to the application.
const (
	// EventConnectionPending: hs.fin checked out; the SAS is known and
	// the service has approved its own side (§6.4). The application
	// shows the SAS so that the member can compare it on the phone.
	EventConnectionPending = "connection.pending"
	// EventConnectionAdded: both sides approved; the connection is active.
	EventConnectionAdded = "connection.added"
	// EventConnectionDeclined: the member declined the request.
	EventConnectionDeclined = "connection.declined"
	// EventConnectionExpired: the request ended without both approvals.
	EventConnectionExpired = "connection.expired"
	// EventConnectionRemoved: the connection ended, by either side.
	EventConnectionRemoved = "connection.removed"
	// EventConnectionSuspended: the connection stopped after a rotation
	// conflict (§3.4 "One successor per key"; rotation.go). It sends and
	// accepts nothing; a new invitation replaces it (chosen; not in the
	// spec).
	EventConnectionSuspended = "connection.suspended"
	// EventSignInApproved: the member signed a challenge (§10.4).
	EventSignInApproved = "signin.approved"
	// EventSignInDenied: the member's vault answered denied, or the
	// answer did not verify.
	EventSignInDenied = "signin.denied"
	// EventSignInExpired: no answer before the challenge's exp.
	EventSignInExpired = "signin.expired"
)

// Event is something the application learns from the peer. It carries
// ids and outcomes only; Tag is the application's own tag of the
// invitation (for example its email index key), never sent to a member.
type Event struct {
	ID           string `json:"id"` // a ULID, stable across redeliveries
	Seq          uint64 `json:"seq"`
	Type         string `json:"type"`
	ConnectionID string `json:"connection_id,omitempty"`
	InviteID     string `json:"invite_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"` // a sign-in challenge
	SAS          string `json:"sas,omitempty"`        // connection.pending only
	Name         string `json:"name,omitempty"`       // the member's account name (self-asserted, §6.4)
	Tag          string `json:"tag,omitempty"`
	Reason       string `json:"reason,omitempty"`      // signin.denied: denied | bad_signature; connection.suspended: rotation_conflict
	KeyChanged   bool   `json:"key_changed,omitempty"` // signin.approved: the pinned key changed (§10.4)
	Direction    string `json:"direction,omitempty"`   // connection.removed: in (the member) | out (the service)
	// The evidence of a challenge's answer (signin.*): the challenge's
	// context, and for a signed answer the credential key, the signature
	// and its signed_at (§10.4). Kept with the event and given to Events;
	// never logged.
	Context   string    `json:"context,omitempty"`
	Key       []byte    `json:"key,omitempty"`
	Signature []byte    `json:"signature,omitempty"`
	SignedAt  time.Time `json:"signed_at,omitzero"`
	At        time.Time `json:"at"`
}

// Events receives the peer's events after they are persisted. Deliver is
// called from one goroutine, in order, until it returns nil; an event is
// delivered at least once.
type Events interface {
	Deliver(ctx context.Context, e *Event) error
}

// emit queues an event; it is written with the changes that caused it.
func (p *Peer) emit(e *Event, now time.Time) {
	e.ID = p.newID(now)
	p.seq++
	e.Seq = p.seq
	e.At = now.UTC().Truncate(time.Millisecond)
	p.events = append(p.events, e)
	p.markDirty(kindEvent, e.ID)
	p.log().Info("event", "type", e.Type, "event_id", e.ID, "connection_id", e.ConnectionID, "invite_id", e.InviteID,
		"request_id", e.RequestID)
}

func (p *Peer) eventByID(id string) *Event {
	for _, e := range p.events {
		if e.ID == id {
			return e
		}
	}
	return nil
}
