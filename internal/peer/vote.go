package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Votes (BALLOT-PROTOCOL §4.2): a member vault's vote.* requests go to the
// application's ballot box, with what it needs to answer them that only
// the connection knows.

// VoteRequest is a vote.* request from a member's vault.
type VoteRequest struct {
	ConnectionID string
	// PeerIK is the member vault's identity key on this connection.
	PeerIK ed25519.PublicKey
	// CredentialKey is the member's credential key pinned at the first
	// signed connection.authenticate.response, or nil.
	CredentialKey []byte
	// Active is false once the connection is no longer active.
	Active bool
	Type   string
	Body   []byte
	// MsgMS is the relay's time of the message, from its msg_id
	// (RELAY-PROTOCOL §6.2), in Unix milliseconds.
	MsgMS uint64
}

// VoteAnswer is the response: Body with Code "" for ok, or an error code
// with its body.
type VoteAnswer struct {
	Body json.RawMessage
	Code string
}

// Votes answers vote.* requests. An error is a storage failure: the
// message is not acknowledged, and the relay delivers it again.
type Votes interface {
	Vote(ctx context.Context, r *VoteRequest) (VoteAnswer, error)
}

// isVoteType reports whether typ is one of the vote family (§4.2).
func isVoteType(typ string) bool { return strings.HasPrefix(typ, "vote.") }

func (p *Peer) vote(ctx context.Context, c *Connection, in *envelope.Inner, ikey, msgID string, now time.Time) error {
	ms, err := ulidMS(msgID)
	if err != nil {
		p.audit("bad_msg_id", c.ID)
		return nil
	}
	a, err := p.cfg.Votes.Vote(ctx, &VoteRequest{ConnectionID: c.ID, PeerIK: c.Peer.IK, CredentialKey: c.AuthKey,
		Active: c.State == StateActive, Type: in.Type, Body: in.Body, MsgMS: ms})
	if err != nil {
		return err
	}
	if a.Code == "" {
		p.respond(c, in, ikey, a.Body, now)
	} else {
		p.respondErrorBody(c, in, ikey, a.Code, a.Body, now)
	}
	return nil
}

// ulidMS is the millisecond time of a ULID's first ten characters.
func ulidMS(id string) (uint64, error) {
	if !envelope.ValidULID(id) {
		return 0, errors.New("peer: not a ULID")
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var ms uint64
	for _, ch := range id[:10] {
		ms = ms<<5 | uint64(strings.IndexRune(alphabet, ch))
	}
	return ms, nil
}
