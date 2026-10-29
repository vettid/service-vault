package peer

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/invite"
)

// InviteTTL is the life of every invitation the service makes: the
// in-person TTL, so the service may approve its own side automatically
// (§6.4 "Approval"; invite.AutoApproveAllowed). A member scans the QR or
// follows the link on the site while the page is open.
var InviteTTL = invite.TTLInPerson

// tokenBackdate is relayclient's backdating of an open token's iat:
// min(60 s, ttl/2) (RELAY-PROTOCOL §5.6). The bundle's exp equals the
// token's exp (§7.1).
const tokenBackdate = 60 * time.Second

// ClaimRelay is the part of relayclient.Client an Inviter uses.
type ClaimRelay interface {
	MintOpenToken(audience string, ttl time.Duration, jti string) (string, error)
	PutClaim(ctx context.Context, data []byte, ttl time.Duration) (claimID string, expiresAt time.Time, err error)
}

// Invite is an invitation the service made (§6.4).
type Invite struct {
	ID      string    // ULID; the bundle's invite_id and hs.init's ctx
	OpenJTI string    // jti of the open token in the bundle
	ClaimID string    // the relay claim holding the sealed bundle
	Exp     time.Time // the bundle's and the open token's exp
	Link    string    // the QR / link payload (§6.4)
	URL     string    // <relay>/connect#<payload>: the site's button and QR
}

// Inviter makes connection invitations.
type Inviter struct {
	Keys     *Keys
	Relay    ClaimRelay
	RelayURL string // the service's relay, as in the bundle (RELAY-PROTOCOL §3)
	HintName string // shown to the member before they accept (§6.4)
	Now      func() time.Time
}

// ErrHintName is returned for a hint name over invite.MaxHintName bytes.
var ErrHintName = errors.New("peer: hint name too long")

// Create makes an in-person connection invitation: an open token for the
// member's vault to deposit hs.init with, the encrypted bundle left as a
// single-fetch claim, and the link that carries the claim id, the
// bundle's hash and its key (§6.4).
func (iv *Inviter) Create(ctx context.Context) (*Invite, error) {
	if len(iv.HintName) > invite.MaxHintName {
		return nil, ErrHintName
	}
	now := iv.Now().UTC()
	id, err := envelope.NewULID(now)
	if err != nil {
		return nil, fmt.Errorf("peer: invite id: %w", err)
	}
	jti, err := envelope.NewULID(now)
	if err != nil {
		return nil, fmt.Errorf("peer: token id: %w", err)
	}
	tok, err := iv.Relay.MintOpenToken(iv.RelayURL, InviteTTL, jti)
	if err != nil {
		return nil, fmt.Errorf("peer: open token: %w", err)
	}
	exp := now.Truncate(time.Second).Add(-min(tokenBackdate, InviteTTL/2)).Add(InviteTTL)
	b := &invite.Bundle{
		Kind:     "connection",
		InviteID: id,
		Remote:   false,
		Vault:    iv.Keys.Principal(iv.RelayURL),
		Token:    tok,
		Exp:      exp,
		HintName: iv.HintName,
		// A member vault keeps a service connection's epoch history, so it
		// takes the service's reconnect after a restore (VAULT-MESSAGING
		// §6.4, §6.6).
		PeerKind: invite.PeerKindService,
	}
	bj, err := b.Marshal()
	if err != nil {
		return nil, fmt.Errorf("peer: bundle: %w", err)
	}
	blob, kb, h, err := invite.SealBundle(bj)
	if err != nil {
		return nil, fmt.Errorf("peer: seal bundle: %w", err)
	}
	claimID, _, err := iv.Relay.PutClaim(ctx, blob, InviteTTL)
	if err != nil {
		return nil, fmt.Errorf("peer: claim: %w", err)
	}
	q := &invite.QR{Kind: invite.KindConnection, Relay: iv.RelayURL, ClaimID: claimID, Hash: h, Key: kb, Exp: exp.Unix()}
	link, err := q.Link()
	if err != nil {
		return nil, fmt.Errorf("peer: link: %w", err)
	}
	return &Invite{ID: id, OpenJTI: jti, ClaimID: claimID, Exp: exp, Link: link,
		URL: strings.TrimRight(iv.RelayURL, "/") + "/connect#" + link}, nil
}
