package peer

import (
	"context"
	"time"
)

// CreateInvite makes an in-person connection invitation (§6.4) and keeps
// it with the application's tag (for example the email index key of the
// address the visitor entered), which comes back in the connection's
// events.
func (p *Peer) CreateInvite(ctx context.Context, tag string) (*InviteRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.started {
		return nil, ErrNotStarted
	}
	now := p.now()
	iv := &Inviter{Keys: p.cfg.Keys, Relay: p.cfg.Relay, RelayURL: p.cfg.RelayURL, HintName: p.cfg.Profile.Name(),
		Now: func() time.Time { return now }}
	inv, err := iv.Create(ctx)
	if err != nil {
		return nil, err
	}
	rec := &InviteRecord{ID: inv.ID, OpenJTI: inv.OpenJTI, ClaimID: inv.ClaimID, Exp: inv.Exp, URL: inv.URL, Link: inv.Link, Tag: tag,
		Status: InviteWaiting}
	p.invites[rec.ID] = rec
	p.markDirty(kindInvite, rec.ID)
	p.issued[inv.OpenJTI] = &IssuedToken{JTI: inv.OpenJTI, Kind: tokOpen, Sub: "*", Exp: inv.Exp}
	p.markDirty(kindToken, inv.OpenJTI)
	if err := p.flush(ctx); err != nil {
		return nil, err
	}
	p.log().Info("invite created", "invite_id", rec.ID)
	c := *rec
	return &c, nil
}

// Invite returns an invitation and what became of it.
func (p *Peer) Invite(id string) (InviteRecord, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inv := p.invites[id]
	if inv == nil {
		return InviteRecord{}, false
	}
	return *inv, true
}

// CancelInvite withdraws an invitation nobody has accepted (§6.4
// "Revocation"): its open token is denylisted and its claim deleted.
func (p *Peer) CancelInvite(ctx context.Context, id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	inv := p.invites[id]
	if inv == nil || inv.Used || inv.Withdrew {
		return ErrNotFound
	}
	now := p.now()
	p.withdrawInvite(inv, now)
	p.endInvite(id, InviteExpired, now)
	return p.flushAndDrain(ctx)
}
