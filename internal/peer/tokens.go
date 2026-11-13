package peer

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Tokens (VAULT-MESSAGING §7.1, §7.2, §7.4), as the member vault issues
// and holds them for a connection.

func i64(v int64) *int64 { return &v }

// capTTL caps a lifetime by the relay's max_token_lifetime_seconds.
func (p *Peer) capTTL(ttl time.Duration) time.Duration {
	if m := time.Duration(p.limits.MaxTokenLifetimeSeconds) * time.Second; m > 0 && m < ttl {
		return m
	}
	return ttl
}

// mint issues a deposit token for the peer np of connection connID and
// records it by jti at once, so that deposits on it are classified (§6.6).
func (p *Peer) mint(connID string, np *peerInfo, kind string, ttl time.Duration, quota *relayauth.Quota, now time.Time) (string, error) {
	tok, _, err := p.mintJTI(connID, np, kind, ttl, quota, now)
	return tok, err
}

// mintJTI is mint, also returning the token's jti (to revoke it if the
// handshake it was minted for fails).
func (p *Peer) mintJTI(connID string, np *peerInfo, kind string, ttl time.Duration, quota *relayauth.Quota, now time.Time) (string, string, error) {
	jti := p.newID(now)
	tok, err := p.cfg.Relay.MintToken(relayauth.EncodeKey(np.Relay.PK), p.cfg.RelayURL,
		relayclient.TokenOptions{TTL: ttl, JTI: jti, Quota: quota})
	if err != nil {
		return "", "", err
	}
	// relayclient backdates iat by 60 s (RELAY-PROTOCOL §5.2); exp = iat + ttl.
	exp := now.UTC().Truncate(time.Second).Add(-peerwire.TokenBackdate).Add(ttl)
	p.seq++
	p.issued[jti] = &IssuedToken{JTI: jti, Kind: kind, Sub: relayauth.EncodeKey(np.Relay.PK), ConnID: connID, Exp: exp, Seq: p.seq}
	p.markDirty(kindToken, jti)
	return tok, jti, nil
}

// mintRequest issues a request token (§7.1): ≤ 16 days, 8 messages / 64 KiB.
func (p *Peer) mintRequest(connID string, np *peerInfo, now time.Time) (string, error) {
	return p.mint(connID, np, tokRequest, p.capTTL(peerwire.RequestTokenConnection),
		&relayauth.Quota{Msgs: i64(peerwire.RequestTokenQuotaMsgs), Bytes: i64(peerwire.RequestTokenQuotaBytes)}, now)
}

// mintStanding issues a standing token with the peer-vault quota (§7.1).
func (p *Peer) mintStanding(connID string, np *peerInfo, now time.Time) (string, error) {
	tok, _, err := p.mintStandingJTI(connID, np, now)
	return tok, err
}

func (p *Peer) mintStandingJTI(connID string, np *peerInfo, now time.Time) (string, string, error) {
	return p.mintJTI(connID, np, tokStanding, p.capTTL(peerwire.StandingMax),
		&relayauth.Quota{Msgs: i64(peerwire.PeerQuotaMsgs), Bytes: i64(peerwire.PeerQuotaBytes)}, now)
}

// mintReconnectPair issues the standing and reconnect tokens of a
// reconnect's hs.resp, with their jtis.
func (p *Peer) mintReconnectPair(connID string, np *peerInfo, now time.Time) (st, rt string, jtis []string, err error) {
	st, j1, err := p.mintJTI(connID, np, tokStanding, p.capTTL(peerwire.StandingMax),
		&relayauth.Quota{Msgs: i64(peerwire.PeerQuotaMsgs), Bytes: i64(peerwire.PeerQuotaBytes)}, now)
	if err != nil {
		return "", "", nil, err
	}
	ttl := handshake.ReconnectTokenLifetime(time.Duration(p.limits.MaxTokenLifetimeSeconds) * time.Second)
	rt, j2, err := p.mintJTI(connID, np, tokReconnect, ttl,
		&relayauth.Quota{Msgs: i64(handshake.ReconnectTokenQuotaMsgs), Bytes: i64(handshake.ReconnectTokenQuotaBytes)}, now)
	if err != nil {
		p.denyJTI(j1, now)
		return "", "", nil, err
	}
	p.issued[j1].Carried, p.issued[j2].Carried = true, true
	return st, rt, []string{j1, j2}, nil
}

// mintReconnect issues a reconnect token (§6.6): ≤ 365 days and the relay
// cap, 4 messages / 64 KiB.
func (p *Peer) mintReconnect(connID string, np *peerInfo, now time.Time) (string, error) {
	tok, _, err := p.mintReconnectJTI(connID, np, now)
	return tok, err
}

func (p *Peer) mintReconnectJTI(connID string, np *peerInfo, now time.Time) (string, string, error) {
	ttl := handshake.ReconnectTokenLifetime(time.Duration(p.limits.MaxTokenLifetimeSeconds) * time.Second)
	return p.mintJTI(connID, np, tokReconnect, ttl,
		&relayauth.Quota{Msgs: i64(handshake.ReconnectTokenQuotaMsgs), Bytes: i64(handshake.ReconnectTokenQuotaBytes)}, now)
}

// heldToken checks a token a member's vault issued to the service
// (peerwire.VerifyHeldToken).
func (p *Peer) heldToken(tok string, np *peerInfo) (HeldToken, error) {
	c, err := peerwire.VerifyHeldToken(tok, np.Relay.PK, np.Relay.Mailbox, np.Relay.URL, p.cfg.Keys.RelayPublic())
	if err != nil {
		return HeldToken{}, err
	}
	return HeldToken{Token: tok, Exp: c.Exp}, nil
}

// denyJTI revokes one token (§7.4: invitations).
func (p *Peer) denyJTI(jti string, now time.Time) {
	if jti == "" {
		return
	}
	if t := p.issued[jti]; t != nil {
		t.Denied = true
		p.markDirty(kindToken, jti)
	}
	p.queueRevoke(jti, now)
}

// denyConnTokens revokes, by jti, every token issued for a connection,
// including those minted in handshakes in flight (§7.4).
func (p *Peer) denyConnTokens(connID string, now time.Time) {
	for _, t := range p.issued {
		if t.ConnID == connID && !t.Denied && t.Kind != tokOpen {
			t.Denied = true
			p.markDirty(kindToken, t.JTI)
			p.queueRevoke(t.JTI, now)
		}
	}
}

func (p *Peer) latestIssued(connID, kind string) *IssuedToken {
	var best *IssuedToken
	for _, t := range p.issued {
		if t.ConnID == connID && t.Kind == kind && !t.Denied && (best == nil || t.Exp.After(best.Exp)) {
			best = t
		}
	}
	return best
}

// remintIssued re-mints standing tokens with less than 10 days left and
// reconnect tokens with less than 60 days left, and delivers them as
// relay.token.issued (§7.2).
func (p *Peer) remintIssued(now time.Time) {
	for _, c := range p.conns {
		if c.State != StateActive || c.Reconnecting {
			continue
		}
		if t := p.latestIssued(c.ID, tokStanding); t == nil ||
			t.Exp.Sub(now) < peerwire.StandingRemintBelow && p.capTTL(peerwire.StandingMax) > peerwire.StandingRemintBelow {
			p.issueTo(c, tokStanding, now)
		}
		if t := p.latestIssued(c.ID, tokReconnect); t == nil || handshake.ReconnectRemintDue(t.Exp, now) {
			p.issueTo(c, tokReconnect, now)
		}
	}
}

func (p *Peer) issueTo(c *Connection, kind string, now time.Time) {
	p.issue(c, kind, false, now)
}

// issue is issueTo; prompt marks a token re-minted at a confirmation.
func (p *Peer) issue(c *Connection, kind string, prompt bool, now time.Time) {
	if c.Reconnecting || p.outboxFor(c.ID) >= MaxOutboxPerConn {
		return // not deliverable now: mint it when it can be sent
	}
	var tok, jti string
	var err error
	if kind == tokReconnect {
		tok, jti, err = p.mintReconnectJTI(c.ID, &c.Peer, now)
	} else {
		tok, jti, err = p.mintStandingJTI(c.ID, &c.Peer, now)
	}
	if err != nil {
		return
	}
	if t := p.issued[jti]; prompt && t != nil {
		t.Prompt = true
	}
	p.sendTo(c, peerwire.TypeTokenIssued, peerwire.TokenIssuedBody(kind, tok), now)
}

// refreshWait is how long a relay.token.refresh may stay unanswered
// before another is sent (chosen; not in the spec).
const refreshWait = time.Hour

// refreshHeld asks a connection for a fresh standing token when the one
// we hold has less than 3 days left (§7.2), or at once (force) after
// token_expired.
func (p *Peer) refreshHeld(c *Connection, now time.Time, force bool) {
	if c.State != StateActive || c.Reconnecting || c.Standing.Token == "" || now.Before(c.RefreshAfter) {
		return
	}
	if !now.Before(c.Standing.Exp) {
		return // past its exp a refresh could not be deposited: a waiting entry reconnects instead (§8.6)
	}
	if !force && c.Standing.Exp.Sub(now) >= peerwire.HolderRefreshBelow {
		return
	}
	if c.RefreshID != "" {
		return
	}
	for _, e := range p.outbox {
		if e.ConnID == c.ID && e.Refresh {
			return // not while one is still queued (§8.6)
		}
	}
	in := &envelope.Inner{ID: p.newID(now), Type: peerwire.TypeTokenRefresh, TS: now, Body: peerwire.TokenRefreshBody()}
	if e := p.sendEntry(c, in, now); e != nil {
		e.Refresh = true
		c.RefreshID, c.RefreshAfter = in.ID, now.Add(refreshWait)
		p.markDirty(kindConn, c.ID)
	}
}

// storeIssuedTo stores a token a member's vault issued to us ({kind,
// token}): a reconnect token replaces ours; a standing token replaces
// ours if it lasts longer.
func (p *Peer) storeIssuedTo(c *Connection, body json.RawMessage) {
	kind, tok, err := peerwire.ParseTokenIssued(body)
	if err != nil {
		p.audit("bad_issued_token", c.ID)
		return
	}
	ht, err := p.heldToken(tok, &c.Peer)
	if err != nil {
		p.audit("bad_issued_token", c.ID)
		return
	}
	if kind == tokReconnect {
		// Only one that is valid and lasts at least as long as the held one
		// (exps are whole seconds), as
		// for a handshake's carried token (§6.3.1): a copy holding the
		// session's keys cannot swap in a shorter-lived one.
		if !p.now().Before(ht.Exp) || ht.Exp.Before(c.Reconnect.Exp) {
			p.audit("issued_token_not_later", c.ID)
			return
		}
		c.Reconnect = ht
		p.markDirty(kindConn, c.ID)
		return
	}
	if ht.Exp.After(c.Standing.Exp) {
		c.Standing = ht
		c.RefreshAfter = time.Time{}
		p.markDirty(kindConn, c.ID)
		p.retryConn(c.ID)
	}
}

// errTooSoon is a refresh answered too_soon (§7.2).
type errTooSoon struct{ after time.Time }

func (e *errTooSoon) Error() string { return peerwire.CodeTooSoon }

// answerTokenRefresh answers a connection's relay.token.refresh (§7.2):
// a fresh standing token, at most one an hour near the token's end and
// one in 24 hours after quota_exceeded (the old ones then denylisted).
func (p *Peer) answerTokenRefresh(c *Connection, now time.Time) (json.RawMessage, error) {
	quota := false
	if t := p.latestIssued(c.ID, tokStanding); t != nil {
		quota = t.Exp.Sub(now) >= peerwire.HolderRefreshBelow
	}
	if quota {
		if !c.Refreshed.IsZero() && now.Sub(c.Refreshed) < peerwire.QuotaRefreshEvery {
			return nil, &errTooSoon{c.Refreshed.Add(peerwire.QuotaRefreshEvery)}
		}
	} else {
		if !c.Renewed.IsZero() && now.Sub(c.Renewed) < peerwire.RenewEvery {
			return nil, &errTooSoon{c.Renewed.Add(peerwire.RenewEvery)}
		}
		c.Renewed = now
		p.markDirty(kindConn, c.ID)
	}
	if quota {
		p.revokeAtRefresh(c, now)
		c.Refreshed = now
		p.markDirty(kindConn, c.ID)
	}
	tok, err := p.mintStanding(c.ID, &c.Peer, now)
	if err != nil {
		return nil, errors.New("relay_error")
	}
	return peerwire.TokenIssuedBody(tokStanding, tok), nil
}

// revokeAtRefresh revokes, at a refresh after quota_exceeded, the standing
// tokens issued to c that §6.3.1 "Revocation by the issuer" lets it
// (RELEASE-29 §12): never one a still-open handshake carried, the newest
// one a reconnect carried, the newest one re-minted at a confirmation, nor
// one newer than the token the refresh was deposited under. When that
// token is unknown (no collect jti), none is revoked.
func (p *Peer) revokeAtRefresh(c *Connection, now time.Time) {
	under := p.issued[p.msgJTI]
	if under == nil || under.ConnID != c.ID {
		return
	}
	keep := map[string]bool{}
	for _, aw := range p.awaiting {
		if aw.ConnID == c.ID && aw.Reconnect != nil {
			for _, j := range aw.Reconnect.Issued {
				keep[j] = true
			}
		}
	}
	for _, og := range p.outgoing {
		if og.ConnID == c.ID {
			for _, j := range og.Issued {
				keep[j] = true
			}
		}
	}
	if c.Pending != nil {
		for _, j := range c.Pending.Issued {
			keep[j] = true
		}
	}
	// Newer: a later exp, then a later mint (Seq; 0 on older records).
	newer := func(a, b *IssuedToken) bool {
		return a.Exp.After(b.Exp) || a.Exp.Equal(b.Exp) && a.Seq > b.Seq
	}
	var carried, prompt *IssuedToken
	for _, t := range p.issued {
		if t.ConnID != c.ID || t.Kind != tokStanding || t.Denied {
			continue
		}
		if t.Carried && (carried == nil || newer(t, carried)) {
			carried = t
		}
		if t.Prompt && (prompt == nil || newer(t, prompt)) {
			prompt = t
		}
	}
	for _, t := range []*IssuedToken{carried, prompt} {
		if t != nil {
			keep[t.JTI] = true
		}
	}
	for _, t := range p.issued {
		if t.ConnID != c.ID || t.Kind != tokStanding || t.Denied || keep[t.JTI] || newer(t, under) {
			continue
		}
		t.Denied = true
		p.markDirty(kindToken, t.JTI)
		p.queueRevoke(t.JTI, now)
	}
}

// handleRefreshAnswer handles the answer to our relay.token.refresh.
func (p *Peer) handleRefreshAnswer(c *Connection, in *envelope.Inner, now time.Time) {
	c.RefreshID = ""
	p.markDirty(kindConn, c.ID)
	if in.Status == envelope.StatusOK {
		p.storeIssuedTo(c, in.Body)
		return
	}
	if in.Error != nil && in.Error.Code == peerwire.CodeTooSoon {
		if t, err := peerwire.ParseTooSoon(in.Body); err == nil && t.After(now) {
			c.RefreshAfter = t
		}
	}
}

// pruneIssued drops registry entries long past expiry.
func (p *Peer) pruneIssued(now time.Time) {
	for jti, t := range p.issued {
		if now.Sub(t.Exp) >= tokenRetention {
			delete(p.issued, jti)
			p.markDirty(kindToken, jti)
		}
	}
}
