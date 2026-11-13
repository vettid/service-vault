package peer

import (
	"context"
	"encoding/json"
	"sort"
	"time"
)

// MessagingRelease is the marker every connection record is written with
// once release 29's rules are complete (RELEASE-29 §11, change 4c;
// VAULT-MESSAGING §6.3.1 "No upgrade: release 29 starts clean").
const MessagingRelease = 29

// RemovedPre29 is connection.removed's reason for a connection ended at a
// start because its record came from before release 29's rules were
// complete: the application can tell it from an operator's removal and
// invite the member again.
const RemovedPre29 = "pre29"

// endPre29 is RELEASE-29 §11, run at every start right after the state is
// loaded, before any reconnect (a restore's included), housekeeping or
// drain: every connection record without the marker, or with a value
// below MessagingRelease, is ended. The member is sent connection.removed
// (best effort), every token issued for the connection is revoked, its
// handshakes end with it, its waiting messages end audited
// drop.undelivered_removed, connection_pre29_ended is audited, and the
// application gets connection.removed with the reason pre29. One alarm
// gives the count. Invitations are not ended: one claimed later makes a
// connection under these rules.
func (p *Peer) endPre29(ctx context.Context, now time.Time) error {
	var old []*Connection
	for _, c := range p.conns {
		// A record from a later release (above 29, after a rollback to
		// this one) is kept: its rules include these.
		if c.MessagingRelease < MessagingRelease {
			old = append(old, c)
		}
	}
	if len(old) == 0 {
		return nil
	}
	sort.Slice(old, func(i, j int) bool { return old[i].ID < old[j].ID })
	for _, c := range old {
		if err := p.endConnection(ctx, c, "connection_pre29_ended", RemovedPre29, now); err != nil {
			return err
		}
	}
	p.log().Error("connections from before release 29 ended: the members must connect again from new invitations",
		"alarm", "pre29_ended", "count", len(old))
	return nil
}

// endConnection ends one connection at a start (endPre29, endAllOnce) and
// stores it in two writes: first everything the end changes but the
// connection record (its tokens denied, its revocations and the member's
// notice queued, its waiting messages and handshakes dropped, the
// application's event), then the deletion of the record itself. The store
// splits a large write into transactions (internal/store: 100 items each),
// so ending many connections in one write could delete records whose
// tokens were never denied; this way, a write that fails leaves the record
// in place, and the next start ends that connection again.
func (p *Peer) endConnection(ctx context.Context, c *Connection, audit, reason string, now time.Time) error {
	p.audit(audit, c.ID)
	p.removeConnectionFor(c, "out", reason, now)
	k := key{kindConn, c.ID}
	_, conn := p.dirty[k]
	delete(p.dirty, k)
	if err := p.flush(ctx); err != nil {
		return err
	}
	if conn {
		p.markDirty(k.kind, k.id)
	}
	return p.flush(ctx)
}

// RemovedEndAll is connection.removed's reason for a connection ended by
// the operator's one-shot EndAllConnections.
const RemovedEndAll = "ended_all"

// endAllOnce is the one-shot setting the owner chose for RELEASE-29 §11's
// runbook step (GC #10082): after a rollback across the marker, the
// operator deploys forward with EndAllConnections set to a date, and the
// first start that sees that date ends every connection the way endPre29
// does (connection.removed to the member, best effort; its tokens
// revoked; its waiting messages audited; connection_ended_all audited;
// connection.removed with the reason ended_all; one alarm with the
// count), and records that it ran (kindOnce). A later start with the same
// date, a restart included, does nothing; the operator then unsets it.
// Invitations are not ended. It runs right after the load, before any
// reconnect, housekeeping or drain.
func (p *Peer) endAllOnce(ctx context.Context, now time.Time) error {
	date := p.cfg.EndAllConnections
	if date == "" {
		return nil
	}
	id := "end_all|" + date
	_, ran, err := p.cfg.Store.Get(ctx, kindOnce, id)
	if err != nil {
		return err
	}
	if ran {
		p.log().Warn("EndAllConnections already ran for this date: nothing done; unset it", "date", date)
		return nil
	}
	var all []*Connection
	for _, c := range p.conns {
		all = append(all, c)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	for _, c := range all {
		if err := p.endConnection(ctx, c, "connection_ended_all", RemovedEndAll, now); err != nil {
			return err // the run is not recorded: the next start ends the rest
		}
	}
	rec, _ := json.Marshal(map[string]any{"date": date, "at": now.UTC(), "count": len(all)})
	p.mark(kindOnce, id, rec, time.Time{})
	if err := p.flush(ctx); err != nil { // recorded once every connection is ended
		return err
	}
	p.log().Error("every connection ended by EndAllConnections: the members must connect again from new invitations",
		"alarm", "connections_ended", "date", date, "count", len(all))
	return nil
}
