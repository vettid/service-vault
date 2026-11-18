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
	n, err := p.endEvery(ctx, func(release int) bool { return release < MessagingRelease }, "pre29_ended", RemovedPre29, now)
	if err != nil || n == 0 {
		return err
	}
	p.log().Error("connections from before release 29 ended: the members must connect again from new invitations",
		"alarm", "pre29_ended", "count", n)
	return nil
}

// endEvery ends, at a start, every connection, request (a connection
// between hs.fin and activation) and first contact's awaiting whose marker
// end selects: connections as endConnection does; requests and awaitings
// with their tokens denied and their invitation ended (connection.expired
// with the reason, for a request or an awaiting whose invitation the
// application knows). Each is stored in two writes, the record's deletion
// last. It returns how many it ended.
func (p *Peer) endEvery(ctx context.Context, end func(release int) bool, audit, reason string, now time.Time) (int, error) {
	var conns, reqs, aws []string
	for id, c := range p.conns {
		if end(c.MessagingRelease) {
			conns = append(conns, id)
		}
	}
	for id, r := range p.requests {
		if end(r.MessagingRelease) {
			reqs = append(reqs, id)
		}
	}
	for id, aw := range p.awaiting {
		if aw.New != nil && end(aw.MessagingRelease) {
			aws = append(aws, id)
		}
	}
	sort.Strings(conns)
	sort.Strings(reqs)
	sort.Strings(aws)
	for _, id := range conns {
		if c := p.conns[id]; c != nil {
			if err := p.endConnection(ctx, c, "connection_"+audit, reason, now); err != nil {
				return 0, err
			}
		}
	}
	for _, id := range reqs {
		r := p.requests[id]
		if r == nil {
			continue
		}
		err := p.endInTwoWrites(ctx, key{kindRequest, id}, func() {
			p.audit("request_"+audit, id)
			p.dropRequest(r, now)
			p.endInvite(r.InviteID, InviteExpired, now)
			p.emit(&Event{Type: EventConnectionExpired, ConnectionID: r.ID, InviteID: r.InviteID, Reason: reason}, now)
		})
		if err != nil {
			return 0, err
		}
	}
	for _, id := range aws {
		aw := p.awaiting[id]
		if aw == nil {
			continue
		}
		err := p.endInTwoWrites(ctx, key{kindAwait, id}, func() {
			p.audit("awaiting_"+audit, aw.ConnID)
			p.dropAwaiting(id, now) // its tokens denied, its invitation ended
		})
		if err != nil {
			return 0, err
		}
	}
	return len(conns) + len(reqs) + len(aws), nil
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
	return p.endInTwoWrites(ctx, key{kindConn, c.ID}, func() {
		p.audit(audit, c.ID)
		p.removeConnectionFor(c, "out", reason, now)
	})
}

// endInTwoWrites runs end, then stores what it changed in two writes: all
// but record k first, k (its deletion) last. A write that fails leaves k,
// so the next start ends it again. If a start stops between the two
// writes, that next start repeats the notice to the member and the
// application's event (README: applications treat a repeated
// connection.removed or connection.expired as one).
func (p *Peer) endInTwoWrites(ctx context.Context, k key, end func()) error {
	end()
	_, rec := p.dirty[k]
	delete(p.dirty, k)
	if err := p.flush(ctx); err != nil {
		return err
	}
	if rec {
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
		// The date identifies one run: a date used before does nothing. The
		// operator meant a run, so this is an alarm, not a note.
		p.log().Error("SV_END_ALL_CONNECTIONS names a date that already ran: nothing was ended; use a date not used before, or unset it",
			"alarm", "end_all_reused", "date", date)
		return nil
	}
	n, err := p.endEvery(ctx, func(int) bool { return true }, "ended_all", RemovedEndAll, now)
	if err != nil {
		return err // the run is not recorded: the next start ends the rest
	}
	rec, _ := json.Marshal(map[string]any{"date": date, "at": now.UTC(), "count": n})
	p.mark(kindOnce, id, rec, time.Time{})
	if err := p.flush(ctx); err != nil { // recorded once every connection is ended
		return err
	}
	p.log().Error("every connection ended by EndAllConnections: the members must connect again from new invitations",
		"alarm", "connections_ended", "date", date, "count", n)
	return nil
}
