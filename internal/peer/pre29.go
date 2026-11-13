package peer

import (
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
func (p *Peer) endPre29(now time.Time) {
	var old []*Connection
	for _, c := range p.conns {
		if c.MessagingRelease < MessagingRelease {
			old = append(old, c)
		}
	}
	if len(old) == 0 {
		return
	}
	sort.Slice(old, func(i, j int) bool { return old[i].ID < old[j].ID })
	for _, c := range old {
		p.audit("connection_pre29_ended", c.ID)
		p.removeConnectionFor(c, "out", RemovedPre29, now)
	}
	p.log().Error("connections from before release 29 ended: the members must connect again from new invitations",
		"alarm", "pre29_ended", "count", len(old))
}
