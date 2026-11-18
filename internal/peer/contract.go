package peer

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Contract is the major.minor of VAULT-SERVICE-CONTRACT this release
// implements, sent as `contract` in every profile.update (VAULT-MESSAGING
// §10.8, 0.90.10). It is informational: nothing here selects behavior,
// relaxes a check or holds a connection by it, ours or a member's
// (VAULT-SERVICE-CONTRACT §1, §5.2).
const Contract = "1.0"

// contractForm is §10.8's form: two decimal numbers without leading zeros,
// each at most four digits, joined by a dot.
var contractForm = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})\.(0|[1-9][0-9]{0,3})$`)

// parseContract reads a profile.update's `contract` (§10.8 "Receiving"):
// absent is "", ok. A value of another JSON type or form is ignored as if
// absent ("", ok false, for the audit); the update itself is still applied.
func parseContract(raw json.RawMessage) (contract string, ok bool) {
	if raw == nil {
		return "", true
	}
	var s string
	if json.Unmarshal(raw, &s) != nil || !contractForm.MatchString(s) {
		return "", false
	}
	return s, true
}

// profileBody is the service's profile.update at version (§10.8): its
// names and identity key, no items, its features and its contract.
func (p *Peer) profileBody(version uint64) []byte {
	return peerwire.ProfileUpdateBody(version, p.cfg.Profile.FirstName, p.cfg.Profile.LastName, p.cfg.Keys.IKPublic(), profileExtras)
}

// sendProfile queues the service's profile.update at version to c and, once
// it is queued, records what was sent. It reports whether it was queued.
func (p *Peer) sendProfile(c *Connection, version uint64, now time.Time) bool {
	if p.sendTo(c, peerwire.TypeProfileUpdate, p.profileBody(version), now) == "" {
		return false
	}
	c.SentProfileVersion, c.SentContract = version, Contract
	p.markDirty(kindConn, c.ID)
	return true
}

// sendContract sends an active connection the service's profile.update
// with its next version when the contract last sent to it differs from
// this release's, a value never sent included (§10.8 "Sending"): at the
// first start under such a release, and again at each housekeeping until
// it is queued; once queued it is retried with the connection's other
// messages (the outbox). While the connection's outbox is full it is not
// tried: outbox_full is logged once for it (outboxFull) rather than at
// every housekeeping, and every other send still logs its own refusal.
func (p *Peer) sendContract(c *Connection, now time.Time) {
	if c.SentContract == Contract {
		delete(p.outboxFull, c.ID)
		return
	}
	if p.outboxFor(c.ID) >= MaxOutboxPerConn {
		if !p.outboxFull[c.ID] {
			p.outboxFull[c.ID] = true
			p.audit("outbox_full", c.ID)
		}
		return
	}
	delete(p.outboxFull, c.ID)
	p.sendProfile(c, nextProfileVersion(c, now), now)
}

// nextProfileVersion is the version of the service's next profile.update
// to c after the one at activation: one more than the last sent (a record
// from before contract was sent version 1 at activation), and at least
// now in Unix seconds. The member's vault keeps an update only when its
// version is higher than the last it applied (§10.8 "Receiving" step 1),
// and the count kept here can go back: a rollback to a release without it
// rewrites the record without it, and a restore brings back an older one.
// Counting from the clock keeps a later update above what an earlier
// record sent (chosen; §10.8 asks only for a higher version, at most
// 2^53−1).
func nextProfileVersion(c *Connection, now time.Time) uint64 {
	return max(max(c.SentProfileVersion, 1)+1, uint64(max(now.Unix(), 0)))
}
