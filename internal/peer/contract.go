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
// messages (the outbox). A record from before contract was sent version 1
// at activation.
func (p *Peer) sendContract(c *Connection, now time.Time) {
	if c.SentContract == Contract {
		return
	}
	if !p.sendProfile(c, max(c.SentProfileVersion, 1)+1, now) {
		p.audit("contract_update_unsent", c.ID)
	}
}
