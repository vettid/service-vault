package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// sentProfile is a profile.update the service sent, as the member read it.
type sentProfile struct {
	Version  uint64          `json:"version"`
	Features []string        `json:"features"`
	Contract json.RawMessage `json:"contract"`
}

// profilesTo lists the profile.update bodies m received, in order.
func profilesTo(t *testing.T, m *peertest.Member) []sentProfile {
	t.Helper()
	var out []sentProfile
	for _, in := range m.Received(peerwire.TypeProfileUpdate) {
		var b sentProfile
		if err := json.Unmarshal(in.Body, &b); err != nil {
			t.Fatalf("profile.update: %v", err)
		}
		out = append(out, b)
	}
	return out
}

// withMember returns a profile.update body with one more member, raw ("":
// left out).
func withMember(t *testing.T, body []byte, name, raw string) []byte {
	t.Helper()
	if raw == "" {
		return body
	}
	var o map[string]json.RawMessage
	if err := json.Unmarshal(body, &o); err != nil {
		t.Fatal(err)
	}
	o[name] = json.RawMessage(raw)
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The profile.update the service sends at activation carries contract
// "1.0" (VAULT-MESSAGING §10.8, 0.90.10); a restart under the same release
// sends nothing more.
func TestContractSentAtActivation(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	got := profilesTo(t, m)
	if len(got) != 1 || got[0].Version != 1 || string(got[0].Contract) != `"1.0"` ||
		!slices.Equal(got[0].Features, []string{"hs_confirm"}) {
		t.Fatalf("profile.update at activation: %+v", got)
	}
	if c := f.p.conns[cid]; c.SentProfileVersion != 1 || c.SentContract != Contract {
		t.Fatalf("sent: version %d, contract %q", c.SentProfileVersion, c.SentContract)
	}
	f.start()
	f.pump()
	if got := profilesTo(t, m); len(got) != 1 {
		t.Fatalf("a restart under the same contract sent %d updates", len(got))
	}
}

// At a start under a release whose contract differs from the one last
// sent (a value never sent included), each active connection gets an
// update with its next version, once (§10.8 "Sending"). The version is at
// least the clock's Unix seconds, so a record a rollback or a restore set
// back cannot send one the member's vault already holds.
func TestContractSentAtStartWhenDiffers(t *testing.T) {
	clock := uint64(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC).Unix()) // the fixture's clock
	for _, tc := range []struct {
		name        string
		lastVersion uint64
		lastSent    string
		want        uint64
	}{
		{"a record from before contract", 0, "", clock},
		{"another contract sent", 4, "0.9", clock},
		{"a version past the clock", clock + 10, "0.9", clock + 11},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			m := f.member(10)
			cid := f.connect(m, "")
			f.p.mu.Lock()
			c := f.p.conns[cid]
			c.SentProfileVersion, c.SentContract = tc.lastVersion, tc.lastSent
			f.p.markDirty(kindConn, cid)
			err := f.p.flush(context.Background())
			f.p.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			f.start()
			f.pump()
			got := profilesTo(t, m)
			if len(got) != 2 || got[1].Version != tc.want || string(got[1].Contract) != `"1.0"` {
				t.Fatalf("updates: %+v", got)
			}
			if c := f.p.conns[cid]; c.SentProfileVersion != tc.want || c.SentContract != Contract {
				t.Fatalf("sent: version %d, contract %q", c.SentProfileVersion, c.SentContract)
			}
			if name, _ := f.p.Connection(cid); name.Name == "" {
				t.Fatal("connection lost")
			}
			f.start()
			f.pump()
			f.clk.Advance(2 * time.Minute)
			if err := f.p.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.pump()
			if got := profilesTo(t, m); len(got) != 2 {
				t.Fatalf("sent again: %d updates", len(got))
			}
		})
	}
}

// The member's contract is kept from the profile.update applied, cleared
// by an applied update without one or with one of another type or form
// (which is still applied), and untouched by an update that is ignored
// (§10.8 "Receiving").
func TestPeerContract(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ik := m.IK.Public().(ed25519.PublicKey)
	step := 0
	for _, tc := range []struct {
		version   uint64
		raw       string
		want      string
		malformed bool
	}{
		{2, `"1.0"`, "1.0", false},
		{3, `"1.10"`, "1.10", false},
		{4, `1`, "", true},
		{5, `"9999.0"`, "9999.0", false},
		{6, `"01.0"`, "", true},
		{7, `"1.0.0"`, "", true},
		{8, `"1"`, "", true},
		{9, `"10000.0"`, "", true},
		{10, `null`, "", true},
		{11, `"0.0"`, "0.0", false},
		{12, ``, "", false},
		{13, `"2.3"`, "2.3", false},
		{13, `"3.0"`, "2.3", false}, // not a higher version: ignored
		{14, `["1.0"]`, "", true},
		{15, `" 1.0"`, "", true},
		{16, `"1.0\n"`, "", true},
		{17, `"1.01"`, "", true},
		{18, `"1.0"`, "1.0", false},
	} {
		step++
		last := "Step" + strings.Repeat("x", step)
		logs := len(f.logs.String())
		m.Send(peerwire.TypeProfileUpdate, withMember(t, peerwire.ProfileUpdateBody(tc.version, "Nora", last, ik, nil), "contract", tc.raw))
		f.pump()
		c := f.p.conns[cid]
		if c.PeerContract != tc.want {
			t.Fatalf("v%d %s: contract %q, want %q", tc.version, tc.raw, c.PeerContract, tc.want)
		}
		if ignored := c.ProfileVersion != tc.version || c.Peer.LastName != last; ignored && tc.raw != `"3.0"` {
			t.Fatalf("v%d %s: the update was not applied", tc.version, tc.raw)
		}
		if got := strings.Contains(f.logs.String()[logs:], "reason=profile_contract_malformed"); got != tc.malformed {
			t.Fatalf("v%d %s: audited %v", tc.version, tc.raw, got)
		}
	}
	f.start()
	if c := f.p.conns[cid]; c.PeerContract != "1.0" {
		t.Fatalf("not kept across a restart: %q", c.PeerContract)
	}
	// A dropped update changes nothing: a malformed core, another ik.
	other := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	for _, body := range [][]byte{
		peerwire.ProfileUpdateBody(19, "", "Empty", ik, nil),
		peerwire.ProfileUpdateBody(20, "Nora", "Other", other, nil),
	} {
		m.Send(peerwire.TypeProfileUpdate, withMember(t, body, "contract", `"2.0"`))
		f.pump()
		if c := f.p.conns[cid]; c.PeerContract != "1.0" || c.ProfileVersion != 18 {
			t.Fatalf("a dropped update changed: %q v%d", c.PeerContract, c.ProfileVersion)
		}
	}
}

// An update that cannot be queued (the outbox full) is not counted as
// sent, and goes at a later housekeeping.
func TestContractRetriedUntilQueued(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	p := f.p
	c := p.conns[cid]
	p.mu.Lock()
	c.SentContract = ""
	for p.outboxFor(cid) < MaxOutboxPerConn {
		p.queueDeposit(&outboxEntry{ConnID: cid, Mailbox: c.Peer.Relay.Mailbox, Payload: []byte("x"), NotBefore: f.clk.Now().Add(1000 * time.Hour)},
			f.clk.Now())
	}
	p.mu.Unlock()
	f.tick()
	f.pump()
	if c.SentContract != "" || len(profilesTo(t, m)) != 1 {
		t.Fatalf("counted as sent with the outbox full: %q", c.SentContract)
	}
	p.mu.Lock()
	p.outbox = slices.DeleteFunc(p.outbox, func(e *outboxEntry) bool { return string(e.Payload) == "x" })
	p.mu.Unlock()
	f.tick()
	f.pump()
	if got := profilesTo(t, m); len(got) != 2 || string(got[1].Contract) != `"1.0"` || c.SentContract != Contract {
		t.Fatalf("not sent once the outbox had room: %+v", got)
	}
}

// clearSent sets the connection back to a record from before contract, as
// stored.
func clearSent(t *testing.T, f *fixture, cid string) {
	t.Helper()
	f.p.mu.Lock()
	defer f.p.mu.Unlock()
	c := f.p.conns[cid]
	c.SentProfileVersion, c.SentContract = 0, ""
	f.p.markDirty(kindConn, cid)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A connection reconnecting at the start (after a restore) is not sent the
// update then, and is sent it at a later housekeeping once the reconnect
// has finished.
func TestContractAfterReconnect(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	clearSent(t, f, cid)
	b := f.backup()
	m.StartRekey()
	f.pump() // this process sends its update now
	before := len(profilesTo(t, m))
	f.restore(b, true) // the restored record has none sent, and reconnects
	if c := f.p.conns[cid]; !c.Reconnecting || c.SentContract != "" {
		t.Fatalf("at the start: reconnecting %v, sent %q", c.Reconnecting, c.SentContract)
	}
	f.pump()
	f.clk.Advance(2 * time.Minute)
	f.tick()
	f.pump()
	c := f.p.conns[cid]
	got := profilesTo(t, m)
	if c.Reconnecting || c.SentContract != Contract || len(got) != before+1 || string(got[len(got)-1].Contract) != `"1.0"` {
		t.Fatalf("after the reconnect: reconnecting %v, sent %q, %d updates (%d before)", c.Reconnecting, c.SentContract, len(got), before)
	}
}

// A queued update that the relay hasn't taken yet survives a restart in
// the outbox, and goes once the relay takes deposits; it is not queued a
// second time.
func TestContractQueuedSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	clearSent(t, f, cid)
	f.failDeposit = func(string, string) error { return errUnavailable }
	f.tick()
	f.start()
	if c := f.p.conns[cid]; c.SentContract != Contract || len(profilesTo(t, m)) != 1 {
		t.Fatalf("sent %q, %d updates", c.SentContract, len(profilesTo(t, m)))
	}
	queued := 0
	for _, e := range f.p.outbox {
		if e.ConnID == cid {
			queued++
		}
	}
	if queued != 1 {
		t.Fatalf("%d entries waiting after the restart", queued)
	}
	f.failDeposit = nil
	f.clk.Advance(time.Hour)
	f.tick()
	f.pump()
	if got := profilesTo(t, m); len(got) != 2 || string(got[1].Contract) != `"1.0"` {
		t.Fatalf("updates: %+v", got)
	}
}

// vote and approval_document are read from profile.update only: a later
// message's inner features never re-add a name a profile.update left out
// (§10.8, 0.90.10; VAULT-SERVICE-CONTRACT §5.3).
func TestWithdrawableFromProfileOnly(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	if !slices.Contains(f.p.Eligible(), cid) {
		t.Fatal("not eligible after its first profile.update")
	}
	ik := m.IK.Public().(ed25519.PublicKey)
	// An update without features, whose own inner features name vote.
	m.SendInner(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeProfileUpdate, TS: f.clk.Now(),
		Body: peerwire.ProfileUpdateBody(2, "Nora", "Withdrawn", ik, nil), Features: []string{"approval_document", "hs_confirm", "vote"}})
	f.pump()
	// Then another message whose inner features name both.
	m.SendInner(&envelope.Inner{ID: m.NewID(), Type: peerwire.TypeConnectionApproved, TS: f.clk.Now(),
		Body: json.RawMessage(`{}`), Features: []string{"approval_document", "hs_confirm", "vote"}})
	f.pump()
	c := f.p.conns[cid]
	if c.ProfileVersion != 2 || len(c.Features) != 0 {
		t.Fatalf("version %d, features %v", c.ProfileVersion, c.Features)
	}
	if slices.Contains(f.p.Eligible(), cid) {
		t.Fatal("vote re-added from an inner features list")
	}
}
