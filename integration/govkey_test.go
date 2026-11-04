//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/approval"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/internal/sealstore"
	"github.com/vettid/service-vault/internal/service"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// The governance key, the bootstrap state and the migration marker survive
// a restart through the real store: the peer and the approvals over the
// sealed records of DynamoDB, as production runs them. The first admin is
// confirmed by the operator, signs in, and their approvals count; a
// later key does not count, after a restart too. An admin written the old
// way (no governance key, no marker) migrates from evidence after a
// restart: the key of the earliest signed approval, not the current one.
func TestGovKeyAndMigrationOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	recKey, err := sealstore.NewRecordKey()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sealstore.New(tbl.Peer(), map[uint32][]byte{1: recKey.Key}, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Pages = tbl
	clk := peertest.NewClock(time.Now().UTC().Truncate(time.Millisecond))
	w := peertest.NewWorld(clk)
	keys, err := peer.KeysFromSeeds(peer.Seeds{IK: bytes.Repeat([]byte{1}, 32), KEM: bytes.Repeat([]byte{2}, 32),
		Relay: bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var p *peer.Peer
	var svc *service.Service
	var mgr *approval.Manager
	// create makes the process: the manager is up before the peer has
	// loaded its state; start loads it.
	create := func() {
		clk.Advance(time.Second) // audit ids order by time: a new process writes later ones
		svc = &service.Service{Store: sealed, ServiceName: "VettID Member Service", Now: clk.Now, Log: log}
		var err error
		if p, err = peer.New(peer.Config{Keys: keys, Relay: w.View(keys.Relay), RelayURL: peertest.RelayURL, Store: sealed,
			Events: svc, Now: clk.Now, Log: log, Profile: peer.Profile{FirstName: "VettID", LastName: "Member Service"}}); err != nil {
			t.Fatal(err)
		}
		svc.Peer = p
		mgr = &approval.Manager{Peer: p, Store: sealed, Pager: sealed, ServiceName: svc.ServiceName, Threshold: 1,
			BootstrapKey: "admin-key", BoundConnection: svc.BoundConnection, Now: clk.Now, Log: log}
		svc.Approvals = mgr
		if err := mgr.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	start := func() {
		if err := p.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	m := peertest.NewMember(t, w, 10)
	pump := func() {
		for i := 0; i < 50; i++ {
			n, err := p.Step(ctx, 0)
			if err != nil {
				t.Fatal(err)
			}
			n += m.Step()
			p.DeliverEvents(ctx)
			if n == 0 {
				return
			}
		}
	}
	create()
	start()
	inv, err := svc.Invites().Create(ctx, "admin-key")
	if err != nil {
		t.Fatal(err)
	}
	m.Accept(inv.URL[strings.IndexByte(inv.URL, '#')+1:], "")
	pump()
	m.Approve()
	pump()
	rec, ok := p.Invite(inv.ID)
	if !ok || rec.ConnID == "" {
		t.Fatalf("invitation %+v", rec)
	}
	cid := rec.ConnID

	// The connection waits for the operator, who confirms it from a
	// process of its own with the store only. The invitation it came
	// through is stored with the waiting state.
	if err := mgr.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	waiting, err := (&approval.Manager{Store: sealed}).BootstrapWaiting(ctx)
	if err != nil || waiting == nil || waiting.ConnectionID != cid || waiting.InviteID != inv.ID || waiting.ConnectedAt.IsZero() {
		t.Fatalf("waiting %+v %v (invitation %s)", waiting, err, inv.ID)
	}
	if a, _ := mgr.Admins(ctx); len(a.Admins) != 0 {
		t.Fatalf("admin before the confirmation: %v", a.Admins)
	}
	confirmBootstrap(t, ctx, sealed, cid)
	if err := mgr.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if a, _ := mgr.Admins(ctx); len(a.Admins) != 1 || a.Admins[0] != cid {
		t.Fatalf("admins %v", a.Admins)
	}

	approve := func(key ed25519.PrivateKey, n string) *approval.Status {
		t.Helper()
		c, err := mgr.Create(ctx, approval.Request{Action: approval.ActionContractTemplateChange, Summary: "Approval " + n, Payload: json.RawMessage(`{"n":` + n + `}`)})
		if err != nil {
			t.Fatal(err)
		}
		pump()
		clk.Advance(time.Second)
		r, err := peerwire.SignConnAuth(key, keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), m.Challenges[len(m.Challenges)-1], clk.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
		pump()
		s, err := mgr.Status(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The first signed response pins the governance key, and the admin's
	// approval counts.
	if s := approve(m.Cred, "1"); s.Status != approval.StatusApproved || len(s.Approvals) != 1 || !s.Approvals[0].Counted {
		t.Fatalf("first approval: %+v", s)
	}
	cred := m.Cred.Public().(ed25519.PublicKey)
	storedConn := func() map[string]json.RawMessage {
		t.Helper()
		recs, err := sealed.Load(ctx, "conn")
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range recs {
			if r.ID == cid {
				var v map[string]json.RawMessage
				if err := json.Unmarshal(r.Data, &v); err != nil {
					t.Fatal(err)
				}
				return v
			}
		}
		t.Fatal("no connection record")
		return nil
	}
	if _, ok := storedConn()["gov_key"]; !ok {
		t.Fatal("the stored connection has no gov_key")
	}
	// The raw DynamoDB item is sealed: nothing readable.
	raw, _ := tbl.Peer().Load(ctx, "conn")
	for _, r := range raw {
		if bytes.Contains(r.Data, []byte("gov_key")) || bytes.Contains(r.Data, []byte("auth_key")) {
			t.Fatal("the connection record is stored in the clear")
		}
	}
	// The migration marker and the bootstrap state are stored.
	if _, ok, err := sealed.Get(ctx, "gov_migrated", "done"); err != nil || !ok {
		t.Fatalf("no migration marker: %v %v", ok, err)
	}

	// A restart: the governance key is read back, and another key signing
	// a later approval does not count (key_changed, then not_repinned).
	create()
	start()
	if ci, ok := p.Connection(cid); !ok || !ed25519.PublicKey(ci.GovKey).Equal(cred) {
		t.Fatalf("governance key after the restart: %x", ci.GovKey)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	for i, want := range []string{approval.ReasonKeyChanged, approval.ReasonNotRepinned} {
		s := approve(other, string(rune('2'+i)))
		if s.Status != approval.StatusPending || len(s.Approvals) != 1 || s.Approvals[0].Counted || s.Approvals[0].Reason != want {
			t.Fatalf("approval with another key (%s): %+v", want, s)
		}
	}
	if ci, _ := p.Connection(cid); !ed25519.PublicKey(ci.AuthKey).Equal(other.Public().(ed25519.PublicKey)) ||
		!ed25519.PublicKey(ci.GovKey).Equal(cred) {
		t.Fatal("the pins after the other key's sign-ins")
	}

	// The old way: no governance key and no marker in the stored record. A
	// restart: the manager ticks before the peer has loaded and pins
	// nothing; once it has, the key of the earliest signed approval is
	// pinned, not the current one, and it is audited.
	v := storedConn()
	delete(v, "gov_key")
	data, _ := json.Marshal(v)
	if err := sealed.Apply(ctx, []peer.Change{{Kind: "conn", ID: cid, Data: data}, {Kind: "gov_migrated", ID: "done"}}); err != nil {
		t.Fatal(err)
	}
	create()
	if err := mgr.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if page, _ := mgr.Audit(ctx, "", 0); countType(page, approval.AuditGovKeyMigrated) != 0 {
		t.Fatal("pinned before the peer loaded")
	}
	start()
	if ci, _ := p.Connection(cid); len(ci.GovKey) != 0 {
		t.Fatalf("setup: governance key still stored: %x", ci.GovKey)
	}
	if err := mgr.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	ci, _ := p.Connection(cid)
	if !ed25519.PublicKey(ci.GovKey).Equal(cred) || ed25519.PublicKey(ci.AuthKey).Equal(cred) {
		t.Fatalf("migrated: gov %x auth %x", ci.GovKey, ci.AuthKey)
	}
	page, _ := mgr.Audit(ctx, "", 0)
	var got *approval.AuditEntry
	for i := range page.Entries {
		if page.Entries[i].Type == approval.AuditGovKeyMigrated {
			got = &page.Entries[i]
		}
	}
	if got == nil || got.ConnectionID != cid || got.Reason != approval.ReasonEvidence || !got.KeyChangesSeen || len(got.Fingerprint) != 16 {
		t.Fatalf("migration audit %+v", got)
	}
	if _, ok, _ := sealed.Get(ctx, "gov_migrated", "done"); !ok {
		t.Fatal("no migration marker after the migration")
	}
	// The current key needs a re-pin; the migrated one still counts.
	if s := approve(other, "4"); s.Approvals[0].Counted {
		t.Fatalf("the current key counts before a re-pin: %+v", s)
	}
	// A fifth ordinary approval within the day would find the admin at
	// the ask limit (4, the fifth being kept for repairs): a day later.
	clk.Advance(25 * time.Hour)
	if s := approve(m.Cred, "5"); s.Status != approval.StatusApproved || !s.Approvals[0].Counted {
		t.Fatalf("the migrated key does not count: %+v", s)
	}
}

func countType(p *approval.AuditPage, typ string) int {
	n := 0
	for _, e := range p.Entries {
		if e.Type == typ {
			n++
		}
	}
	return n
}
