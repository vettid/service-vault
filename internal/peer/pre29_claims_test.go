package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// storedField rewrites one member of a stored record's JSON (nil value:
// deleted), as an older image would have written it.
func (f *fixture) storedField(kind, id, name string, value any) {
	f.t.Helper()
	ctx := context.Background()
	b, ok, err := f.store.Get(ctx, kind, id)
	if err != nil || !ok {
		f.t.Fatalf("no %s record %s: %v", kind, id, err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		f.t.Fatal(err)
	}
	if value == nil {
		delete(m, name)
	} else {
		m[name], _ = json.Marshal(value)
	}
	b, _ = json.Marshal(m)
	if err := f.store.Apply(ctx, []Change{{Kind: kind, ID: id, Data: b}}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) onlyRequest() *request {
	f.t.Helper()
	if len(f.p.requests) != 1 {
		f.t.Fatalf("%d requests", len(f.p.requests))
	}
	for _, r := range f.p.requests {
		return r
	}
	return nil
}

// A claimed invitation not yet activated (a request) is ended by the
// one-shot SV_END_ALL_CONNECTIONS: its tokens are denied, the invitation
// ends, the application gets connection.expired with reason ended_all, and
// the member's approval afterwards makes no connection (the blind pair's
// reproduction, GC #10114).
func TestEndAllEndsRequests(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	inv := f.invite("")
	m.Accept(inv.Link, "")
	f.pump()
	r := f.onlyRequest()
	f.endAll = "2026-11-13"
	f.start()
	if len(f.p.requests) != 0 {
		t.Fatal("the request survived")
	}
	for _, tok := range f.p.issued {
		if tok.ConnID == r.ID && tok.Kind != tokOpen && !tok.Denied {
			t.Fatalf("token %s of the ended request not denied", tok.JTI)
		}
	}
	if got, _ := f.p.Invite(inv.ID); got.Status != InviteExpired {
		t.Fatalf("invitation %s", got.Status)
	}
	f.p.DeliverEvents(context.Background())
	ok := false
	for _, e := range f.ev.of(EventConnectionExpired) {
		ok = ok || e.ConnectionID == r.ID && e.Reason == RemovedEndAll
	}
	if !ok || !f.audited("request_ended_all") {
		t.Fatal("no connection.expired with the reason, or no audit")
	}
	m.IgnoreRevoked = true // its request token is revoked: the relay refuses the approval
	m.Approve()
	f.pump()
	if len(f.p.conns) != 0 {
		t.Fatal("an ended request became a connection")
	}
}

// The pre29 sweep ends a request and a first contact's awaiting whose
// records lack the marker; ones written with it stay.
func TestPre29EndsUnmarkedClaims(t *testing.T) {
	f := newFixture(t)
	// A marked request, which stays.
	m3 := f.member(30)
	inv3 := f.invite("")
	m3.Accept(inv3.Link, "")
	f.pump()
	// A request, to be stored without the marker.
	m := f.member(10)
	inv := f.invite("")
	m.Accept(inv.Link, "")
	f.pump()
	var rID string
	for id, r := range f.p.requests {
		if r.InviteID == inv.ID {
			rID = id
		}
	}
	// A first contact's awaiting (hs.init answered, no hs.fin yet), to be
	// stored without the marker.
	m2 := f.member(20)
	inv2 := f.invite("")
	m2.Accept(inv2.Link, "")
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var awID string
	for id, aw := range f.p.awaiting {
		if aw.New != nil {
			awID = id
		}
	}
	// A marked awaiting, which stays.
	m4 := f.member(40)
	inv4 := f.invite("")
	m4.Accept(inv4.Link, "")
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatal(err)
	}
	var keepAw string
	for id, aw := range f.p.awaiting {
		if aw.New != nil && id != awID {
			keepAw = id
		}
	}
	if rID == "" || awID == "" || keepAw == "" {
		t.Fatal("setup")
	}
	f.storedField(kindRequest, rID, "messaging_release", nil)
	f.storedField(kindAwait, awID, "messaging_release", nil)
	f.start()
	if _, ok := f.p.requests[rID]; ok {
		t.Fatal("an unmarked request stayed")
	}
	if _, ok := f.p.awaiting[awID]; ok {
		t.Fatal("an unmarked awaiting stayed")
	}
	if _, ok := f.p.awaiting[keepAw]; !ok {
		t.Fatal("a marked awaiting was ended")
	}
	if len(f.p.requests) != 1 || !f.audited("request_pre29_ended") || !f.audited("awaiting_pre29_ended") {
		t.Fatalf("%d requests left", len(f.p.requests))
	}
	for _, id := range []string{inv.ID, inv2.ID} {
		if got, _ := f.p.Invite(id); got.Status != InviteExpired {
			t.Fatalf("invitation %s: %s", id, got.Status)
		}
	}
}

// A connection that a relay.address.update moved, ended by the sweep, is
// sent no connection.removed: its stored address may be a copy's.
func TestPre29NoNoticeToMovedAddress(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.storedRelease(cid, 0)
	f.storedField(kindConn, cid, "prev_relay_pk", base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public().(ed25519.PublicKey)))
	f.start()
	f.pump()
	if _, ok := f.p.conns[cid]; ok {
		t.Fatal("not ended")
	}
	if len(m.Received("connection.removed")) != 0 {
		t.Fatal("connection.removed sent to an address a relay.address.update moved")
	}
}

// A date used before ends nothing and raises end_all_reused.
func TestEndAllReusedDateAlarm(t *testing.T) {
	f := newFixture(t)
	f.endAll = "2026-11-13"
	f.start()
	cid := f.connect(f.member(10), "")
	f.start()
	if _, ok := f.p.conns[cid]; !ok || !bytes.Contains([]byte(f.logs.String()), []byte("alarm=end_all_reused")) {
		t.Fatal("a reused date ended a connection, or raised no alarm")
	}
}
