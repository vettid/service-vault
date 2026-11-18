package peer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// storedRelease rewrites the stored connection record's marker (0: none),
// as a record written before change 4c, or by an older image after a
// rollback, has it.
func (f *fixture) storedRelease(cid string, release int) {
	f.t.Helper()
	ctx := context.Background()
	b, ok, err := f.store.Get(ctx, kindConn, cid)
	if err != nil || !ok {
		f.t.Fatalf("no record: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		f.t.Fatal(err)
	}
	if string(m["messaging_release"]) != "29" {
		f.t.Fatalf("the record was written without the marker: %s", m["messaging_release"])
	}
	if release == 0 {
		delete(m, "messaging_release")
	} else {
		m["messaging_release"], _ = json.Marshal(release)
	}
	b, _ = json.Marshal(m)
	if err := f.store.Apply(ctx, []Change{{Kind: kindConn, ID: cid, Data: b}}); err != nil {
		f.t.Fatal(err)
	}
}

// RELEASE-29 §11 (U1): every connection record is written with the
// marker; at a start, one without it (or below 29) is ended before
// anything else: the member is sent connection.removed, the tokens issued
// for it are revoked, its waiting messages end audited, and the
// application gets connection.removed with the reason pre29. A connection
// with the marker, and an open invitation, stay.
func TestPre29EndedAtStart(t *testing.T) {
	for _, release := range []int{0, 28} {
		f := newFixture(t)
		m := f.member(10)
		old := f.connect(m, "")
		m2 := f.member(20)
		keep := f.connect(m2, "")
		inv := f.invite("later")
		f.p.sendTo(f.p.conns[old], "test.note", []byte(`{}`), f.clk.Now()) // waits: the member is not collected
		f.p.retryConn(old)
		f.failDeposit = func(string, string) error { return errUnavailable }
		f.p.drainOutbox(context.Background())
		if err := f.p.flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.failDeposit = nil
		f.storedRelease(old, release)
		revoked := len(f.revokes)
		f.start()
		if _, ok := f.p.conns[old]; ok {
			t.Fatalf("release %d: the old record was not ended", release)
		}
		if _, ok := f.p.conns[keep]; !ok {
			t.Fatal("a record with the marker was ended")
		}
		if _, ok := f.p.invites[inv.ID]; !ok {
			t.Fatal("an invitation was ended")
		}
		f.p.DeliverEvents(context.Background())
		var got *Event
		for _, e := range f.ev.of(EventConnectionRemoved) {
			if e.ConnectionID == old {
				got = e
			}
		}
		if got == nil || got.Reason != RemovedPre29 || got.Direction != "out" {
			t.Fatalf("connection.removed: %+v", got)
		}
		logs := f.logs.String()
		for _, want := range []string{"reason=connection_pre29_ended", "alarm=pre29_ended", "reason=undelivered_removed"} {
			if !strings.Contains(logs, want) {
				t.Fatalf("release %d: no %s", release, want)
			}
		}
		if len(f.revokes) <= revoked {
			t.Fatal("no token was revoked")
		}
		f.pump()
		if len(m.Received("connection.removed")) == 0 {
			t.Fatal("the member was not sent connection.removed")
		}
		if !f.signIn(m2, keep) {
			t.Fatal("the connection with the marker no longer works")
		}
	}
}

// A connection made under this version is written with the marker and
// survives a restart.
func TestMarkerWrittenAndKept(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.storedRelease(cid, 29) // checks the marker is there
	f.start()
	if _, ok := f.p.conns[cid]; !ok || f.audited("connection_pre29_ended") {
		t.Fatal("a record with the marker was ended")
	}

}

// The one-shot EndAllConnections (owner decision a, GC #10082): the first
// start that sees a date ends every connection (connection.removed with
// reason ended_all, audited, the alarm), invitations stay; a restart with
// the same date ends nothing more; a new date runs again.
func TestEndAllConnectionsOnce(t *testing.T) {
	f := newFixture(t)
	a := f.connect(f.member(10), "")
	b := f.connect(f.member(20), "")
	inv := f.invite("later")
	f.endAll = "2026-11-13"
	f.start()
	if len(f.p.conns) != 0 {
		t.Fatalf("%d connections left", len(f.p.conns))
	}
	if _, ok := f.p.invites[inv.ID]; !ok {
		t.Fatal("an invitation was ended")
	}
	f.p.DeliverEvents(context.Background())
	ended := map[string]bool{}
	for _, e := range f.ev.of(EventConnectionRemoved) {
		if e.Reason == RemovedEndAll && e.Direction == "out" {
			ended[e.ConnectionID] = true
		}
	}
	if !ended[a] || !ended[b] || !strings.Contains(f.logs.String(), "alarm=connections_ended") {
		t.Fatalf("ended %v", ended)
	}
	// A connection made after the run survives a restart with the same date.
	m := f.member(30)
	c := f.connect(m, "")
	n := strings.Count(f.logs.String(), "reason=connection_ended_all")
	f.start()
	if _, ok := f.p.conns[c]; !ok || strings.Count(f.logs.String(), "reason=connection_ended_all") != n {
		t.Fatal("the same date ran again")
	}
	if !f.signIn(m, c) {
		t.Fatal("the connection does not work after the restart")
	}
	// A new date runs again.
	f.endAll = "2026-11-14"
	f.start()
	if _, ok := f.p.conns[c]; ok {
		t.Fatal("a new date did not run")
	}
	// Unset: nothing happens.
	c2 := f.connect(f.member(40), "")
	f.endAll = ""
	f.start()
	if _, ok := f.p.conns[c2]; !ok {
		t.Fatal("ended without the setting")
	}
}
