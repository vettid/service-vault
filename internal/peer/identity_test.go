package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	wrongKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{88}, 32))
	thirdKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
)

// setIdentityRecord stores the table's identity record naming ik.
func setIdentityRecord(t *testing.T, st *MemStore, ik ed25519.PublicKey) {
	t.Helper()
	b, _ := json.Marshal(identityRecord{IK: ik})
	if err := st.Apply(context.Background(), []Change{{Kind: kindIdentity, ID: identityID, Data: b}}); err != nil {
		t.Fatal(err)
	}
}

// recordedIdentity is the key the table's identity record names (nil:
// none).
func recordedIdentity(t *testing.T, st *MemStore) ed25519.PublicKey {
	t.Helper()
	b, ok, err := st.Get(context.Background(), kindIdentity, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return nil
	}
	var r identityRecord
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.IK
}

// heldStart starts under ik, which must not be the table's: Start fails
// with ErrIdentityMismatch, and the store and the relay are untouched.
func heldStart(t *testing.T, f *fixture, ik ed25519.PrivateKey) {
	t.Helper()
	right := f.keys.IK
	defer func() { f.keys.IK = right }()
	f.keys.IK = ik
	before := f.backup()
	deposits := 0
	f.failDeposit = func(string, string) error { deposits++; return nil }
	defer func() { f.failDeposit = nil }()
	err := f.startErr()
	var m *IdentityMismatch
	if !errors.Is(err, ErrIdentityMismatch) || !errors.As(err, &m) || !bytes.Equal(m.Configured, ik.Public().(ed25519.PublicKey)) {
		t.Fatalf("Start under another key: %v", err)
	}
	if !reflect.DeepEqual(before.m, f.store.m) {
		t.Fatal("the store changed while held")
	}
	if deposits != 0 {
		t.Fatalf("%d deposits while held", deposits)
	}
	if len(f.p.conns) != 0 || len(f.p.outgoing) != 0 {
		t.Fatal("state read into the held peer")
	}
}

// The first start writes the table's identity record from the configured
// key; it survives restarts unchanged.
func TestIdentityRecordWritten(t *testing.T) {
	f := newFixture(t)
	if got := recordedIdentity(t, f.store); !bytes.Equal(got, f.keys.IKPublic()) {
		t.Fatalf("record %x", got)
	}
	f.member(10)
	f.connect(f.ms[0], "")
	f.start()
	f.start()
	if got := recordedIdentity(t, f.store); !bytes.Equal(got, f.keys.IKPublic()) {
		t.Fatalf("record after restarts %x", got)
	}
}

// A table from before the record: the first start writes it from the
// configured key when nothing stored names another; a stored handshake of
// the service's under another key is a mismatch, and nothing is written.
func TestIdentityOldTable(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	drop := func() {
		if err := f.store.Apply(context.Background(), []Change{{Kind: kindIdentity, ID: identityID}}); err != nil {
			t.Fatal(err)
		}
	}
	drop()
	f.start()
	if got := recordedIdentity(t, f.store); !bytes.Equal(got, f.keys.IKPublic()) {
		t.Fatalf("not written from the configured key: %x", got)
	}
	// A rekey of the service's, stored, then the record lost.
	f.failDeposit = func(string, string) error { return errUnavailable }
	f.p.startRekey(f.p.conns[cid], f.clk.Now())
	f.p.Step(context.Background(), 0)
	f.failDeposit = nil
	drop()
	heldStart(t, f, wrongKey)
	if got := recordedIdentity(t, f.store); got != nil {
		t.Fatalf("written while the state names another key: %x", got)
	}
	f.start() // the right key: the record written again, the rekey goes on
	if len(f.p.outgoing) != 1 {
		t.Fatalf("%d outgoing after the right key", len(f.p.outgoing))
	}
	if got := recordedIdentity(t, f.store); !bytes.Equal(got, f.keys.IKPublic()) {
		t.Fatalf("record after the right key: %x", got)
	}
}

// A table from before the record whose only handshake of the service's is
// a pending epoch (hs.resp taken, not yet confirmed): its own key decides.
func TestIdentityOldTablePending(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ctx := context.Background()
	f.p.startRekey(f.p.conns[cid], f.clk.Now())
	f.p.Step(ctx, 0) // the hs.init goes
	m.Step()         // the member answers hs.resp
	f.p.Step(ctx, 0) // taken: a pending epoch, its hs.fin queued
	if c := f.p.conns[cid]; c.Pending == nil || len(f.p.outgoing) != 0 {
		t.Fatalf("pending %v, %d outgoing", c.Pending != nil, len(f.p.outgoing))
	}
	if err := f.store.Apply(ctx, []Change{{Kind: kindIdentity, ID: identityID}}); err != nil {
		t.Fatal(err)
	}
	heldStart(t, f, wrongKey)
	if got := recordedIdentity(t, f.store); got != nil {
		t.Fatalf("written while a pending epoch names another key: %x", got)
	}
	f.start()
	if c := f.p.conns[cid]; c.Pending == nil {
		t.Fatal("the pending epoch was lost")
	}
}

// racingStore answers the first Get of the identity record "absent" and
// then has another task write it, with its own key, before our write.
type racingStore struct {
	*MemStore
	other ed25519.PublicKey
	raced bool
}

func (s *racingStore) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	if kind == kindIdentity && !s.raced {
		s.raced = true
		b, _ := json.Marshal(identityRecord{IK: s.other})
		if err := s.MemStore.Apply(ctx, []Change{{Kind: kindIdentity, ID: identityID, Data: b}}); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	return s.MemStore.Get(ctx, kind, id)
}

// A record written by another task between our read and our write wins:
// the write is conditional, and the key it names is compared.
func TestIdentityRecordRace(t *testing.T) {
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	st := &racingStore{MemStore: NewMemStore(), other: wrongKey.Public().(ed25519.PublicKey)}
	var m *IdentityMismatch
	if err := CheckIdentity(context.Background(), st, ik); !errors.As(err, &m) || m.From != "record" {
		t.Fatalf("raced write: %v", err)
	}
	if got := recordedIdentity(t, st.MemStore); !bytes.Equal(got, wrongKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("the other task's record was overwritten: %x", got)
	}
}

// A record that can't be read holds, as a mismatch, rather than being
// trusted or failing the start.
func TestIdentityRecordUnreadable(t *testing.T) {
	st := NewMemStore()
	if err := st.Apply(context.Background(), []Change{{Kind: kindIdentity, ID: identityID, Data: []byte(`{"ik":"AAAA"}`)}}); err != nil {
		t.Fatal(err)
	}
	var m *IdentityMismatch
	if err := CheckIdentity(context.Background(), st, wrongKey); !errors.As(err, &m) || m.From != "unreadable" {
		t.Fatalf("unreadable record: %v", err)
	}
}

// A table from before the record whose stored events name another key
// (a sign-in's carries the challenger's) holds, with nothing written.
func TestIdentityOldTableEvents(t *testing.T) {
	st := NewMemStore()
	b, _ := json.Marshal(map[string]any{"id": "e1", "type": "signin.completed", "service_ik": thirdKey.Public().(ed25519.PublicKey)})
	if err := st.Apply(context.Background(), []Change{{Kind: kindEvent, ID: "e1", Data: b}}); err != nil {
		t.Fatal(err)
	}
	var m *IdentityMismatch
	if err := CheckIdentity(context.Background(), st, wrongKey); !errors.As(err, &m) || m.From != "state" ||
		!bytes.Equal(m.Recorded, thirdKey.Public().(ed25519.PublicKey)) {
		t.Fatalf("events naming another key: %v", err)
	}
	if got := recordedIdentity(t, st); got != nil {
		t.Fatalf("written: %x", got)
	}
	if err := CheckIdentity(context.Background(), st, thirdKey); err != nil {
		t.Fatalf("the events' own key: %v", err)
	}
}

// Right, then a start under another key (held, nothing changed or sent),
// then the right key again: everything goes on, no try spent.
func TestIdentityRightWrongRight(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	heldStart(t, f, wrongKey)
	f.start()
	c := f.p.conns[cid]
	if c.Reconnecting || c.ReconnectTries != 0 {
		t.Fatalf("reconnecting %v, tries %d", c.Reconnecting, c.ReconnectTries)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the right key came back")
	}
	if strings.Contains(f.logs.String(), "alarm=outgoing_identity_changed") {
		t.Fatal("a stored handshake was dropped")
	}
}

// A restore started under the wrong key holds: the restore marker stays,
// no reconnect starts. Under the right key the restore's start runs as
// usual: exactly one try, which completes.
func TestIdentityWrongAtRestoreThenRight(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.store = b
	cleared := 0
	f.afterRestore = func(context.Context) error { cleared++; return nil }
	heldStart(t, f, wrongKey)
	if cleared != 0 {
		t.Fatal("the restore marker was cleared while held")
	}
	f.start()
	f.afterRestore = nil
	c := f.p.conns[cid]
	if cleared != 1 || !c.Reconnecting || c.ReconnectTries != 1 || len(f.p.outgoing) != 1 {
		t.Fatalf("cleared %d, reconnecting %v, tries %d, %d outgoing", cleared, c.Reconnecting, c.ReconnectTries, len(f.p.outgoing))
	}
	f.pump()
	c = f.p.conns[cid]
	if c.Reconnecting || c.kr.Current().ID() != m.KR.Current().ID() {
		t.Fatalf("not reconnected: reconnecting %v", c.Reconnecting)
	}
	if !f.signIn(m, cid) {
		t.Fatal("sign-in after the reconnect")
	}
}

// A reconnect open when the key goes wrong, then a third key: held both
// times, nothing spent. The try keeps its own clock, so once the right
// key is back past ReconnectTimeout it ends as any unanswered try does
// and the next one starts: the second try, not a fourth.
func TestIdentityThirdKeyHeldTryEndsAtTimeout(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	b := f.backup()
	m.StartRekey()
	f.pump()
	f.restore(b, true) // the first try, which the member never answers
	if c := f.p.conns[cid]; c.ReconnectTries != 1 || len(f.p.outgoing) != 1 {
		t.Fatalf("tries %d, %d outgoing", c.ReconnectTries, len(f.p.outgoing))
	}
	heldStart(t, f, wrongKey)
	heldStart(t, f, thirdKey)
	f.clk.Advance(ReconnectTimeout + time.Minute)
	heldStart(t, f, thirdKey)
	f.start()
	c := f.p.conns[cid]
	if !strings.Contains(f.logs.String(), "reason=reconnect_try_expired") || !c.Reconnecting || c.ReconnectTries != 2 {
		t.Fatalf("expired %v, reconnecting %v, tries %d", strings.Contains(f.logs.String(), "reason=reconnect_try_expired"), c.Reconnecting, c.ReconnectTries)
	}
}
