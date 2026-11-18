package peer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// keptFixture is a peer with a ballot box and one signed-in member.
func keptFixture(t *testing.T) (*fixture, *recordVotes, *peertest.Member, string) {
	t.Helper()
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	rv.reqs = nil
	return f, rv, m, cid
}

func (f *fixture) casts(rv *recordVotes) []VoteRequest {
	var out []VoteRequest
	for _, r := range rv.reqs {
		if r.Type == typeVoteCast {
			out = append(out, r)
		}
	}
	return out
}

// The bound on kept keys covers a vote open at the removal until its
// count, and stays inside the inner ts allowance (BALLOT-PROTOCOL 0.14.2).
func TestKeptKeysBound(t *testing.T) {
	worst := vote.MaxWindow*time.Second + vote.MaxExtension*time.Second + unackedHold + time.Minute
	if KeptKeysFor < worst {
		t.Fatalf("KeptKeysFor %v under the worst case %v", KeptKeysFor, worst)
	}
	if KeptKeysFor >= envelope.MaxDurableAge {
		t.Fatalf("KeptKeysFor %v not under the durable ts allowance %v", KeptKeysFor, envelope.MaxDurableAge)
	}
	if KeptRecordFor <= KeptKeysFor {
		t.Fatal("the tombstone outlives the keys")
	}
}

// receiveOnly's keyring opens but can't send or rekey, and every epoch is
// kept until the bound.
func TestReceiveOnlyKeyring(t *testing.T) {
	f, _, m, cid := keptFixture(t)
	c := f.p.conns[cid]
	until := f.clk.Now().Add(KeptKeysFor)
	kr, err := receiveOnly(c.kr.Export(), until)
	if err != nil {
		t.Fatal(err)
	}
	if kr.Current() != nil || kr.Pending() != nil {
		t.Fatal("a current or pending epoch kept")
	}
	st := kr.Export()
	if len(st.Retired) == 0 {
		t.Fatal("no epoch kept")
	}
	for _, r := range st.Retired {
		if r.Epoch.SendKey != nil || r.Epoch.RK != nil || !r.Until.Equal(until) {
			t.Fatalf("kept epoch can send or rekey, or another bound: %+v until %v", r.Epoch.ID, r.Until)
		}
		e, err := handshake.ImportEpoch(r.Epoch)
		if err != nil || e.CanSend() || e.HasRK() {
			t.Fatalf("imported epoch can send %v or rekey %v (%v)", e != nil && e.CanSend(), e != nil && e.HasRK(), err)
		}
	}
	// It opens what the member seals now.
	raw, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: typeVoteCast, TS: f.clk.Now(), Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kr.Open(env, f.clk.Now()); err != nil {
		t.Fatalf("the receive-only keyring doesn't open: %v", err)
	}
	// The live keyring is untouched.
	if c.kr.Current() == nil || !c.kr.Current().CanSend() {
		t.Fatal("the live keyring lost its send key")
	}
}

// An outage backlog across an operator removal: a vote.cast the relay
// received before the removal is still decrypted and goes to the box,
// with the removal's time, and is not answered.
func TestKeptBacklogAcrossRemoval(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send(typeVoteCast, []byte(`{"n":1}`)) // waits at the relay
	f.clk.Advance(time.Minute)
	removedAt := uint64(f.clk.Now().UnixMilli())
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	before := len(m.Received(typeVoteCast))
	f.pump()
	cs := f.casts(rv)
	if len(cs) != 1 {
		t.Fatalf("%d casts reached the box", len(cs))
	}
	r := cs[0]
	if r.ConnectionID != cid || r.Left != LeftRemovedOut || r.LeftAtMS != removedAt || r.MsgMS >= r.LeftAtMS || r.CredentialKey == nil {
		t.Fatalf("request %+v (removed at %d)", r, removedAt)
	}
	if len(m.Received(typeVoteCast)) != before {
		t.Fatal("a removed connection's cast was answered")
	}
	if _, live := f.p.conns[cid]; live {
		t.Fatal("the removed connection is live")
	}
	for _, id := range f.p.Eligible() {
		if id == cid {
			t.Fatal("a kept connection is eligible")
		}
	}
}

// An inbound removal is timed by its message's relay time, not by when
// the service handles it: a copy's cast deposited after the removal, and
// handled in the same backlog, carries a msg_ms at or after the leave.
func TestKeptInboundRemovalRelayTime(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send(typeVoteCast, []byte(`{"n":1}`))
	f.clk.Advance(time.Second)
	removalSent := uint64(f.clk.Now().UnixMilli())
	m.Send(peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody())
	f.clk.Advance(time.Minute)
	m.Send(typeVoteCast, []byte(`{"n":2}`)) // a copy, after the removal
	f.clk.Advance(2 * time.Hour)            // the backlog is handled later
	f.pump()
	cs := f.casts(rv)
	if len(cs) != 2 {
		t.Fatalf("%d casts reached the box", len(cs))
	}
	if cs[0].LeftAtMS != 0 {
		t.Fatalf("the first cast, while connected: %+v", cs[0])
	}
	k := f.p.kept[cid]
	if k == nil || k.Kind != LeftRemovedIn || k.LeftAtMS < removalSent || k.LeftAtMS > removalSent+1000 {
		t.Fatalf("kept %+v, removal sent near %d", k, removalSent)
	}
	if cs[1].LeftAtMS != k.LeftAtMS || cs[1].MsgMS < cs[1].LeftAtMS || cs[1].Left != LeftRemovedIn {
		t.Fatalf("the copy's cast %+v", cs[1])
	}
}

// Only a vote.cast passes a kept record: nothing else reaches the box or
// changes anything, and a deposit under another token is refused.
func TestKeptGate(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send("vote.status", []byte(`{}`))
	m.Send(peerwire.TypeProfileUpdate, m.ProfileBody(9))
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	f.pump()
	if len(rv.reqs) != 0 {
		t.Fatalf("%d requests reached the box", len(rv.reqs))
	}
	if n := strings.Count(f.logs.String(), "kept_type_refused"); n != 2 {
		t.Fatalf("%d refusals logged", n)
	}
}

// A deposit under another token than the connection's frozen standing
// ones is refused by a kept record.
func TestKeptGateToken(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send(typeVoteCast, []byte(`{}`))
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	f.p.kept[cid].JTIs = []string{"another"}
	f.pump()
	if len(rv.reqs) != 0 || !strings.Contains(f.logs.String(), "kept_token_refused") {
		t.Fatal("a cast under another token passed")
	}
}

// The kept record survives a restart, and its keys are destroyed at the
// bound, its tombstone forgotten at KeptRecordFor.
func TestKeptRestartAndBounds(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send(typeVoteCast, []byte(`{"n":1}`)) // queued before the removal
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	f.start() // a restart before the backlog is collected
	k := f.p.kept[cid]
	if k == nil || k.kr == nil {
		t.Fatal("the kept record or its keys lost at a restart")
	}
	f.pump()
	if len(f.casts(rv)) != 1 {
		t.Fatal("a queued cast after a restart didn't reach the box")
	}
	// A second removal's backlog, still queued when the keys' bound
	// passes, is not opened.
	f2, rv2, m2, cid2 := keptFixture(t)
	m2.Send(typeVoteCast, []byte(`{"n":2}`))
	if err := f2.p.Remove(context.Background(), cid2); err != nil {
		t.Fatal(err)
	}
	f2.clk.Advance(KeptKeysFor)
	f2.tick()
	if k := f2.p.kept[cid2]; k == nil || k.kr != nil || k.Keyring != nil {
		t.Fatal("kept keys not destroyed at the bound")
	}
	if l := f2.p.Left([]string{cid2})[cid2]; !l.Known || l.Kind != LeftRemovedOut {
		t.Fatalf("the tombstone %+v", l)
	}
	f2.pump()
	if len(f2.casts(rv2)) != 0 {
		t.Fatal("a cast reached the box after the keys' bound")
	}
	f.clk.Advance(KeptKeysFor)
	f.tick()
	// A restart past the bound keeps no keys either.
	f.start()
	if k := f.p.kept[cid]; k == nil || k.kr != nil {
		t.Fatal("keys back after a restart")
	}
	f.clk.Advance(KeptRecordFor - KeptKeysFor)
	f.tick()
	if _, ok := f.p.kept[cid]; ok {
		t.Fatal("the tombstone kept past KeptRecordFor")
	}
	if l := f.p.Left([]string{cid})[cid]; l.Known {
		t.Fatalf("a forgotten leave reported known: %+v", l)
	}
}

// A suspended connection keeps a tombstone only: its time stays first,
// through a later removal, and nothing of it is accepted.
func TestKeptSuspended(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	c := f.p.conns[cid]
	f.p.suspendFor(c, SuspendEpoch, f.clk.Now())
	suspendedAt := c.SuspendedAtMS
	if suspendedAt == 0 {
		t.Fatal("no suspension time")
	}
	if l := f.p.Left([]string{cid})[cid]; !l.Known || l.Kind != LeftSuspended || l.AtMS != suspendedAt {
		t.Fatalf("left %+v", l)
	}
	f.clk.Advance(time.Hour)
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	k := f.p.kept[cid]
	if k == nil || k.kr != nil || k.Keyring != nil || k.Kind != LeftSuspended || k.LeftAtMS != suspendedAt {
		t.Fatalf("kept %+v", k)
	}
	m.IgnoreRevoked = true
	m.Send(typeVoteCast, []byte(`{}`))
	f.pump()
	if len(f.casts(rv)) != 0 {
		t.Fatal("a suspended connection's cast reached the box")
	}
}

// A stale connection is active for voting: its cast carries no leave.
func TestStaleCastsAsActive(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	f.p.conns[cid].State = StateStale
	m.Send(typeVoteCast, []byte(`{}`))
	f.pump()
	cs := f.casts(rv)
	if len(cs) != 1 || cs[0].LeftAtMS != 0 || cs[0].Left != "" {
		t.Fatalf("casts %+v", cs)
	}
	if _, listed := f.p.Left([]string{cid})[cid]; listed {
		t.Fatal("a stale connection listed as left")
	}
}

// A replaced connection's backlog: a cast sealed under the old
// connection's epoch, queued before the member connected again with the
// same keys, opens through the kept record (the live connection's
// keyring doesn't hold its kid) and is judged as the old connection's.
func TestKeptReplacedBacklog(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	sealedAt := f.clk.Now()
	old, err := m.KR.Current().Seal(&envelope.Inner{ID: m.NewID(), Type: typeVoteCast, TS: sealedAt, Body: []byte(`{"old":1}`)})
	if err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(time.Minute)
	// Only a stale or suspended connection is made afresh by a new
	// invitation (§7.4): the old one went stale.
	f.p.conns[cid].State = StateStale
	f.ms = nil
	m2 := f.member(10) // the same member's keys, connecting again: the old connection is replaced
	cid2 := f.connect(m2, "t")
	if cid2 == cid {
		t.Fatal("not a new connection")
	}
	if _, live := f.p.conns[cid]; live {
		t.Fatal("the old connection wasn't replaced")
	}
	k := f.p.kept[cid]
	if k == nil || k.Kind != LeftReplaced || k.kr == nil {
		t.Fatalf("kept %+v", k)
	}
	// The old cast arrives now, as a backlog the relay accepted under the
	// old standing token before the replacement.
	f.w.Redeliver(m2.SvcMailbox(), relayclient.Message{MsgID: f.ulid(sealedAt), Sender: relayauth.EncodeKey(k.RelayPK),
		JTI: k.JTIs[0], DepositedAt: sealedAt.UTC().Format(time.RFC3339Nano), Payload: old})
	f.pump()
	var got *VoteRequest
	for _, r := range f.casts(rv) {
		if string(r.Body) == `{"old":1}` {
			got = &r
		}
	}
	if got == nil {
		t.Fatalf("the old connection's backlog cast didn't reach the box: %s", tail600(f.logs.String()))
	}
	if got.ConnectionID != cid || got.Left != LeftReplaced || got.MsgMS >= got.LeftAtMS {
		t.Fatalf("judged as %+v", got)
	}
	if _, live := f.p.conns[cid2]; !live {
		t.Fatal("the new connection is gone")
	}
}

func tail600(s string) string { return s[max(0, len(s)-600):] }

// A start past the bound destroys kept keys that a store (a restore)
// still holds, before any message is handled.
func TestKeptPrunedAtStart(t *testing.T) {
	f, rv, m, cid := keptFixture(t)
	m.Send(typeVoteCast, []byte(`{}`)) // queued before the removal
	if err := f.p.Remove(context.Background(), cid); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(KeptKeysFor) // no housekeeping ran: the store still holds the keys
	f.start()
	if k := f.p.kept[cid]; k == nil || k.kr != nil {
		t.Fatal("keys past their bound kept at a start")
	}
	f.pump()
	if len(f.casts(rv)) != 0 {
		t.Fatal("a cast opened with keys past their bound")
	}
}
