package peer

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// queuedChallenge opens a reconnect of the service's on a new connection
// and sends an approval challenge on it, which waits in the outbox.
func queuedChallenge(t *testing.T, f *fixture) (cid, req string) {
	t.Helper()
	m := f.member(10)
	cid = f.connect(m, "")
	f.beginReconnectNow(cid)
	req, err := f.p.Authenticate(context.Background(), cid, "x", peerwire.PurposeApproval, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("%q", d)
	}
	return cid, req
}

// Queued, then sent at the reconnect's confirmation, in one process.
func TestChallengeQueuedThenSentOneProcess(t *testing.T) {
	f := newFixture(t)
	cid, req := queuedChallenge(t, f)
	m := f.ms[0]
	f.pump()
	if f.p.conns[cid].Reconnecting {
		t.Fatal("not confirmed")
	}
	if d := f.p.ChallengeDelivery(req); d != DeliverySent || len(m.Received(peerwire.TypeConnAuthChallenge)) != 1 {
		t.Fatalf("%q", d)
	}
	if got := f.p.ChallengeDeliveries([]string{req, "nope"}); got[req] != DeliverySent || got["nope"] != DeliveryNone {
		t.Fatalf("%v", got)
	}
}

// A queued challenge reloaded after a restart may have reached the relay
// (every waiting deposit is marked tried at load): its cancel withdraws
// it, and it is not dropped from the outbox.
func TestQueuedChallengeAfterRestartCancelWithdraws(t *testing.T) {
	f := newFixture(t)
	cid, req := queuedChallenge(t, f)
	m := f.ms[0]
	f.start()
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("after a restart: %q", d)
	}
	if ok, err := f.p.CancelChallenge(context.Background(), req); err != nil || !ok {
		t.Fatalf("cancel %v %v", ok, err)
	}
	carried := false
	for _, e := range f.p.outbox {
		carried = carried || e.Challenge == req
	}
	if !carried {
		t.Fatal("dropped from the outbox though it may have reached the relay")
	}
	f.pump()
	if f.p.conns[cid].Reconnecting {
		t.Fatal("not confirmed")
	}
	if len(m.Received(peerwire.TypeConnAuthChallenge)) != 1 || len(m.Received(peerwire.TypeConnAuthWithdraw)) != 1 {
		t.Fatal("not withdrawn")
	}
	if !strings.Contains(f.logs.String(), "withdrawn=true") {
		t.Fatal("log")
	}
}

// The entry carrying a queued challenge is sealed again at the reconnect's
// confirmation and still carries it: the challenge is queued until that
// entry is deposited.
func TestQueuedChallengeResealKeepsEntry(t *testing.T) {
	f := newFixture(t)
	cid, req := queuedChallenge(t, f)
	m := f.ms[0]
	before := append([]byte(nil), f.p.outboxByID(f.p.challenges[req].Entry).Payload...)
	f.failDeposit = func(string, string) error {
		if c := f.p.conns[cid]; c != nil && !c.Reconnecting {
			return errUnavailable // what follows the confirmation waits
		}
		return nil
	}
	f.pump()
	if f.p.conns[cid].Reconnecting {
		t.Fatal("not confirmed")
	}
	e := f.p.outboxByID(f.p.challenges[req].Entry)
	if e == nil || e.Challenge != req || bytes.Equal(e.Payload, before) {
		t.Fatalf("entry %+v", e)
	}
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("after the reseal: %q", d)
	}
	f.failDeposit = nil
	f.clk.Advance(time.Minute)
	f.pump()
	if d := f.p.ChallengeDelivery(req); d != DeliverySent || len(m.Received(peerwire.TypeConnAuthChallenge)) != 1 {
		t.Fatalf("%q", d)
	}
}

// failAuthDelete is the store failing the write that deletes one
// challenge's record: a crash at that point.
type failAuthDelete struct {
	*MemStore
	id string
}

func (s *failAuthDelete) Apply(ctx context.Context, cs []Change) error {
	for _, c := range cs {
		if c.Kind == kindAuth && c.ID == s.id && c.Data == nil {
			return errors.New("crash")
		}
	}
	return s.MemStore.Apply(ctx, cs)
}

// A crash between the cancel's two writes (the entry dropped, the record
// not yet deleted) leaves a challenge that is never delivered and keeps
// its place counted until its exp: never one delivered and uncounted.
func TestCancelUnsentCrashBetweenWrites(t *testing.T) {
	f := newFixture(t)
	cid, req := queuedChallenge(t, f)
	m := f.ms[0]
	w := &failAuthDelete{MemStore: f.store, id: req}
	f.p.cfg.Store = w
	if _, err := f.p.CancelChallenge(context.Background(), req); err == nil {
		t.Fatal("the failing write didn't fail the cancel")
	}
	f.start() // after the crash, from what was stored
	if d := f.p.ChallengeDelivery(req); d != DeliveryUndelivered {
		t.Fatalf("%q", d)
	}
	if n := f.p.held(cid, f.clk.Now()); n != 1 {
		t.Fatalf("%d places", n)
	}
	f.pump()
	if len(m.Received(peerwire.TypeConnAuthChallenge)) != 0 {
		t.Fatal("delivered after its cancel")
	}
}

// A split flush that stored the challenge as having left the outbox
// unsent, but not the entry's removal: at load the challenge waits with
// its entry again, may reach the member, and holds its place.
func TestSplitFlushReconciledAtLoad(t *testing.T) {
	f := newFixture(t)
	cid, req := queuedChallenge(t, f)
	m := f.ms[0]
	ch := f.p.challenges[req]
	ch.Entry, ch.Undelivered, ch.Unsent = "", true, true // as the first write of a split flush left it
	f.p.markDirty(kindAuth, req)
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("%q", d)
	}
	if n := f.p.held(cid, f.clk.Now()); n != 1 {
		t.Fatalf("%d places", n)
	}
	f.pump()
	if d := f.p.ChallengeDelivery(req); d != DeliverySent || len(m.Received(peerwire.TypeConnAuthChallenge)) != 1 {
		t.Fatalf("%q", d)
	}
}
