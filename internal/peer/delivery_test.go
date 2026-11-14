package peer

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// A challenge sent while the service's reconnect is open is accepted and
// queued, not sent; it is sent at the reconnect's confirmation, and its
// state survives a restart in between.
func TestChallengeDeliveryQueuedThenSent(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	ctx := context.Background()
	sent, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := f.p.ChallengeDelivery(sent); d != DeliverySent {
		t.Fatalf("before the reconnect: %q", d)
	}
	f.pump() // the member collects it
	f.beginReconnectNow(cid)
	before := len(m.Received(peerwire.TypeConnAuthChallenge))
	req, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("during the reconnect: %q", d)
	}
	f.start() // reloaded from the store
	if d := f.p.ChallengeDelivery(req); d != DeliveryQueued {
		t.Fatalf("after a restart: %q", d)
	}
	f.pump()
	if c := f.p.conns[cid]; c.Reconnecting {
		t.Fatal("not confirmed")
	}
	if d := f.p.ChallengeDelivery(req); d != DeliverySent {
		t.Fatalf("after the confirmation: %q", d)
	}
	if n := len(m.Received(peerwire.TypeConnAuthChallenge)) - before; n != 1 {
		t.Fatalf("%d challenges reached the member", n)
	}
	if d := f.p.ChallengeDelivery("nope"); d != DeliveryNone {
		t.Fatalf("unknown: %q", d)
	}
}

// A queued challenge that leaves the outbox without being deposited is
// undelivered.
func TestChallengeDeliveryUndelivered(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	req, err := f.p.Authenticate(context.Background(), cid, "x", peerwire.PurposeApproval, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	f.p.dropUndelivered(f.p.conns[cid], "undelivered_suspended", nil)
	f.p.mu.Unlock()
	if d := f.p.ChallengeDelivery(req); d != DeliveryUndelivered {
		t.Fatalf("%q", d)
	}
	if err := f.p.flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.start()
	if d := f.p.ChallengeDelivery(req); d != DeliveryUndelivered {
		t.Fatalf("after a restart: %q", d)
	}
}

// A challenge cancelled while it waits in the outbox, never tried, is
// dropped there: neither it nor a withdraw reaches the member, and it
// holds no place at the member vault.
func TestCancelQueuedChallengeUnsent(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "")
	f.beginReconnectNow(cid)
	ctx := context.Background()
	req, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := f.p.CancelChallenge(ctx, req); err != nil || !ok {
		t.Fatalf("cancel %v %v", ok, err)
	}
	for _, e := range f.p.outbox {
		if e.Challenge == req {
			t.Fatal("still queued")
		}
	}
	if f.p.challenges[req] != nil || f.p.held(cid, f.clk.Now()) != 0 {
		t.Fatal("its place still counts")
	}
	f.pump()
	if f.p.conns[cid].Reconnecting {
		t.Fatal("not confirmed")
	}
	if n := len(m.Received(peerwire.TypeConnAuthChallenge)) + len(m.Received(peerwire.TypeConnAuthWithdraw)); n != 0 {
		t.Fatalf("%d challenges or withdraws reached the member", n)
	}
}
