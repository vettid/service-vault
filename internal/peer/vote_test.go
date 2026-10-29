package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// recordVotes answers every vote.* request with ok and records it.
type recordVotes struct {
	mu   sync.Mutex
	reqs []VoteRequest
	code string
	fail error // when set, the next request fails with it (a store error)
}

func (r *recordVotes) Vote(_ context.Context, req *VoteRequest) (VoteAnswer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.fail; err != nil {
		r.fail = nil
		return VoteAnswer{}, err
	}
	r.reqs = append(r.reqs, *req)
	return VoteAnswer{Code: r.code, Body: json.RawMessage(`{"ok":1}`)}, nil
}

// A member's vote.* request reaches Config.Votes with the connection's
// keys and the relay's time, and its answer goes back as the response.
func TestVoteRouted(t *testing.T) {
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv // as Config.Votes; f.votes keeps it across restarts
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	sent := f.clk.Now()
	id := m.Send("vote.status", []byte(`{"proposal_id":"01JBQZ0000000000000000000A"}`))
	f.pump()
	if len(rv.reqs) != 1 {
		t.Fatalf("%d requests reached the box", len(rv.reqs))
	}
	r := rv.reqs[0]
	if r.ConnectionID != cid || r.Type != "vote.status" || !r.Active || !r.PeerIK.Equal(m.IK.Public().(ed25519.PublicKey)) || r.CredentialKey == nil {
		t.Fatalf("request %+v", r)
	}
	if want := uint64(sent.UnixMilli()); r.MsgMS < want-1000 || r.MsgMS > want+1000 {
		t.Fatalf("msg_ms %d, deposited near %d", r.MsgMS, want)
	}
	var resp *envelope.Inner
	for _, in := range m.Received("vote.status") {
		if in.Re == id {
			resp = in
		}
	}
	if resp == nil || resp.Status != envelope.StatusOK || string(resp.Body) != `{"ok":1}` {
		t.Fatalf("response %+v", resp)
	}
	// An error code goes back as an error response.
	rv.code = "not_eligible"
	id = m.Send("vote.cast", []byte(`{}`))
	f.pump()
	found := false
	for _, in := range m.Received("vote.cast") {
		found = found || (in.Re == id && in.Status == envelope.StatusError && in.Error.Code == "not_eligible")
	}
	if !found {
		t.Fatal("no not_eligible response")
	}
}

// A ballot whose handling failed stays leased at the relay, out of every
// collect: until its lease is over, neither a later message nor an empty
// collect shows that the messages before the close were all handled
// (BALLOT-PROTOCOL §7). Nor does anything right after a start.
func TestCaughtWaitsOutLeases(t *testing.T) {
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	ctx := context.Background()
	f.clk.Advance(2 * time.Minute) // past the start's leases
	f.pump()
	if !f.p.Caught(f.clk.Now().Add(-time.Second)) {
		t.Fatal("not caught up with nothing leased")
	}

	rv.fail = errors.New("store down")
	m.Send("vote.cast", []byte(`{}`))
	m.Step()
	closeAt := f.clk.Now().Add(time.Millisecond)
	if _, err := f.p.Step(ctx, 0); err == nil {
		t.Fatal("the failed cast didn't fail the step")
	}
	f.clk.Advance(time.Second)
	m.Send("vote.status", []byte(`{}`)) // a later message, handled
	f.pump()
	if len(rv.reqs) != 1 || rv.reqs[0].Type != "vote.status" {
		t.Fatalf("requests %+v", rv.reqs)
	}
	if f.p.Caught(closeAt) {
		t.Fatal("caught up while the cast is still leased")
	}
	f.clk.Advance(30 * time.Second)
	f.pump()
	if f.p.Caught(closeAt) {
		t.Fatal("caught up before the lease is over")
	}
	f.clk.Advance(time.Minute)
	f.pump()
	if len(rv.reqs) != 2 || rv.reqs[1].Type != "vote.cast" {
		t.Fatalf("the cast wasn't redelivered: %+v", rv.reqs)
	}
	if !f.p.Caught(closeAt) {
		t.Fatal("not caught up once the cast was handled")
	}

	// A restart may leave leases behind: not caught up for one timeout.
	f.start()
	f.pump()
	if f.p.Caught(f.clk.Now()) {
		t.Fatal("caught up right after a start")
	}
	f.clk.Advance(2 * time.Minute)
	f.pump()
	if !f.p.Caught(f.clk.Now().Add(-time.Second)) {
		t.Fatal("not caught up a timeout after the start")
	}
}

// Without Config.Votes, a vote.* request is unsupported_type.
func TestVoteUnsupported(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	f.connect(m, "t")
	id := m.Send("vote.cast", []byte(`{}`))
	f.pump()
	for _, in := range m.Received("vote.cast") {
		if in.Re == id && in.Error != nil && in.Error.Code == "unsupported_type" {
			return
		}
	}
	t.Fatal("no unsupported_type response")
}

func TestULIDMS(t *testing.T) {
	if ms, err := ulidMS("01JBQZ0000000000000000000A"); err != nil || ms != 1730602336256 {
		t.Fatalf("ulidMS = %d, %v", ms, err)
	}
	if _, err := ulidMS("not a ulid"); err == nil {
		t.Fatal("accepted")
	}
}

// Eligible lists the active connections, and SendMessage reaches one.
func TestSendMessage(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	if got := f.p.Eligible(); len(got) != 1 || got[0] != cid {
		t.Fatalf("Eligible = %v", got)
	}
	id, err := f.p.SendMessage(context.Background(), cid, "vote.proposal", json.RawMessage(`{"proposal":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	got := m.Received("vote.proposal")
	if len(got) != 1 || got[0].ID != id || string(got[0].Body) != `{"proposal":"x"}` {
		t.Fatalf("received %v", got)
	}
	if _, err := f.p.SendMessage(context.Background(), "nope", "vote.proposal", nil); err != ErrNotFound {
		t.Fatalf("unknown connection: %v", err)
	}
	if _, err := f.p.SendMessage(context.Background(), cid, "Bad Type", nil); err == nil {
		t.Fatal("invalid type sent")
	}
}

// A sign-in challenge carries its purpose; a vault that knows purposes
// signs over it, and one that doesn't (release 23 and earlier) answers
// without, and both are approved (VAULT-MESSAGING 0.65.0 §10.4).
func TestChallengePurpose(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	if _, err := f.p.Authenticate(context.Background(), cid, "Sign in", "nonsense", time.Minute); err != ErrPurpose {
		t.Fatalf("an unknown purpose: %v", err)
	}
	for _, old := range []bool{false, true} {
		before := len(f.ev.of(EventSignInApproved))
		id, err := f.p.Authenticate(context.Background(), cid, "Sign in", peerwire.PurposeSignIn, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		f.pump()
		var ch *peerwire.ConnAuthChallenge
		for _, c := range m.Challenges {
			if c.RequestID == id {
				ch = c
			}
		}
		if ch == nil || ch.Purpose != peerwire.PurposeSignIn {
			t.Fatalf("challenge %+v", ch)
		}
		if old {
			ch.Purpose = "" // an older vault reads no purpose and signs without
		}
		r, err := peerwire.SignConnAuth(m.Cred, f.keys.IKPublic(), m.IK.Public().(ed25519.PublicKey), ch, f.clk.Now(), nil)
		if err != nil {
			t.Fatal(err)
		}
		m.Send(peerwire.TypeConnAuthResponse, r.Marshal())
		f.pump()
		if len(f.ev.of(EventSignInApproved)) != before+1 {
			t.Fatalf("old vault %v: not approved", old)
		}
	}
}
