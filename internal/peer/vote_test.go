package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/peer/peertest"
	"github.com/vettid/vettid-relay/relayclient"
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
	if !f.caught(f.clk.Now().Add(-time.Second)) {
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
	if f.caught(closeAt) {
		t.Fatal("caught up while the cast is still leased")
	}
	f.clk.Advance(30 * time.Second)
	f.pump()
	if f.caught(closeAt) {
		t.Fatal("caught up before the lease is over")
	}
	f.clk.Advance(time.Minute)
	f.pump()
	if len(rv.reqs) != 2 || rv.reqs[1].Type != "vote.cast" {
		t.Fatalf("the cast wasn't redelivered: %+v", rv.reqs)
	}
	if !f.caught(closeAt) {
		t.Fatal("not caught up once the cast was handled")
	}

	// A restart may leave leases behind: not caught up for one timeout.
	f.start()
	f.pump()
	if f.caught(f.clk.Now()) {
		t.Fatal("caught up right after a start")
	}
	f.clk.Advance(2 * time.Minute)
	f.pump()
	if !f.caught(f.clk.Now().Add(-time.Second)) {
		t.Fatal("not caught up a timeout after the start")
	}
}

func (f *fixture) caught(t time.Time) bool {
	f.t.Helper()
	ok, _, err := f.p.Caught(context.Background(), t, time.Time{}, time.Time{}, t)
	if err != nil {
		f.t.Fatal(err)
	}
	return ok
}

// A message left unacked holds Caught false only for a time after it: a
// member can't stall a close with a message it keeps coming back with.
// Another process's leases hold it false until they are over.
func TestCaughtUnackedAndOtherProcess(t *testing.T) {
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	f.clk.Advance(time.Second)
	// After the close, a message left unacked again and again.
	rv.fail = errors.New("store down")
	m.Send("vote.status", []byte(`{}`))
	m.Step()
	if _, err := f.p.Step(context.Background(), 0); err == nil {
		t.Fatal("the failed message didn't fail the step")
	}
	f.clk.Advance(time.Second) // it is still leased
	m.Send("vote.status", []byte(`{}`))
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("a message after the close, still leased, held Caught false")
	}
	f.clk.Advance(2 * time.Minute) // redelivered and handled
	f.pump()
	// Another process leased messages a moment ago.
	data, _ := json.Marshal(leaseMark{At: f.clk.Now()})
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindLease, ID: "another", Data: data,
		Expires: f.clk.Now().Add(2 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	// This process leasing a batch meanwhile doesn't hide the other's.
	m.Send("vote.status", []byte(`{}`))
	f.pump()
	if f.caught(closeAt) {
		t.Fatal("caught up while another process's leases may be out")
	}
	f.clk.Advance(30 * time.Second)
	f.pump()
	if f.caught(closeAt) {
		t.Fatal("caught up before another process's leases are over")
	}
	f.clk.Advance(time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("not caught up after another process's leases")
	}
}

// A message left unacked holds Caught false at most MaxUnackedWait: a
// member can't keep a count waiting for the relay's whole TTL.
func TestCaughtUnackedCap(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	id, err := envelope.NewULID(closeAt.Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	f.p.mu.Lock()
	f.p.leaveUnacked(relayclient.Message{MsgID: id}, f.clk.Now())
	f.p.mu.Unlock()
	f.clk.Advance(time.Hour)
	f.pump()
	if f.caught(closeAt) {
		t.Fatal("caught up with a message before the close left unacked")
	}
	f.clk.Advance(MaxUnackedWait)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("still waiting past the cap")
	}
	if !strings.Contains(f.logs.String(), "no longer holds the count") {
		t.Fatal("the cap wasn't logged")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d, want the one given up on", n)
	}
	if n := f.unhandled(closeAt, closeAt.Add(-2*time.Hour), closeAt.Add(-time.Hour)); n != 0 {
		t.Fatalf("unhandled %d outside the window", n)
	}

	// Its redelivery doesn't start a new wait.
	f.leave(id)
	if !f.caught(closeAt) {
		t.Fatal("a redelivery after the cap holds the count again")
	}
	// It stays counted past the relay's TTL, which drops it unhandled.
	f.clk.Advance(15 * 24 * time.Hour)
	f.pump()
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d past the TTL, want 1", n)
	}
	f.clk.Advance(gaveUpKeep)
	f.pump()
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 0 {
		t.Fatalf("unhandled %d long after, want it forgotten", n)
	}
}

// Two overlapping messages left unacked, each redelivered every hour,
// each wait MaxUnackedWait from when they were first left.
func TestCaughtUnackedOverlap(t *testing.T) {
	for run := 0; run < 20; run++ {
		f := newFixture(t)
		f.clk.Advance(2 * time.Minute)
		f.pump()
		closeAt := f.clk.Now()
		a := f.ulid(closeAt.Add(-2 * time.Second))
		b := f.ulid(closeAt.Add(-time.Second))
		f.leave(a)
		f.clk.Advance(12 * time.Hour)
		f.leave(b)
		for h := 0; h < 30; h++ {
			f.clk.Advance(time.Hour)
			f.leave(a) // redelivered, also after its cap
			f.leave(b)
			f.pump()
			// a is capped 24 h after it was first left, b 24 h after; the
			// count waits for the later cap, 36 h after a.
			if got, want := f.caught(closeAt), h+1 >= 24; got != want {
				t.Fatalf("run %d, %d h after b: caught %v, want %v", run, h+1, got, want)
			}
		}
		if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 2 {
			t.Fatalf("unhandled %d, want 2", n)
		}
	}
}

// A message left unacked that the relay drops before the cap still
// counts as unhandled.
func TestCaughtUnackedTTL(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	ttl := time.Duration(f.p.limits.MessageTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 14 * 24 * time.Hour
	}
	// First left an hour before the relay drops it.
	id := f.ulid(closeAt.Add(-time.Second))
	f.clk.Advance(ttl - time.Hour)
	f.pump()
	f.leave(id)
	if f.caught(closeAt) {
		t.Fatal("caught up with a message before the close left unacked")
	}
	f.clk.Advance(2 * time.Hour)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("still waiting after the relay dropped it")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d, want the dropped one", n)
	}
}

func (f *fixture) ulid(at time.Time) string {
	f.t.Helper()
	id, err := envelope.NewULID(at)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fixture) leave(id string) {
	f.p.mu.Lock()
	f.p.leaveUnacked(relayclient.Message{MsgID: id}, f.clk.Now())
	f.p.mu.Unlock()
}

func (f *fixture) unhandled(t, from, until time.Time) int64 {
	f.t.Helper()
	_, n, err := f.p.Caught(context.Background(), t, time.Time{}, from, until)
	if err != nil {
		f.t.Fatal(err)
	}
	return n
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

// Eligible counts a connection by its last profile.update's features
// (VAULT-MESSAGING §10.19.1); Active lists every active one.
func TestEligibleByFeature(t *testing.T) {
	f := newFixture(t)
	a := f.member(10)
	ca := f.connect(a, "a")
	b := f.member(20)
	b.Features = nil // a vault before release 25
	cb := f.connect(b, "b")
	check := func(step string, want ...string) {
		t.Helper()
		got := f.p.Eligible()
		if !slices.Equal(got, want) {
			t.Fatalf("%s: Eligible = %v, want %v", step, got, want)
		}
		if act := f.p.Active(); len(act) != 2 {
			t.Fatalf("%s: Active = %v", step, act)
		}
	}
	check("connected", ca)
	f.start() // kept across a restart
	check("restarted", ca)
	profile := func(m *peertest.Member, v uint64, features ...string) {
		m.Features = features
		m.Send(peerwire.TypeProfileUpdate, m.ProfileBody(v))
		f.pump()
	}
	profile(a, 2)
	check("a's update without features")
	profile(a, 3, "vote", "calls")
	check("not sorted: none")
	profile(a, 4, "Vote")
	check("not a name: none")
	profile(b, 2, "calls", "vote")
	check("b now votes", cb)
	profile(b, 2)
	check("an old version changes nothing", cb)
}

// Eligible lists the active connections, and SendMessage reaches one.
func TestSendMessage(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	if got := f.p.Eligible(); len(got) != 1 || got[0] != cid {
		t.Fatalf("Eligible = %v", got)
	}
	id, err := f.p.SendMessage(context.Background(), cid, "vote.proposal", json.RawMessage(`{"proposal":"x"}`), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	got := m.Received("vote.proposal")
	if len(got) != 1 || got[0].ID != id || string(got[0].Body) != `{"proposal":"x"}` {
		t.Fatalf("received %v", got)
	}
	if _, err := f.p.SendMessage(context.Background(), "nope", "vote.proposal", nil, time.Time{}); err != ErrNotFound {
		t.Fatalf("unknown connection: %v", err)
	}
	if _, err := f.p.SendMessage(context.Background(), cid, "Bad Type", nil, time.Time{}); err == nil {
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

// A signed answer's event carries all that its signature covers, so the
// signature verifies from the event alone (§10.4).
func TestSignInEventEvidence(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	evs := f.ev.of(EventSignInApproved)
	e := evs[len(evs)-1]
	if !bytes.Equal(e.ServiceIK, f.keys.IKPublic()) || !bytes.Equal(e.MemberIK, m.IK.Public().(ed25519.PublicKey)) || len(e.Nonce) == 0 {
		t.Fatalf("evidence: nonce %x, service %x, member %x", e.Nonce, e.ServiceIK, e.MemberIK)
	}
	ch := &peerwire.ConnAuthChallenge{RequestID: e.RequestID, Nonce: e.Nonce, Context: e.Context, Purpose: e.Purpose}
	r := &peerwire.ConnAuthResponse{RequestID: e.RequestID, Status: peerwire.ConnAuthSigned, Key: e.Key, Sig: e.Signature,
		Purpose: e.Purpose, HasPurpose: e.Purpose != ""}
	if err := peerwire.VerifyConnAuthResponse(r, e.ServiceIK, e.MemberIK, ch); err != nil {
		t.Fatalf("the event's evidence doesn't verify: %v", err)
	}
}

// The messages left unacked are stored: a restart neither starts a
// message's wait again nor forgets the ones given up on.
func TestCaughtUnackedAcrossRestart(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	a, b := f.ulid(closeAt.Add(-2*time.Second)), f.ulid(closeAt.Add(-time.Second))
	f.leave(a)
	f.caught(closeAt) // stores it
	f.clk.Advance(MaxUnackedWait + time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("still waiting past the cap")
	}
	f.leave(b)
	f.caught(closeAt)

	f.start() // a restart: a fresh peer on the same store
	f.clk.Advance(2 * time.Minute)
	f.pump()
	f.leave(a) // redelivered after the restart
	f.leave(b)
	if f.caught(closeAt) {
		t.Fatal("b no longer holds the count after the restart")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d after the restart, want a", n)
	}
	// b's wait runs from when it was first left, not from the restart:
	// 24 h 1 min since then, 23 h 59 min since it was left again.
	f.clk.Advance(MaxUnackedWait - time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("b's wait started again at the restart")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 2 {
		t.Fatalf("unhandled %d, want 2", n)
	}
}

// A message handled after it was left unacked loses its record in the
// write of its handling: it neither holds the count nor counts.
func TestCaughtUnackedHandled(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	id := f.ulid(closeAt.Add(-time.Second))
	f.leave(id)
	if f.caught(closeAt) {
		t.Fatal("caught up with a message left unacked")
	}
	recs, _ := f.store.Load(context.Background(), kindUnacked)
	if len(recs) != 1 {
		t.Fatalf("%d unacked records stored, want 1", len(recs))
	}
	f.p.mu.Lock()
	f.p.handledUnacked(id)
	err := f.p.flush(context.Background())
	delete(f.p.unacked, id)
	f.p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if recs, _ := f.store.Load(context.Background(), kindUnacked); len(recs) != 0 {
		t.Fatalf("%d unacked records after the handling", len(recs))
	}
	f.start() // another process, or a restart, doesn't see it either
	f.clk.Advance(2 * time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("a handled message still holds the count")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 0 {
		t.Fatalf("unhandled %d, want 0", n)
	}
}

// A message handled twice before a flush (its first flush failed, and it
// came back) deletes its record once: a transaction takes one change
// per item.
func TestCaughtUnackedHandledTwice(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	id := f.ulid(closeAt.Add(-time.Second))
	f.leave(id)
	f.caught(closeAt) // stores it
	f.p.mu.Lock()
	f.p.handledUnacked(id)
	f.p.handledUnacked(id)
	err := f.p.flush(context.Background())
	f.p.mu.Unlock()
	if err != nil {
		t.Fatalf("flush after a message handled twice: %v", err)
	}
}

// unackedFailing fails every write of an unacked record while on.
type unackedFailing struct {
	Store
	on bool
}

func (s *unackedFailing) Apply(ctx context.Context, changes []Change) error {
	for _, c := range changes {
		if s.on && c.Kind == kindUnacked {
			return errors.New("unavailable")
		}
	}
	return s.Store.Apply(ctx, changes)
}

// A message given up on before its record could be stored stays given
// up on, and is stored so once the store takes writes again.
func TestCaughtUnackedGaveUpBeforeStored(t *testing.T) {
	f := newFixture(t)
	fs := &unackedFailing{Store: f.store, on: true}
	f.p.cfg.Store = fs
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	id := f.ulid(closeAt.Add(-time.Second))
	f.leave(id)
	f.clk.Advance(MaxUnackedWait + time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("still waiting past the cap")
	}
	fs.on = false
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d once the store is back, want 1", n)
	}
	recs, _ := f.store.Load(context.Background(), kindUnacked)
	var rec unackedRec
	if len(recs) != 1 || json.Unmarshal(recs[0].Data, &rec) != nil || !rec.GaveUp {
		t.Fatalf("stored %d records (%+v), want one given up on", len(recs), rec)
	}
	f.leave(id) // redelivered: no new wait
	if !f.caught(closeAt) {
		t.Fatal("a redelivery started a new wait")
	}
}

// Giving up on a stored message marks its record given up on; one that
// another process handled meanwhile (its record deleted) is neither
// written back nor counted.
func TestCaughtUnackedGaveUpStored(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	kept, handled := f.ulid(closeAt.Add(-2*time.Second)), f.ulid(closeAt.Add(-time.Second))
	f.leave(kept)
	f.leave(handled)
	f.caught(closeAt) // stores both
	stored := func() map[string]unackedRec {
		t.Helper()
		recs, err := f.store.Load(context.Background(), kindUnacked)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]unackedRec{}
		for _, r := range recs {
			var rec unackedRec
			if err := json.Unmarshal(r.Data, &rec); err != nil {
				t.Fatal(err)
			}
			out[r.ID] = rec
		}
		return out
	}
	if s := stored(); len(s) != 2 || s[kept].GaveUp || s[handled].GaveUp {
		t.Fatalf("stored %+v, want both, not given up on", s)
	}
	// Another process handles one: its record goes.
	if err := f.store.Apply(context.Background(), []Change{{Kind: kindUnacked, ID: handled}}); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(MaxUnackedWait + time.Minute)
	f.pump()
	if !f.caught(closeAt) {
		t.Fatal("still waiting past the cap")
	}
	s := stored()
	if len(s) != 1 || !s[kept].GaveUp {
		t.Fatalf("stored %+v, want only the kept one, given up on", s)
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 1 {
		t.Fatalf("unhandled %d, want the kept one", n)
	}
}

// handledMeanwhile deletes an unacked record just before the peer's
// write marking it given up on, as another process handling the message
// between the peer's load and that write would.
type handledMeanwhile struct {
	Store
	done bool
}

func (s *handledMeanwhile) Apply(ctx context.Context, changes []Change) error {
	if c := changes[0]; !s.done && c.Kind == kindUnacked && c.IfVersion != 0 {
		s.done = true
		if err := s.Store.Apply(ctx, []Change{{Kind: kindUnacked, ID: c.ID}}); err != nil {
			return err
		}
	}
	return s.Store.Apply(ctx, changes)
}

// A message handled elsewhere while the peer gives up on it isn't counted.
func TestCaughtUnackedGaveUpRace(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	closeAt := f.clk.Now()
	id := f.ulid(closeAt.Add(-time.Second))
	f.leave(id)
	f.caught(closeAt) // stores it
	f.clk.Advance(MaxUnackedWait + time.Minute)
	f.pump()
	f.p.cfg.Store = &handledMeanwhile{Store: f.store}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 0 {
		t.Fatalf("unhandled %d with the message handled meanwhile, want 0", n)
	}
	if !f.caught(closeAt) {
		t.Fatal("not caught up once the next load shows it handled")
	}
	if n := f.unhandled(closeAt, closeAt.Add(-time.Hour), closeAt); n != 0 {
		t.Fatalf("unhandled %d later, want 0", n)
	}
}

// A sign-in challenge keeps its match code with the challenge; a code
// that isn't 2 or 3 digits is refused (VAULT-MESSAGING 0.79.0 §10.4).
func TestChallengeMatchCode(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	for _, bad := range []string{"", "7", "1234", "1a", "٣٣"} {
		if _, err := f.p.AuthenticateSignIn(context.Background(), cid, "Sign in", bad, time.Minute); err != ErrMatchCode {
			t.Fatalf("match code %q: %v", bad, err)
		}
	}
	id, err := f.p.AuthenticateSignIn(context.Background(), cid, "Sign in", "07", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.pump()
	f.p.mu.Lock()
	ch := f.p.challenges[id]
	f.p.mu.Unlock()
	if ch == nil || ch.MatchCode != "07" || ch.Purpose != peerwire.PurposeSignIn {
		t.Fatalf("challenge %+v", ch)
	}
	if len(m.Challenges) != 1 || m.Challenges[0].MatchCode != "07" || m.Challenges[0].Purpose != peerwire.PurposeSignIn {
		t.Fatalf("member saw %+v", m.Challenges)
	}
	f.start() // kept across a restart, for the challenge's resend
	f.p.mu.Lock()
	ch = f.p.challenges[id]
	f.p.mu.Unlock()
	if ch == nil || ch.MatchCode != "07" {
		t.Fatalf("after a restart: %+v", ch)
	}
}

// EligibleUnsigned lists the eligible connections with no pinned
// credential key: a signed answer pins one; a connection that does not
// vote or is not active is not listed.
func TestEligibleUnsigned(t *testing.T) {
	f := newFixture(t)
	a, b, n := f.member(10), f.member(20), f.member(30)
	ca, cb := f.connect(a, "a"), f.connect(b, "b")
	n.Features = nil // not vote-capable
	f.connect(n, "n")
	got := f.p.EligibleUnsigned()
	slices.Sort(got)
	want := []string{ca, cb}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("EligibleUnsigned = %v, want %v", got, want)
	}
	if !f.signIn(a, ca) {
		t.Fatal("sign-in not approved")
	}
	if got := f.p.EligibleUnsigned(); len(got) != 1 || got[0] != cb {
		t.Fatalf("after a signed: %v, want [%s]", got, cb)
	}
	f.p.mu.Lock()
	f.p.conns[cb].State = StateStale
	f.p.mu.Unlock()
	if got := f.p.EligibleUnsigned(); len(got) != 0 {
		t.Fatalf("an inactive connection is listed: %v", got)
	}
}

// HasPendingSignIn is true from a sign-in challenge until it is
// answered or expires; an approval challenge does not count.
func TestHasPendingSignIn(t *testing.T) {
	f := newFixture(t)
	m := f.member(10)
	cid := f.connect(m, "t")
	ctx := context.Background()
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("pending before any challenge")
	}
	if _, err := f.p.Authenticate(ctx, cid, "x", peerwire.PurposeApproval, time.Minute); err != nil {
		t.Fatal(err)
	}
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("an approval challenge counted")
	}
	id, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !f.p.HasPendingSignIn(cid) || f.p.HasPendingSignIn("other") {
		t.Fatal("not pending, or pending elsewhere")
	}
	f.p.CancelChallenge(ctx, id)
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("pending after cancel")
	}
	if _, err := f.p.AuthenticateSignIn(ctx, cid, "Sign in", "42", time.Minute); err != nil {
		t.Fatal(err)
	}
	f.clk.Advance(2 * time.Minute)
	if f.p.HasPendingSignIn(cid) {
		t.Fatal("pending past its exp")
	}
}

// A Votes error that wraps ErrNoAnswer acknowledges the request without
// answering it: the step does not fail, the next message in the batch is
// handled, nothing holds the close, and it is not delivered again.
func TestVoteNoAnswer(t *testing.T) {
	f := newFixture(t)
	rv := &recordVotes{}
	f.votes = rv
	f.p.cfg.Votes = rv
	m := f.member(10)
	cid := f.connect(m, "t")
	if !f.signIn(m, cid) {
		t.Fatal("sign-in failed")
	}
	f.clk.Advance(2 * time.Minute) // past the start's leases
	f.pump()
	rv.fail = fmt.Errorf("held: %w", ErrNoAnswer)
	held := m.Send("vote.cast", []byte(`{"n":1}`))
	next := m.Send("vote.status", []byte(`{"n":2}`))
	m.Step()
	if _, err := f.p.Step(context.Background(), 0); err != nil {
		t.Fatalf("the step failed: %v", err)
	}
	answered := func(id string) bool {
		for _, typ := range []string{"vote.cast", "vote.status"} {
			for _, in := range m.Received(typ) {
				if in.Re == id {
					return true
				}
			}
		}
		return false
	}
	m.Step()
	if answered(held) || !answered(next) {
		t.Fatalf("held answered %v, next answered %v", answered(held), answered(next))
	}
	if !f.caught(f.clk.Now().Add(-time.Millisecond)) {
		t.Fatal("the unanswered request holds the close")
	}
	n := len(rv.reqs)
	f.clk.Advance(2 * time.Minute) // past any lease
	f.pump()
	if answered(held) || len(rv.reqs) != n {
		t.Fatal("delivered again")
	}
}

// An empty collect is timed by this clock, which may run fast: it is
// evidence only when it started at or after emptyAfter (the passing
// timestamp-authority probe plus the margin, BALLOT-PROTOCOL §7 0.13.12).
func TestCaughtEmptyCollectAfterTheProbe(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump() // an empty collect now
	at := f.clk.Now().Add(-time.Second)
	ok, _, err := f.p.Caught(context.Background(), at, f.clk.Now().Add(time.Minute), time.Time{}, at)
	if err != nil || ok {
		t.Fatalf("an empty collect before emptyAfter counted: %v %v", ok, err)
	}
	f.clk.Advance(2 * time.Minute)
	f.pump()
	if ok, _, err := f.p.Caught(context.Background(), at, f.clk.Now().Add(-time.Second), time.Time{}, at); err != nil || !ok {
		t.Fatalf("an empty collect after emptyAfter: %v %v", ok, err)
	}
}

// The boundary: an empty collect started exactly at emptyAfter counts.
func TestCaughtEmptyCollectAtEmptyAfter(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	at := f.p.emptyAt
	if ok, _, err := f.p.Caught(context.Background(), at.Add(-time.Second), at, time.Time{}, at); err != nil || !ok {
		t.Fatalf("at emptyAfter: %v %v", ok, err)
	}
	if ok, _, _ := f.p.Caught(context.Background(), at.Add(-time.Second), at.Add(time.Nanosecond), time.Time{}, at); ok {
		t.Fatal("before emptyAfter counted")
	}
}

// Step's empty-collect time carries this process's monotonic reading (the
// evidence is compared on it, BALLOT-PROTOCOL §7 0.13.12).
func TestEmptyAtIsMonotonic(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(2 * time.Minute)
	f.pump()
	f.p.cfg.Now = time.Now
	f.pump()
	if !strings.Contains(f.p.emptyAt.String(), " m=") {
		t.Fatalf("emptyAt without a monotonic reading: %v", f.p.emptyAt)
	}
}

// SendMessage stops adding to an outbox the relay isn't taking from, by
// entries and by bytes, with ErrOutboxFull; once the relay takes them,
// sends go again.
func TestSendMessageOutboxBound(t *testing.T) {
	ctx := context.Background()
	for _, bound := range []string{"entries", "bytes"} {
		f := newFixture(t)
		var cids []string
		for i := 0; i < 4; i++ {
			cids = append(cids, f.connect(f.member(byte(10+i)), fmt.Sprintf("t%d", i)))
		}
		f.pump()
		down := true
		f.failDeposit = func(string, string) error {
			if down {
				return errUnavailable
			}
			return nil
		}
		body := json.RawMessage(`{"proposal":"` + strings.Repeat("x", 1000) + `"}`)
		old := sendOutboxLimit
		n, _ := f.p.voteOutboxLoad(f.clk.Now())
		if bound == "entries" {
			sendOutboxLimit.n = n + 5
		} else {
			_, size := f.p.voteOutboxLoad(f.clk.Now())
			sendOutboxLimit.bytes = size + 5*1000 // about 5 sealed bodies
		}
		t.Cleanup(func() { sendOutboxLimit = old })
		queued, full := 0, 0
		for i := 0; i < 40; i++ {
			_, err := f.p.SendMessage(ctx, cids[i%len(cids)], "vote.proposal", body, time.Time{})
			switch {
			case err == nil:
				queued++
			case errors.Is(err, ErrOutboxFull):
				full++
			default:
				t.Fatalf("%s: send %d: %v", bound, i, err)
			}
		}
		if queued == 0 || queued > 5 || full != 40-queued {
			t.Fatalf("%s: queued %d, full %d", bound, queued, full)
		}
		if got, _ := f.p.voteOutboxLoad(f.clk.Now()); got > n+5 {
			t.Fatalf("%s: outbox %d entries", bound, got)
		}
		down = false
		f.clk.Advance(time.Minute) // past the deposits' retry backoff
		f.pump()
		if _, err := f.p.SendMessage(ctx, cids[0], "vote.proposal", body, time.Time{}); err != nil {
			t.Fatalf("%s: after the relay is back: %v", bound, err)
		}
		sendOutboxLimit = old
	}
}

// Members whose deposits the relay refuses (their vaults gone, no
// connection.removed) don't count toward the bound, nor do the token
// refreshes and other messages queued for them: a healthy member is
// still sent to, however many such members there are. A vote deposit
// past its notAfter is dropped and stops counting.
func TestSendMessageBoundIgnoresUnreachable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	var gone []string
	for i := 0; i < 6; i++ {
		gone = append(gone, f.connect(f.member(byte(20+i)), fmt.Sprintf("g%d", i)))
	}
	ok := f.connect(f.member(30), "ok")
	f.pump()
	goneBox := map[string]bool{}
	for _, c := range gone {
		goneBox[f.p.conns[c].Peer.Relay.Mailbox] = true
	}
	f.failDeposit = func(mailbox, _ string) error {
		if goneBox[mailbox] {
			return &relayclient.Error{Status: 401, Code: codeTokenExpired}
		}
		return nil
	}
	old := sendOutboxLimit
	t.Cleanup(func() { sendOutboxLimit = old })
	sendOutboxLimit.n = 3
	body := json.RawMessage(`{"proposal":"x"}`)
	// Each gone member: one vote deposit, refused and parked; after it,
	// SendMessage queues nothing more for them (ErrBusy, member-only).
	for _, c := range gone {
		if _, err := f.p.SendMessage(ctx, c, "vote.proposal", body, time.Time{}); err != nil {
			t.Fatalf("first send to %s: %v", c, err)
		}
	}
	f.pump()
	for _, c := range gone {
		if !f.p.awaitingToken(c) {
			t.Fatalf("%s not parked", c)
		}
		if _, err := f.p.SendMessage(ctx, c, "vote.extended", body, time.Time{}); !errors.Is(err, ErrBusy) {
			t.Fatalf("a parked member: %v", err)
		}
	}
	// Other messages pile up for them (refreshes, say): not counted.
	for _, c := range gone {
		for i := 0; i < 10; i++ {
			f.p.mu.Lock()
			f.p.queueDeposit(&outboxEntry{ConnID: c, Mailbox: f.p.conns[c].Peer.Relay.Mailbox, Payload: make([]byte, 100)}, f.clk.Now())
			f.p.mu.Unlock()
		}
	}
	if n, _ := f.p.voteOutboxLoad(f.clk.Now()); n != 0 {
		t.Fatalf("%d counted", n)
	}
	for i := 0; i < 5; i++ {
		if _, err := f.p.SendMessage(ctx, ok, "vote.proposal", body, time.Time{}); err != nil {
			t.Fatalf("the healthy member, send %d: %v", i, err)
		}
	}
	f.pump()
	if got := len(f.ms[len(f.ms)-1].Received("vote.proposal")); got != 5 {
		t.Fatalf("the healthy member got %d", got)
	}

	// Past its notAfter, a vote deposit no longer counts, and the drain
	// drops it.
	f.failDeposit = func(string, string) error { return errUnavailable }
	until := f.clk.Now().Add(time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := f.p.SendMessage(ctx, ok, "vote.proposal", body, until); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.p.SendMessage(ctx, ok, "vote.proposal", body, until); !errors.Is(err, ErrOutboxFull) {
		t.Fatalf("at the bound: %v", err)
	}
	f.clk.Advance(2 * time.Hour)
	if n, _ := f.p.voteOutboxLoad(f.clk.Now()); n != 0 {
		t.Fatalf("%d counted past notAfter", n)
	}
	f.pump()
	f.p.mu.Lock()
	left := 0
	for _, e := range f.p.outbox {
		if e.Vote && e.ConnID == ok {
			left++
		}
	}
	f.p.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d expired vote deposits kept", left)
	}
}
