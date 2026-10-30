package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"github.com/vettid/vettid-relay/relayclient"
	"strings"
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
	ok, _, err := f.p.Caught(context.Background(), t, time.Time{}, t)
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
	_, n, err := f.p.Caught(context.Background(), t, from, until)
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
	f.start() // kept across a restart, for the challenge's resend
	f.p.mu.Lock()
	ch = f.p.challenges[id]
	f.p.mu.Unlock()
	if ch == nil || ch.MatchCode != "07" {
		t.Fatalf("after a restart: %+v", ch)
	}
}
