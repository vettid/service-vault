package peer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// recordVotes answers every vote.* request with ok and records it.
type recordVotes struct {
	mu   sync.Mutex
	reqs []VoteRequest
	code string
}

func (r *recordVotes) Vote(_ context.Context, req *VoteRequest) (VoteAnswer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
