package ballot

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
)

// The box on the record store and the copy: a cast is kept in both; after
// the table is restored without it, the copy still decides the tag's
// ballot, and Rebuild puts it back.
func TestRecordStoreSurvivesRestore(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	cp := &MemCopy{}
	rs := &RecordStore{Records: peer.NewMemStore(), Copy: cp}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	if err := rs.SaveProposal(ctx, f.open, true); err == nil {
		t.Fatal("a proposal created twice")
	}
	f.box.Store = rs
	body, _ := f.castBody("c0", "yes")
	if a := f.send("c0", TypeCast, body, f.during(), true); a.Code != "" {
		t.Fatalf("cast refused: %s", a.Code)
	}
	tag := f.open.Members["c0"].Tag
	if r, _ := rs.Ballot(ctx, f.p.ProposalID, tag); r == nil || r.Ballot.ChoiceID != "yes" {
		t.Fatal("ballot not in the record store")
	}

	// The table is restored from before the cast: the proposal is there,
	// the ballot isn't.
	rs.Records = peer.NewMemStore()
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	other, _ := f.castBody("c0", "no")
	a := f.send("c0", TypeCast, other, f.during(), true)
	if a.Code != CodeAlreadyVoted {
		t.Fatalf("a second ballot after the restore: %q", a.Code)
	}
	if x := parseAnswer(t, a); x.Ballot == nil || x.Ballot.ChoiceID != "yes" {
		t.Fatal("already_voted doesn't name the first ballot")
	}
	// The copy answered alone; Rebuild puts its ballot back into the
	// table, once.
	if n, err := rs.Rebuild(ctx, f.p.ProposalID); err != nil || n != 1 {
		t.Fatalf("Rebuild: %d, %v", n, err)
	}
	if n, err := rs.Rebuild(ctx, f.p.ProposalID); err != nil || n != 0 {
		t.Fatalf("Rebuild again: %d, %v", n, err)
	}
	if _, ok, _ := rs.Records.Get(ctx, KindBallot, ballotID(f.p.ProposalID, tag)); !ok {
		t.Fatal("the table lacks the rebuilt ballot")
	}
	if r, _ := rs.Ballot(ctx, f.p.ProposalID, tag); r == nil || r.Ballot.ChoiceID != "yes" {
		t.Fatal("Rebuild didn't restore the ballot")
	}
}

// A stored proposal reads back whole.
func TestRecordStoreProposal(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	rs := &RecordStore{Records: peer.NewMemStore(), Copy: &MemCopy{}}
	if o, err := rs.OpenProposal(ctx, f.p.ProposalID); o != nil || err != nil {
		t.Fatal("a proposal before it was saved")
	}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	o, err := rs.OpenProposal(ctx, f.p.ProposalID)
	if err != nil || len(o.Members) != 3 || o.ClosesAt != f.p.ClosesAt {
		t.Fatalf("read back: %v", err)
	}
	if p, err := o.Parsed(); err != nil || p.ProposalID != f.p.ProposalID {
		t.Fatalf("parsed: %v", err)
	}
}

// The sealed copy keeps no plaintext, and reads back through Rebuild.
func TestSealedCopy(t *testing.T) {
	ctx := context.Background()
	f := newBoxFixture(t)
	seal, err := sealstore.New(peer.NewMemStore(), map[uint32][]byte{1: bytes.Repeat([]byte{7}, 32)}, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	raw := &MemCopy{}
	rs := &RecordStore{Records: peer.NewMemStore(), Copy: &SealedCopy{Inner: raw, Seal: seal.Seal, Open: seal.Open}}
	if err := rs.SaveProposal(ctx, f.open, true); err != nil {
		t.Fatal(err)
	}
	f.box.Store = rs
	body, _ := f.castBody("c1", "no")
	if a := f.send("c1", TypeCast, body, f.during(), true); a.Code != "" {
		t.Fatalf("cast refused: %s", a.Code)
	}
	items, _ := raw.List(ctx, f.p.ProposalID)
	if len(items) != 1 || bytes.Contains(items[0].Data, []byte(`"choice_id"`)) {
		t.Fatal("the copy holds plaintext")
	}
	rs.Records = peer.NewMemStore()
	if n, err := rs.Rebuild(ctx, f.p.ProposalID); err != nil || n != 1 {
		t.Fatalf("Rebuild: %d, %v", n, err)
	}
	if r, _ := rs.Ballot(ctx, f.p.ProposalID, f.open.Members["c1"].Tag); r == nil || r.Ballot.ChoiceID != "no" {
		t.Fatal("rebuilt ballot")
	}
	// A sealed item moved to another tag doesn't open.
	other := f.open.Members["c2"].Tag
	if _, err := (&SealedCopy{Inner: raw, Seal: seal.Seal, Open: seal.Open}).Open(KindBallot, ballotID(f.p.ProposalID, other), items[0].Data); err == nil {
		t.Fatal("opened in another place")
	}
}

// openHook runs a function once the box has read a proposal, as another
// writer would between the box's read and its write.
type openHook struct {
	BoxStore
	after func()
	once  bool
	fired int
	reads int
}

func (h *openHook) OpenProposal(ctx context.Context, id string) (*OpenProposal, error) {
	o, err := h.BoxStore.OpenProposal(ctx, id)
	h.reads++
	if h.after != nil && (!h.once || h.fired == 0) {
		h.fired++
		h.after()
	}
	return o, err
}

// guardedBox is a fixture whose box runs on a RecordStore with a MemCopy
// that checks guards against the same records.
func guardedBox(t *testing.T) (*boxFixture, *RecordStore, *MemCopy) {
	t.Helper()
	f := newBoxFixture(t)
	recs := peer.NewMemStore()
	cp := &MemCopy{Records: recs}
	rs := &RecordStore{Records: recs, Copy: cp}
	if err := rs.SaveProposal(context.Background(), f.open, true); err != nil {
		t.Fatal(err)
	}
	f.box.Store = rs
	return f, rs, cp
}

// A cast that read the proposal before the close's publication was saved
// is late, and isn't in the copy.
func TestCastRacingCloseIsLate(t *testing.T) {
	ctx := context.Background()
	f, rs, cp := guardedBox(t)
	f.box.Store = &openHook{BoxStore: rs, once: true, after: func() {
		o, err := rs.OpenProposal(ctx, f.p.ProposalID)
		if err != nil {
			t.Error(err)
			return
		}
		o.Published = true
		if err := rs.SaveProposal(ctx, o, false); err != nil {
			t.Error(err)
		}
	}}
	body, leaf := f.castBody("c0", "yes")
	a := f.send("c0", TypeCast, body, f.during(), true)
	f.checkRefusal(a, "c0", CodeLate, f.open.Members["c0"].Tag, sum(leaf))
	if items, _ := cp.List(ctx, f.p.ProposalID); len(items) != 0 {
		t.Fatalf("%d ballots in the copy", len(items))
	}
	if r, _ := rs.Ballot(ctx, f.p.ProposalID, f.open.Members["c0"].Tag); r != nil {
		t.Fatal("a late ballot is recorded")
	}
}

// Another save of the proposal (an extension, say) between the read and
// the write costs the cast one retry; a second change is an error.
func TestCastGuardRetry(t *testing.T) {
	ctx := context.Background()
	f, rs, cp := guardedBox(t)
	bump := func() {
		o, err := rs.OpenProposal(ctx, f.p.ProposalID)
		if err != nil {
			t.Error(err)
			return
		}
		if err := rs.SaveProposal(ctx, o, false); err != nil {
			t.Error(err)
		}
	}
	hook := &openHook{BoxStore: rs, once: true, after: bump}
	f.box.Store = hook
	body, _ := f.castBody("c0", "yes")
	if a := f.send("c0", TypeCast, body, f.during(), true); a.Code != "" {
		t.Fatalf("refused after an unrelated change: %q", a.Code)
	}
	if hook.reads != 2 {
		t.Fatalf("the proposal was read %d times", hook.reads)
	}
	if items, _ := cp.List(ctx, f.p.ProposalID); len(items) != 1 {
		t.Fatalf("%d ballots in the copy", len(items))
	}

	// Changed again on the retry: an error, nothing written.
	f.box.Store = &openHook{BoxStore: rs, after: bump}
	body, _ = f.castBody("c1", "no")
	j, _ := json.Marshal(body)
	_, err := f.box.Vote(ctx, &peer.VoteRequest{ConnectionID: "c1", Type: TypeCast, Body: j, MsgMS: f.during(), Active: true,
		CredentialKey: f.creds["c1"].Public().(ed25519.PublicKey)})
	if !errors.Is(err, ErrGuard) {
		t.Fatalf("a second change: %v", err)
	}
	if items, _ := cp.List(ctx, f.p.ProposalID); len(items) != 1 {
		t.Fatalf("%d ballots in the copy", len(items))
	}
}

// An item already in the copy is returned whatever the guard says.
func TestMemCopyGuard(t *testing.T) {
	ctx := context.Background()
	recs := peer.NewMemStore()
	cp := &MemCopy{Records: recs}
	if err := recs.Apply(ctx, []peer.Change{{Kind: "k", ID: "a", Data: []byte("1"), IfAbsent: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.PutOnce(ctx, "p", []byte{1}, []byte("x"), &Guard{Kind: "k", ID: "a", Version: 9}); !errors.Is(err, ErrGuard) {
		t.Fatalf("a stale guard: %v", err)
	}
	if _, err := cp.PutOnce(ctx, "p", []byte{1}, []byte("x"), &Guard{Kind: "k", ID: "gone", Version: 1}); !errors.Is(err, ErrGuard) {
		t.Fatalf("a guard on a missing record: %v", err)
	}
	if got, err := cp.PutOnce(ctx, "p", []byte{1}, []byte("x"), &Guard{Kind: "k", ID: "a", Version: 1}); err != nil || string(got) != "x" {
		t.Fatalf("a current guard: %q %v", got, err)
	}
	if got, err := cp.PutOnce(ctx, "p", []byte{1}, []byte("y"), &Guard{Kind: "k", ID: "a", Version: 9}); err != nil || string(got) != "x" {
		t.Fatalf("an item there, stale guard: %q %v", got, err)
	}
}

// Status and the duplicate check read the copy: with the table's row
// gone they answer the same.
func TestStatusAndDuplicatesReadTheCopy(t *testing.T) {
	ctx := context.Background()
	f, rs, _ := guardedBox(t)
	body, _ := f.castBody("c0", "yes")
	first := f.send("c0", TypeCast, body, f.during(), true)
	if first.Code != "" {
		t.Fatalf("cast refused: %q", first.Code)
	}
	tag := f.open.Members["c0"].Tag
	if err := rs.Records.Apply(ctx, []peer.Change{{Kind: KindBallot, ID: ballotID(f.p.ProposalID, tag)}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := rs.Records.Get(ctx, KindBallot, ballotID(f.p.ProposalID, tag)); ok {
		t.Fatal("the table row is still there")
	}
	again := f.send("c0", TypeCast, body, f.during()+1, true)
	if again.Code != "" || !bytes.Equal(parseAnswer(t, again).ReceiptSig, parseAnswer(t, first).ReceiptSig) {
		t.Fatalf("the same ballot again: %q", again.Code)
	}
	other, _ := f.castBody("c0", "no")
	if a := f.send("c0", TypeCast, other, f.during()+2, true); a.Code != CodeAlreadyVoted {
		t.Fatalf("another ballot: %q", a.Code)
	}
	st := f.send("c0", TypeStatus, map[string]string{"proposal_id": f.p.ProposalID}, f.during()+3, true)
	if x := parseAnswer(t, st); st.Code != "" || x.Ballot == nil || x.Ballot.ChoiceID != "yes" {
		t.Fatalf("status: %q %+v", st.Code, x)
	}
}
