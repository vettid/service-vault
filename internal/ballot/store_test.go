package ballot

import (
	"bytes"
	"context"
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
	// The refused cast put the copy's ballot back; Rebuild finds nothing
	// more to do, and on a fresh table puts it back itself.
	if n, err := rs.Rebuild(ctx, f.p.ProposalID); err != nil || n != 0 {
		t.Fatalf("Rebuild: %d, %v", n, err)
	}
	rs.Records = peer.NewMemStore()
	if n, err := rs.Rebuild(ctx, f.p.ProposalID); err != nil || n != 1 {
		t.Fatalf("Rebuild on a fresh table: %d, %v", n, err)
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
