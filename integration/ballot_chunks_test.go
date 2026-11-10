//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/internal/ballot/ballottest"
	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/sealstore"
	"github.com/vettid/service-vault/vote"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

type closingSite struct{ site }

func (closingSite) PublishResults(context.Context, string, []byte, []byte, []byte) (ballot.Receipt, error) {
	now := time.Now().Unix()
	return ballot.Receipt{Bundle: ballottest.Bundle(now, now)}, nil
}

func (closingSite) Extension(context.Context, string, int64) (*ballot.SiteExtension, error) {
	return nil, nil
}

// approveAll approves every use (the approval flow has its own tests).
type approveAll struct{}

func (approveAll) Consume(context.Context, string, string, []byte, ballot.Use) error { return nil }

type caught struct{}

func (caught) Caught(context.Context, time.Time, time.Time, time.Time) (bool, int64, error) {
	return true, 0, nil
}

// At ballot.MaxEligible members, on DynamoDB with sealed records: the
// proposal's members and the results' rows (a row per member, voted or
// not) are stored in chunks, every item within DynamoDB's 400 KB, and
// read back whole; with a chunk deleted, the proposal can't be read.
func TestBallotChunksAtCapOnDynamoDB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	tbl := newTable(t, ctx)
	recKey, err := sealstore.NewRecordKey()
	if err != nil {
		t.Fatal(err)
	}
	st, err := sealstore.New(tbl.Peer(), map[uint32][]byte{1: recKey.Key}, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	r := make(roster, ballot.MaxEligible)
	for i := range r {
		r[i] = fmt.Sprintf("01JBQZ%020d", i) // a ULID's length
	}
	ik := ed25519.NewKeyFromSeed(sha256Bytes("service ik"))
	now := time.Now()
	m := &ballot.Manager{Store: &ballot.RecordStore{Records: st, Copy: &ballot.MemCopy{}}, IK: ik.Public().(ed25519.PublicKey),
		Sign:   func(label string, msg []byte) ([]byte, error) { return suite.Sign(ik, label, msg) },
		Roster: r, Sender: sink{}, Publisher: closingSite{}, Catcher: caught{}, Approvals: approveAll{}, NewID: envelope.NewULID,
		Now: func() time.Time { return now }, Timestamp: ballottest.Time}
	opens := now.Add(time.Hour).Unix()
	in := ballot.ProposalInput{Title: "Adopt the 2027 budget", Choices: []ballot.ChoiceInput{{Label: "Yes"}, {Label: "No"}},
		Quorum: vote.Quorum{MinBallots: 0}, OpensAt: opens, ClosesAt: opens + 86400, OutageRule: ballot.DefaultOutageRule}
	c, err := m.Create(ctx, "apv", in)
	if err != nil {
		t.Fatal(err)
	}
	o, err := m.Store.OpenProposal(ctx, c.ProposalID)
	if err != nil || o == nil || len(o.Members) != ballot.MaxEligible || len(o.MemberChunks) < 2 {
		t.Fatalf("proposal: %v (%d members)", err, len(o.Members))
	}

	now = time.Unix(in.ClosesAt, 0).Add(2 * ballot.CollectMargin)
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	pr, err := m.Results(ctx, c.ProposalID)
	if err != nil || pr == nil || len(pr.RowChunks) < 2 {
		t.Fatalf("results: %v", err)
	}
	if _, _, err := vote.Check(m.IK, pr.Results, pr.Sig, pr.Rows); err != nil {
		t.Fatalf("the rows read back don't check: %v", err)
	}
	raw, err := tbl.Peer().Load(ctx, ballot.KindChunk)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(o.MemberChunks)+len(pr.RowChunks) {
		t.Errorf("%d chunks stored, %d named", len(raw), len(o.MemberChunks)+len(pr.RowChunks))
	}
	for _, rec := range raw {
		if !ballot.ChunksOf(c.ProposalID, rec.ID) || len(rec.Data) > 400_000-16_000 {
			t.Errorf("chunk %s: %d bytes", rec.ID, len(rec.Data))
		}
	}
	t.Logf("%d members in %d chunks, %d bytes of rows in %d chunks", len(o.Members), len(o.MemberChunks), len(pr.Rows), len(pr.RowChunks))

	// A chunk lost: the proposal is an error, never a proposal without
	// members.
	if err := tbl.Peer().Apply(ctx, []peer.Change{{Kind: ballot.KindChunk, ID: o.MemberChunks[1].ID}}); err != nil {
		t.Fatal(err)
	}
	if o, err := m.Store.OpenProposal(ctx, c.ProposalID); o != nil || !errors.Is(err, ballot.ErrChunkMissing) {
		t.Fatalf("with a chunk deleted: %v", err)
	}
}
