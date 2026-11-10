//go:build !race

package ballot

// The size and timing test at MaxEligible. It casts MaxEligible ballots,
// which takes seconds without the race detector and minutes with it, so
// the race run leaves it out and CI runs it in a step of its own.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/service-vault/vote"
)

// At MaxEligible members, everyone voting, with the largest inputs the
// service takes (the longest title, text and labels, 16 choices, 26-byte
// connection ids, MaxExtensions extensions and a 10 KB anchor bundle),
// every item stored (the proposal's record, the results' record and each
// of their chunks) still fits one DynamoDB item (400 KB), with room for
// the seal, the keys and the attribute names, and the rows fit the votes
// site's upload.
func TestMaxEligibleFitsOneItem(t *testing.T) {
	if testing.Short() {
		t.Skip("casts MaxEligible ballots")
	}
	// Each request (create, close) answers well within the API's 30 s
	// WriteTimeout (cmd/service-vault), and the sends end.
	const requestBudget = 15 * time.Second
	const itemLimit = 400_000 - 16_000 // the seal, keys and attribute names
	ctx := context.Background()
	m, _, _ := newManager(t)
	ct := &fakeCatcher{caught: true}
	m.Catcher = ct
	roster := make(fakeRoster, MaxEligible)
	for i := range roster {
		roster[i] = fmt.Sprintf("01JBQZ%020d", i) // a ULID's length
	}
	m.Roster = roster
	// The largest input create accepts: the longest title (the text may
	// only repeat it), then the most and longest labels the admins'
	// summary still shows whole.
	in := input()
	in.Title = strings.Repeat("T", MaxTitleBytes())
	in.Text = in.Title
	var c *Created
	var err error
	for n := MaxRealChoices; n >= 2 && c == nil; n-- {
		for l := MaxLabelRunes; l >= 2 && c == nil; l-- {
			in.Choices = nil
			for i := range n {
				in.Choices = append(in.Choices, ChoiceInput{Label: fmt.Sprintf("%c", 'A'+i) + strings.Repeat("l", l-1)})
			}
			start := time.Now()
			if c, err = m.Create(ctx, "apv", in); err != nil {
				c = nil
			} else if d := time.Since(start); d > requestBudget {
				t.Errorf("create took %v", d)
			} else {
				t.Logf("create (with publish) took %v at %d members", d.Round(time.Millisecond), MaxEligible)
			}
		}
	}
	if c == nil {
		t.Fatalf("no input accepted: %v", err)
	}
	start := time.Now()
	m.Wait()
	t.Logf("vote.proposal to %d members took %v (a fake peer)", MaxEligible, time.Since(start).Round(time.Millisecond))
	t.Logf("%d choices, labels of %d, title of %d", len(in.Choices), len(in.Choices[0].Label), len(in.Title))
	// MaxExtensions extensions, each moving the close by a second for an
	// outage of just over an hour that is over.
	out := vote.Outage{From: in.OpensAt + 60, To: in.OpensAt + 60 + MinOutage + 1, Source: "https://status.vettid.org/"}
	now := time.Unix(out.To+60, 0)
	m.Now = func() time.Time { return now }
	closes := in.ClosesAt
	for range MaxExtensions {
		closes++
		if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: closes, Outage: out}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Extend(ctx, c.ProposalID, "apv", ExtensionInput{ClosesAt: closes + 1, Outage: out}); err == nil {
		t.Fatal("an extension past MaxExtensions")
	}
	during := uint64(in.OpensAt)*1000 + 1
	for _, conn := range roster {
		if code := castFor(t, m, c.ProposalID, conn, vote.AbstainID, during); code != "" { // the longest choice id
			t.Fatalf("%s: %q", conn, code)
		}
	}
	m.Now = func() time.Time { return time.Unix(closes, 0).Add(2 * CollectMargin) }
	start = time.Now()
	if _, err := m.Close(ctx, c.ProposalID); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > requestBudget {
		t.Errorf("close took %v", d)
	} else {
		t.Logf("close (count, results, publish) took %v at %d members", d.Round(time.Millisecond), MaxEligible)
	}
	m.Wait()
	bundle, _ := json.Marshal(map[string]string{"pad": strings.Repeat("b", 10<<10)})
	for _, kind := range []string{KindProposal, KindResults} {
		data, ok, err := m.Store.Records.Get(ctx, kind, c.ProposalID)
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", kind, ok, err)
		}
		// A real Sigstore bundle is larger than the test's.
		var rec map[string]json.RawMessage
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatal(err)
		}
		rec["bundle"] = bundle
		data, _ = json.Marshal(rec)
		if len(data) > itemLimit {
			t.Errorf("%s record: %d bytes, over %d", kind, len(data), itemLimit)
		}
		t.Logf("%s record: %d bytes at %d members", kind, len(data), MaxEligible)
	}
	chunks, err := m.Store.Records.Load(ctx, KindChunk)
	if err != nil || len(chunks) == 0 {
		t.Fatalf("chunks: %d, %v", len(chunks), err)
	}
	for _, r := range chunks {
		if len(r.Data) > itemLimit {
			t.Errorf("chunk %s: %d bytes, over %d", r.ID, len(r.Data), itemLimit)
		}
	}
	pr, err := m.Results(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	if n := base64.StdEncoding.EncodedLen(len(pr.Rows)); n > siteRowsUpload {
		t.Errorf("rows: %d bytes as base64, over the site's %d", n, siteRowsUpload)
	}
	// The per-member bounds the chunk lists are checked against.
	o, err := m.Store.OpenProposal(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	md, _ := json.Marshal(o.Members)
	if len(md) > MaxEligible*maxMemberBytes || len(pr.Rows) > MaxEligible*maxRowBytes {
		t.Errorf("members %d bytes, rows %d bytes: over %d and %d a member", len(md), len(pr.Rows), maxMemberBytes, maxRowBytes)
	}
	t.Logf("members %d bytes, rows %d bytes at %d members", len(md), len(pr.Rows), MaxEligible)
	if len(pr.RowChunks) > maxRowChunks || len(o.MemberChunks) > maxMemberChunks {
		t.Errorf("%d row chunks, %d member chunks", len(pr.RowChunks), len(o.MemberChunks))
	}
	t.Logf("%d chunks; rows %d bytes in %d chunks at %d members", len(chunks), len(pr.Rows), len(pr.RowChunks), MaxEligible)
}
