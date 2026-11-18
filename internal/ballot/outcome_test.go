package ballot

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/service-vault/vote"
)

// The title limit is derived from the final summary strings (owner
// decision on GC #1367, S-d). With "removed votes" gone (0.14.1, GC
// #1374), the extension summary bounds it: 35 bytes.
func TestMaxTitleBytes(t *testing.T) {
	if n := MaxTitleBytes(); n != 35 {
		t.Fatalf("title limit %d, want 35", n)
	}
	// The edge itself: the widest extension summary is exactly
	// maxSummary at 35 bytes, and refused at 36.
	s, err := ExtensionSummary(widestExtension(), strings.Repeat("T", 35))
	if err != nil || len(s) != maxSummary || maxSummary != 172 {
		t.Fatalf("at 35: %d %v", len(s), err)
	}
	if _, err := ExtensionSummary(widestExtension(), strings.Repeat("T", 36)); err == nil {
		t.Fatal("36 bytes fit")
	}
}

// A two-choice "Approve"/"Reject" motion always fits: every decision,
// binding or advisory, the largest quorum, the widest times and the
// longest title, counted as quoted.
func TestWidestMotionAlwaysFits(t *testing.T) {
	n := MaxTitleBytes()
	titles := []string{strings.Repeat("T", n), `"` + strings.Repeat("T", n-2), strings.Repeat("é", n/2)}
	for _, d := range validDecisions() {
		for _, binding := range []bool{false, true} {
			for _, title := range titles {
				in := input()
				in.Title, in.Decision, in.Binding = title, d, binding
				in.Choices = []ChoiceInput{{Label: "Approve"}, {Label: "Reject"}}
				in.Quorum.MinBallots = vote.MaxEligible
				in.OpensAt, in.ClosesAt = 7258118400-vote.MaxWindow, 7258118400
				s, err := ProposalSummary(mustCanon(t, in))
				if err != nil || len(s) > maxSummary {
					t.Fatalf("%s %+v binding %v: %d %v", title, d, binding, len(s), err)
				}
			}
		}
	}
	in := input()
	in.Title = strings.Repeat("T", n+1)
	if _, err := ProposalSummary(mustCanon(t, in)); !errors.As(err, new(*ErrNotShown)) {
		t.Fatalf("a title one byte over: %v", err)
	}
	// Quoted bytes count: a title of n bytes with a quote is one over.
	in.Title = `"` + strings.Repeat("T", n-1)
	if _, err := ProposalSummary(mustCanon(t, in)); !errors.As(err, new(*ErrNotShown)) {
		t.Fatalf("a quoted title one byte over: %v", err)
	}
}

func TestSummaryShowsRule(t *testing.T) {
	cases := map[string]vote.Decision{
		"rule >1/2 cast,":   {Rule: vote.RuleMajority, Base: vote.BaseOf(vote.BaseCast)},
		"rule >=2/3 voted,": {Rule: vote.RuleThreshold, Base: vote.BaseOf(vote.BaseVoted), Threshold: &vote.Threshold{Num: 2, Den: 3}},
		"rule >=9/10 elig,": {Rule: vote.RuleThreshold, Base: vote.BaseOf(vote.BaseElig), Threshold: &vote.Threshold{Num: 9, Den: 10}},
		"rule most,":        {Rule: vote.RulePlurality},
	}
	for want, d := range cases {
		in := input()
		in.Decision = d
		s, err := ProposalSummary(mustCanon(t, in))
		if err != nil || !strings.Contains(s, "quorum 1, "+want) || strings.Contains(s, "removed") {
			t.Errorf("%q: %q %v", want, s, err)
		}
	}
}

// elig needs no flag (0.14.1, E-a'): a vote of every eligible member is
// made with removed_may_vote false.
func TestCreateEligWithoutFlag(t *testing.T) {
	m, _, _, a := strictManager(t)
	in := input()
	in.Decision.Base = vote.BaseOf(vote.BaseElig)
	approveProposal(t, a, "a", in)
	if _, err := m.Create(context.Background(), "a", in); err != nil {
		t.Fatal(err)
	}
}

// What the admins could not read as one meaning is refused before
// anything is made, and the approval stays usable.
func TestCreateRefusesDecision(t *testing.T) {
	ctx := context.Background()
	for name, mod := range map[string]func(*ProposalInput){
		"no decision":           func(i *ProposalInput) { i.Decision = vote.Decision{} },
		"removed_may_vote true": func(i *ProposalInput) { i.RemovedMayVote = true },
		"plurality with a base": func(i *ProposalInput) { i.Decision.Rule = vote.RulePlurality },
		"threshold 4/6": func(i *ProposalInput) {
			i.Decision = vote.Decision{Rule: vote.RuleThreshold, Base: vote.BaseOf(vote.BaseCast), Threshold: &vote.Threshold{Num: 4, Den: 6}}
		},
		"quorum over the most eligible": func(i *ProposalInput) { i.Quorum.MinBallots = vote.MaxEligible + 1 },
	} {
		m, _, _, a := strictManager(t)
		in := input()
		mod(&in)
		a.add("a", ActionProposalCreate, mustCanon(t, in), "")
		var ei *ErrInput
		if _, err := m.Create(ctx, "a", in); !errors.As(err, &ei) || a.used["a"] || stored(t, m) != 0 {
			t.Errorf("%s: %v, used %v", name, err, a.used["a"])
		}
		if _, err := ProposalSummary(mustCanon(t, in)); err == nil {
			t.Errorf("%s: summarised", name)
		}
	}
}

// The summary shows the close without its year, so a window that doesn't
// close after it opens, within 7 days, is refused before any summary.
func TestSummaryRefusesWindow(t *testing.T) {
	ctx := context.Background()
	for name, mod := range map[string]func(*ProposalInput){
		"reversed":       func(i *ProposalInput) { i.ClosesAt = i.OpensAt - 3600 },
		"empty":          func(i *ProposalInput) { i.ClosesAt = i.OpensAt },
		"over 7 days":    func(i *ProposalInput) { i.ClosesAt = i.OpensAt + vote.MaxWindow + 1 },
		"a year and two": func(i *ProposalInput) { i.ClosesAt = i.OpensAt + 372*86400 },
	} {
		in := input()
		mod(&in)
		if _, err := ProposalSummary(mustCanon(t, in)); err == nil {
			t.Errorf("%s: summarised", name)
		}
		m, _, _, a := strictManager(t)
		a.add("a", ActionProposalCreate, mustCanon(t, in), "")
		if _, err := m.Create(ctx, "a", in); err == nil || a.used["a"] {
			t.Errorf("%s: %v, used %v", name, err, a.used["a"])
		}
	}
	in := input()
	in.ClosesAt = in.OpensAt + vote.MaxWindow
	if _, err := ProposalSummary(mustCanon(t, in)); err != nil {
		t.Errorf("a 7-day window: %v", err)
	}
}

// A quorum over the roster's eligible members is refused at the moment of
// use, before the approval is used (§3.4).
func TestCreateQuorumUnreachable(t *testing.T) {
	ctx := context.Background()
	m, _, _, a := strictManager(t)
	in := input()
	in.Quorum.MinBallots = int64(len(m.Roster.Eligible())) + 1
	approveProposal(t, a, "a", in)
	if _, err := m.Create(ctx, "a", in); !errors.Is(err, ErrQuorumUnreachable) || a.used["a"] || stored(t, m) != 0 {
		t.Fatalf("%v, used %v", err, a.used["a"])
	}
	in.Quorum.MinBallots--
	approveProposal(t, a, "b", in)
	if _, err := m.Create(ctx, "b", in); err != nil {
		t.Fatalf("a quorum of every eligible member: %v", err)
	}
}

// The proposal carries the approved decision, and its results the outcome.
func TestCreateCarriesDecision(t *testing.T) {
	ctx := context.Background()
	m, _, _, a := strictManager(t)
	in := input()
	in.Decision = vote.Decision{Rule: vote.RuleThreshold, Base: vote.BaseOf(vote.BaseVoted), Threshold: &vote.Threshold{Num: 3, Den: 4}}
	approveProposal(t, a, "a", in)
	c, err := m.Create(ctx, "a", in)
	if err != nil {
		t.Fatal(err)
	}
	m.Wait()
	o, err := m.Store.OpenProposalFresh(ctx, c.ProposalID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := vote.ParseProposal(o.Doc)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decision; d.Rule != vote.RuleThreshold || *d.Base != vote.BaseVoted || *d.Threshold != (vote.Threshold{Num: 3, Den: 4}) {
		t.Fatalf("decision %+v", d)
	}
}
