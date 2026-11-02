package ballot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/vote"
)

// strictManager is a manager whose approvals are the registry of
// fakeApprovals, as approval.Manager.Consume checks them.
func strictManager(t *testing.T) (*Manager, *fakeSender, *fakePublisher, *fakeApprovals) {
	t.Helper()
	m, s, p := newManager(t)
	a := &fakeApprovals{approved: map[string]fakeApproval{}, used: map[string]bool{}}
	m.Approvals = a
	return m, s, p, a
}

func approveProposal(t *testing.T, a *fakeApprovals, id string, in ProposalInput) {
	t.Helper()
	pl, err := CanonicalProposal(in)
	if err != nil {
		t.Fatal(err)
	}
	a.add(id, ActionProposalCreate, pl, "")
}

func stored(t *testing.T, m *Manager) int {
	t.Helper()
	recs, err := m.Store.Records.Load(context.Background(), KindProposal)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs)
}

func TestCreateNeedsApproval(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		id     string
		setup  func(a *fakeApprovals)
		change func(in *ProposalInput)
	}{
		"no approval id": {id: ""},
		"unknown":        {id: "nope"},
		"pending":        {id: "a", setup: func(a *fakeApprovals) { a.add("a", ActionProposalCreate, mustCanon(t, input()), "pending") }},
		"denied":         {id: "a", setup: func(a *fakeApprovals) { a.add("a", ActionProposalCreate, mustCanon(t, input()), "denied") }},
		"expired":        {id: "a", setup: func(a *fakeApprovals) { a.add("a", ActionProposalCreate, mustCanon(t, input()), "expired") }},
		"wrong action":   {id: "a", setup: func(a *fakeApprovals) { a.add("a", ActionVoteExtend, mustCanon(t, input()), "") }},
		"one byte off": {id: "a", setup: func(a *fakeApprovals) { approveProposal(t, a, "a", input()) },
			change: func(in *ProposalInput) { in.Title = "Adopt the 2027 budgex" }},
		"a field the approval lacks": {id: "a", setup: func(a *fakeApprovals) { approveProposal(t, a, "a", input()) },
			change: func(in *ProposalInput) { in.Binding = true }},
		"another window": {id: "a", setup: func(a *fakeApprovals) { approveProposal(t, a, "a", input()) },
			change: func(in *ProposalInput) { in.ClosesAt++ }},
	} {
		t.Run(name, func(t *testing.T) {
			m, s, pub, a := strictManager(t)
			if tc.setup != nil {
				tc.setup(a)
			}
			in := input()
			if tc.change != nil {
				tc.change(&in)
			}
			if _, err := m.Create(ctx, tc.id, in); err == nil {
				t.Fatal("created without a matching approval")
			}
			if stored(t, m) != 0 || pub.calls != 0 || len(s.sent) != 0 || a.consumed != 0 {
				t.Fatalf("something was done: stored %d, published %d, sent %d, consumed %d", stored(t, m), pub.calls, len(s.sent), a.consumed)
			}
		})
	}
}

func mustCanon(t *testing.T, in ProposalInput) []byte {
	t.Helper()
	b, err := CanonicalProposal(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCreateConsumesApprovalOnce(t *testing.T) {
	ctx := context.Background()
	m, s, _, a := strictManager(t)
	approveProposal(t, a, "a", input())
	if _, err := m.Create(ctx, "a", input()); err != nil {
		t.Fatal(err)
	}
	if !a.used["a"] || stored(t, m) != 1 || len(s.sent) != 3 {
		t.Fatalf("used %v, stored %d", a.used["a"], stored(t, m))
	}
	if _, err := m.Create(ctx, "a", input()); err == nil || stored(t, m) != 1 {
		t.Fatalf("a second use: %v, stored %d", err, stored(t, m))
	}
}

func TestCreateConcurrentUse(t *testing.T) {
	ctx := context.Background()
	m, _, _, a := strictManager(t)
	approveProposal(t, a, "a", input())
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = m.Create(ctx, "a", input())
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) || stored(t, m) != 1 {
		t.Fatalf("results %v, %v; stored %d", errs[0], errs[1], stored(t, m))
	}
}

// A refusal before the approval is used leaves it usable; a failure
// after leaves it used.
func TestCreateApprovalOrder(t *testing.T) {
	ctx := context.Background()
	m, _, pub, a := strictManager(t)
	approveProposal(t, a, "a", input())
	roster := m.Roster
	m.Roster = fakeRoster{}
	var ei *ErrInput
	if _, err := m.Create(ctx, "a", input()); !errors.As(err, &ei) || a.used["a"] {
		t.Fatalf("no eligible members: %v, used %v", err, a.used["a"])
	}
	m.Publisher = nil
	m.Roster = roster
	if _, err := m.Create(ctx, "a", input()); !errors.Is(err, ErrNoPublisher) || a.used["a"] {
		t.Fatalf("no publisher: %v, used %v", err, a.used["a"])
	}
	m.Publisher = pub
	pub.fail = true
	var np *ErrNotPublished
	if _, err := m.Create(ctx, "a", input()); !errors.As(err, &np) || !a.used["a"] {
		t.Fatalf("publication failed: %v, used %v", err, a.used["a"])
	}
	pub.fail = false
	if _, err := m.Create(ctx, "a", input()); err == nil {
		t.Fatal("an approval used by a create that failed to publish was used again")
	}
}

func TestNoApprovalsRefuses(t *testing.T) {
	m, _, _ := newManager(t)
	m.Approvals = nil
	if _, err := m.Create(context.Background(), "a", input()); !errors.Is(err, ErrNoApprovals) || stored(t, m) != 0 {
		t.Fatalf("%v", err)
	}
}

// extendFixture is a created proposal and an extension of it.
func extendFixture(t *testing.T) (*Manager, *fakeSender, *fakeApprovals, string, ExtensionInput) {
	t.Helper()
	m, s, _ := newManager(t)
	c, err := m.Create(context.Background(), "apv", input())
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeApprovals{approved: map[string]fakeApproval{}, used: map[string]bool{}}
	m.Approvals = a
	in := input()
	clock := time.Unix(in.ClosesAt-600, 0)
	m.Now = func() time.Time { return clock }
	x := ExtensionInput{ClosesAt: in.ClosesAt + 7200, Outage: vote.Outage{From: in.ClosesAt - 7200, To: in.ClosesAt - 7200 + 5400, Source: "https://status.vettid.org/"}}
	s.sent = nil
	return m, s, a, c.ProposalID, x
}

func approveExtension(t *testing.T, a *fakeApprovals, apv, pid string, x ExtensionInput) {
	t.Helper()
	pl, err := CanonicalExtension(pid, x)
	if err != nil {
		t.Fatal(err)
	}
	a.add(apv, ActionVoteExtend, pl, "")
}

func extended(t *testing.T, m *Manager, pid string) int {
	t.Helper()
	o, err := m.Store.OpenProposal(context.Background(), pid)
	if err != nil {
		t.Fatal(err)
	}
	return len(o.Extensions)
}

func TestExtendNeedsApproval(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput){
		"no approval id": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {},
		"pending": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {
			a.add("a", ActionVoteExtend, mustExt(t, pid, x), "pending")
		},
		"denied": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {
			a.add("a", ActionVoteExtend, mustExt(t, pid, x), "denied")
		},
		"wrong action": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {
			a.add("a", ActionProposalCreate, mustExt(t, pid, x), "")
		},
		"another proposal": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {
			a.add("a", ActionVoteExtend, mustExt(t, "01JBQZ0000000000000000000A", x), "")
		},
		"one byte off": func(t *testing.T, a *fakeApprovals, pid string, x ExtensionInput) {
			y := x
			y.Outage.Source += "x"
			a.add("a", ActionVoteExtend, mustExt(t, pid, y), "")
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, s, a, pid, x := extendFixture(t)
			tc(t, a, pid, x)
			id := "a"
			if name == "no approval id" {
				id = ""
			}
			if _, err := m.Extend(ctx, pid, id, x); err == nil {
				t.Fatal("extended without a matching approval")
			}
			if extended(t, m, pid) != 0 || len(s.sent) != 0 || a.consumed != 0 {
				t.Fatalf("something was done: %d extensions, %d sent", extended(t, m, pid), len(s.sent))
			}
		})
	}
}

func mustExt(t *testing.T, pid string, x ExtensionInput) []byte {
	t.Helper()
	b, err := CanonicalExtension(pid, x)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtendConsumesApprovalOnce(t *testing.T) {
	ctx := context.Background()
	m, _, a, pid, x := extendFixture(t)
	approveExtension(t, a, "a", pid, x)
	// An invalid extension is refused before the approval is used.
	bad := x
	bad.ClosesAt += 10 * 3600
	approveExtension(t, a, "b", pid, bad)
	var ei *ErrInput
	if _, err := m.Extend(ctx, pid, "b", bad); !errors.As(err, &ei) || a.used["b"] {
		t.Fatalf("an invalid extension: %v, used %v", err, a.used["b"])
	}
	if _, err := m.Extend(ctx, pid, "a", x); err != nil {
		t.Fatal(err)
	}
	if !a.used["a"] || extended(t, m, pid) != 1 {
		t.Fatal("not consumed")
	}
	if _, err := m.Extend(ctx, pid, "a", x); err == nil || extended(t, m, pid) != 1 {
		t.Fatalf("a second use: %v", err)
	}
}

func TestExtendConcurrentUse(t *testing.T) {
	ctx := context.Background()
	m, _, a, pid, x := extendFixture(t)
	approveExtension(t, a, "a", pid, x)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = m.Extend(ctx, pid, "a", x)
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) || extended(t, m, pid) != 1 {
		t.Fatalf("results %v, %v; %d extensions", errs[0], errs[1], extended(t, m, pid))
	}
}

func TestProposalSummaryFromPayload(t *testing.T) {
	in := input()
	in.Binding = true
	s, err := ProposalSummary(mustCanon(t, in))
	if err != nil {
		t.Fatal(err)
	}
	opens, _ := when(in.OpensAt)
	closes, _ := when(in.ClosesAt)
	for _, want := range []string{"BINDING", "opens " + opens, "closes " + closes, `"Yes"/"No"`, "quorum 1", `"Adopt the 2027 budget"`} {
		if !strings.Contains(s, want) {
			t.Errorf("%q lacks %q", s, want)
		}
	}
	in.Binding = false
	if s, _ = ProposalSummary(mustCanon(t, in)); !strings.HasPrefix(s, "ADVISORY") {
		t.Errorf("%q", s)
	}
	// A long title is cut, never the rest.
	in.Title = strings.Repeat("Budget ", 25)
	s, err = ProposalSummary(mustCanon(t, in))
	if err != nil || len(s) > maxSummary || !strings.Contains(s, "…") || !strings.Contains(s, "closes "+closes) {
		t.Errorf("%d %q %v", len(s), s, err)
	}
	// What can't be shown honestly is refused.
	for name, mod := range map[string]func(*ProposalInput){
		"bidi title":    func(i *ProposalInput) { i.Title = "a\u202eb" },
		"newline title": func(i *ProposalInput) { i.Title = "a\nb" },
		"empty title":   func(i *ProposalInput) { i.Title = "" },
		"bidi label":    func(i *ProposalInput) { i.Choices[0].Label = "Y\u2066es" },
		"time":          func(i *ProposalInput) { i.OpensAt = 5 },
		"many choices": func(i *ProposalInput) {
			for k := range 12 {
				i.Choices = append(i.Choices, ChoiceInput{Label: strings.Repeat("l", 10) + string(rune('a'+k))})
			}
		},
		"text":           func(i *ProposalInput) { i.Text = "A different motion" },
		"quorum text":    func(i *ProposalInput) { i.Quorum.Text = "A third" },
		"outage rule":    func(i *ProposalInput) { i.OutageRule = "Never extended" },
		"long label":     func(i *ProposalInput) { i.Choices[0].Label = strings.Repeat("l", 25) },
		"abstain label":  func(i *ProposalInput) { i.Choices[0].Label = "ABSTAIN" },
		"repeated label": func(i *ProposalInput) { i.Choices[1].Label = "yes" },
		"padded label":   func(i *ProposalInput) { i.Choices[1].Label = "No " },
		"one choice":     func(i *ProposalInput) { i.Choices = i.Choices[:1] },
		"seventeen":      func(i *ProposalInput) { i.Choices = make([]ChoiceInput, 17) },
	} {
		x := input()
		x.Choices = append([]ChoiceInput{}, x.Choices...)
		mod(&x)
		if _, err := ProposalSummary(mustCanon(t, x)); err == nil {
			t.Errorf("%s: summarized", name)
		}
	}
	// A payload that isn't the canonical full form of an input.
	for name, p := range map[string]string{
		"spaces":     strings.ReplaceAll(string(mustCanon(t, input())), ",", ", "),
		"missing":    `{"title":"T"}`,
		"unknown":    strings.Replace(string(mustCanon(t, input())), `"binding"`, `"extra":1,"binding"`, 1),
		"duplicate":  strings.Replace(string(mustCanon(t, input())), `"binding":false`, `"binding":false,"binding":true`, 1),
		"upper case": strings.Replace(string(mustCanon(t, input())), `"title"`, `"Title"`, 1),
		"bom":        "\xef\xbb\xbf" + string(mustCanon(t, input())),
	} {
		if _, err := ProposalSummary([]byte(p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestExtensionSummaryFromPayload(t *testing.T) {
	x := ExtensionInput{ClosesAt: 1793527200, Outage: vote.Outage{From: 1793512800, To: 1793518200, Source: "https://status.vettid.org/"}}
	pid := "01JBQZ0000000000000000000A"
	s, err := ExtensionSummary(mustExt(t, pid, x), "Adopt the budget")
	closes, _ := when(x.ClosesAt)
	if err != nil || !strings.Contains(s, pid) || !strings.Contains(s, "new close "+closes) || !strings.HasPrefix(s, `"Adopt the budget"`) || !strings.Contains(s, "status.vettid.org") || len(s) > maxSummary {
		t.Fatalf("%q %v", s, err)
	}
	for _, src := range []string{"s", "http://status.vettid.org/", "https://status.vettid.org/long/long/long", "https://a b/"} {
		y := x
		y.Outage.Source = src
		if _, err := ExtensionSummary(mustExt(t, pid, y), "T"); err == nil {
			t.Errorf("source %q accepted", src)
		}
	}
	if _, err := ExtensionSummary([]byte(`{"closes_at":1}`), "T"); err == nil {
		t.Fatal("accepted a partial payload")
	}
	if _, err := ExtensionSummary(mustExt(t, "short", x), "T"); err == nil {
		t.Fatal("accepted a bad proposal id")
	}
}

// Only what the admins' phones show is executed: a field outside that
// is refused, and nothing is created or used.
func TestCreateRefusesFieldsNotShown(t *testing.T) {
	ctx := context.Background()
	for name, mod := range map[string]func(*ProposalInput){
		"text":        func(i *ProposalInput) { i.Text = "A different motion" },
		"quorum text": func(i *ProposalInput) { i.Quorum.Text = "A third" },
		"outage rule": func(i *ProposalInput) { i.OutageRule = "Never extended" },
		"long label":  func(i *ProposalInput) { i.Choices[0].Label = strings.Repeat("l", 25) },
		"abstain":     func(i *ProposalInput) { i.Choices[1].Label = "Abstain" },
	} {
		t.Run(name, func(t *testing.T) {
			m, s, pub, a := strictManager(t)
			in := input()
			in.Choices = append([]ChoiceInput{}, in.Choices...)
			mod(&in)
			a.add("a", ActionProposalCreate, mustCanon(t, in), "")
			var ei *ErrInput
			if _, err := m.Create(ctx, "a", in); !errors.As(err, &ei) {
				t.Fatalf("%v", err)
			}
			if stored(t, m) != 0 || pub.calls != 0 || len(s.sent) != 0 || a.consumed != 0 {
				t.Fatal("something was done")
			}
		})
	}
	// The motion may be the title, or empty; the rule the default or empty.
	m, _, _ := newManager(t)
	in := input()
	in.Text, in.OutageRule = in.Title, ""
	if _, err := m.Create(ctx, "a", in); err != nil {
		t.Fatal(err)
	}
}

// The service assigns the ids: c1, c2, … in the order of the labels, then
// abstain; the executed rule is the default.
func TestCreateAssignsChoiceIDs(t *testing.T) {
	ctx := context.Background()
	m, _, _ := newManager(t)
	in := input()
	in.Choices = append(in.Choices, ChoiceInput{Label: "Maybe"})
	in.OutageRule = ""
	c, err := m.Create(ctx, "a", in)
	if err != nil {
		t.Fatal(err)
	}
	o, _ := m.Store.OpenProposal(ctx, c.ProposalID)
	p, _ := o.Parsed()
	var ids []string
	for _, ch := range p.Choices {
		ids = append(ids, ch.ID+"="+ch.Label)
	}
	if got := strings.Join(ids, ","); got != "c1=Yes,c2=No,c3=Maybe,abstain=Abstain" || p.OutageRule != DefaultOutageRule || p.Quorum.Text != "" {
		t.Fatalf("%s, %q", got, p.OutageRule)
	}
	// An application-supplied id is not a field of the input.
	var x ProposalInput
	if err := parseCanonical([]byte(`{"binding":false,"choices":[{"id":"abstain","label":"Yes"}]}`), &x); err == nil {
		t.Fatal("accepted an id")
	}
}
