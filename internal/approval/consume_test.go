package approval

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/vote"
)

func proposalInput() ballot.ProposalInput {
	return ballot.ProposalInput{Title: "Adopt the 2027 budget", Text: "As circulated.",
		Choices: []vote.Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}},
		Quorum:  vote.Quorum{Text: "A third", MinBallots: 1}, Binding: true, OpensAt: 1793520000, ClosesAt: 1793520000 + 86400,
		OutageRule: "Extended by a relay outage over 1 hour, 24 h at most."}
}

func extensionInput() ballot.ExtensionInput {
	return ballot.ExtensionInput{ClosesAt: 1793520000 + 86400 + 7200,
		Outage: vote.Outage{From: 1793600000, To: 1793605400, Source: "https://status.vettid.org/"}}
}

const extProposal = "01JBQZ0000000000000000000A"

func canonProposal(t *testing.T, in ballot.ProposalInput) []byte {
	t.Helper()
	b, err := ballot.CanonicalProposal(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func canonExtension(t *testing.T, in ballot.ExtensionInput) []byte {
	t.Helper()
	b, err := ballot.CanonicalExtension(extProposal, in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// built creates an approval of a built-summary action and returns it with
// its payload.
func (f *fixture) built(action string, payload []byte) *Created {
	f.t.Helper()
	return f.create(action, "", string(payload))
}

func (f *fixture) consume(id, action string, payload []byte) error {
	return f.m.Consume(context.Background(), id, action, payload)
}

func TestVoteOpenAndCloseAreUnknownActions(t *testing.T) {
	f := newFixture(t, 1, "c1")
	for _, a := range []string{"vote.open", "vote.close"} {
		_, err := f.m.Create(context.Background(), Request{Action: a, Summary: "x", Payload: json.RawMessage(`{}`)})
		if codeOf(err) != CodeInvalidAction {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// The summary the admins read is built from the payload; the application
// supplies none.
func TestBuiltSummary(t *testing.T) {
	f := newFixture(t, 1, "c1")
	pl := canonProposal(t, proposalInput())
	want, err := ballot.ProposalSummary(pl)
	if err != nil {
		t.Fatal(err)
	}
	c := f.built(ActionProposalCreate, pl)
	st := f.status(c.ID)
	if st.Summary != want || !strings.HasPrefix(want, "BINDING") {
		t.Fatalf("summary %q, want %q", st.Summary, want)
	}
	ctxt := f.p.sent[0].ctxt
	if !strings.Contains(ctxt, want) || !regexp.MustCompile(` — ref [0-9a-f]{16}$`).MatchString(ctxt) || !strings.HasSuffix(ctxt, c.ActionHash[:16]) {
		t.Fatalf("context %q", ctxt)
	}
	// The summary is in the audit entry, as built.
	if a := f.audit(); a[0].Summary != want {
		t.Fatalf("audit %q", a[0].Summary)
	}
	// A different payload gives a different summary.
	in := proposalInput()
	in.Binding, in.Title = false, "Something else"
	g := f.built(ActionProposalCreate, canonProposal(t, in))
	if s := f.status(g.ID).Summary; !strings.HasPrefix(s, "ADVISORY") || !strings.Contains(s, "Something else") {
		t.Fatalf("summary %q", s)
	}
	// Extension.
	h := f.built(ActionVoteExtend, canonExtension(t, extensionInput()))
	if s := f.status(h.ID).Summary; !strings.HasPrefix(s, "EXTEND vote "+extProposal) || !strings.Contains(s, "new close ") {
		t.Fatalf("summary %q", s)
	}
	// No text from the application, and only an exact full-form payload.
	for name, req := range map[string]Request{
		"a summary":   {Action: ActionProposalCreate, Summary: "Routine", Payload: json.RawMessage(pl)},
		"spaced":      {Action: ActionProposalCreate, Payload: json.RawMessage(strings.ReplaceAll(string(pl), ",", ", "))},
		"partial":     {Action: ActionProposalCreate, Payload: json.RawMessage(`{"title":"T"}`)},
		"ext partial": {Action: ActionVoteExtend, Payload: json.RawMessage(`{"closes_at":1}`)},
		"ext summary": {Action: ActionVoteExtend, Summary: "x", Payload: json.RawMessage(canonExtension(t, extensionInput()))},
	} {
		_, err := f.m.Create(context.Background(), req)
		if c := codeOf(err); (name == "a summary" || name == "ext summary") && c != CodeInvalidSummary || strings.Contains(name, "partial") && c != CodeInvalidPayload || name == "spaced" && c != "" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestChallengeRefIs16Hex(t *testing.T) {
	f := newFixture(t, 1, "c1")
	c := f.create(ActionContractTemplateChange, "Change", `{}`)
	if m := regexp.MustCompile(`ref ([0-9a-f]+)$`).FindStringSubmatch(f.p.sent[0].ctxt); m == nil || len(m[1]) < 16 || m[1] != c.ActionHash[:len(m[1])] {
		t.Fatalf("context %q", f.p.sent[0].ctxt)
	}
	if _, err := ChallengeContext("S", "x", "abcdef01"); err == nil {
		t.Fatal("a ref of 8 digits")
	}
}

type consumeCase struct {
	action  string
	payload func(t *testing.T) []byte
	off     func(t *testing.T) []byte // the payload, one byte different
	other   string                    // an action it can't be used for
}

var consumeCases = map[string]consumeCase{
	"proposal.create": {ActionProposalCreate,
		func(t *testing.T) []byte { return canonProposal(t, proposalInput()) },
		func(t *testing.T) []byte { in := proposalInput(); in.Title += "x"; return canonProposal(t, in) }, ActionVoteExtend},
	"vote.extend": {ActionVoteExtend,
		func(t *testing.T) []byte { return canonExtension(t, extensionInput()) },
		func(t *testing.T) []byte { in := extensionInput(); in.ClosesAt++; return canonExtension(t, in) }, ActionProposalCreate},
}

func TestConsume(t *testing.T) {
	for name, tc := range consumeCases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, "c1")
			pl := tc.payload(t)
			// Pending.
			c := f.built(tc.action, pl)
			if code := codeOf(f.consume(c.ID, tc.action, pl)); code != CodeApprovalNotApproved {
				t.Fatalf("pending: %q", code)
			}
			// Unknown, empty.
			if code := codeOf(f.consume("01JBQZ0000000000000000000B", tc.action, pl)); code != CodeApprovalNotFound {
				t.Fatalf("unknown: %q", code)
			}
			if code := codeOf(f.consume("", tc.action, pl)); code != CodeApprovalRequired {
				t.Fatalf("empty: %q", code)
			}
			// Denied.
			d := f.built(tc.action, tc.off(t))
			f.answer("c1", "deny")
			if s := f.status(d.ID); s.Status != StatusDenied {
				t.Fatalf("status %s", s.Status)
			}
			if code := codeOf(f.consume(d.ID, tc.action, tc.off(t))); code != CodeApprovalNotApproved {
				t.Fatalf("denied: %q", code)
			}
			// Approved.
			a := f.built(tc.action, pl)
			f.answerTo(f.p.last("c1"), "approve")
			if s := f.status(a.ID); s.Status != StatusApproved {
				t.Fatalf("status %s", s.Status)
			}
			if code := codeOf(f.consume(a.ID, tc.other, pl)); code != CodeApprovalWrongAction {
				t.Fatalf("wrong action: %q", code)
			}
			if code := codeOf(f.consume(a.ID, ActionContractTemplateChange, pl)); code != CodeInvalidAction {
				t.Fatalf("other action: %q", code)
			}
			if code := codeOf(f.consume(a.ID, tc.action, tc.off(t))); code != CodeApprovalMismatch {
				t.Fatalf("one byte off: %q", code)
			}
			if code := codeOf(f.consume(a.ID, tc.action, append(append([]byte{}, pl...), ' '))); code != CodeApprovalMismatch {
				t.Fatalf("trailing space: %q", code)
			}
			if code := codeOf(f.consume(a.ID, tc.action, nil)); code != CodeApprovalMismatch {
				t.Fatalf("no payload: %q", code)
			}
			// None of the refusals used it.
			if _, used, _ := f.st.Get(context.Background(), kindUsed, a.ID); used {
				t.Fatal("used by a refusal")
			}
			if err := f.consume(a.ID, tc.action, pl); err != nil {
				t.Fatal(err)
			}
			if _, used, _ := f.st.Get(context.Background(), kindUsed, a.ID); !used {
				t.Fatal("no apv_used record")
			}
			n := 0
			for _, e := range f.audit() {
				if e.Type == AuditConsumed && e.ApprovalID == a.ID && e.Action == tc.action && e.ActionHash == a.ActionHash {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d approval.consumed entries", n)
			}
			if code := codeOf(f.consume(a.ID, tc.action, pl)); code != CodeApprovalUsed {
				t.Fatalf("second use: %q", code)
			}
		})
	}
}

func TestConsumeConcurrent(t *testing.T) {
	for name, tc := range consumeCases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, "c1")
			pl := tc.payload(t)
			a := f.built(tc.action, pl)
			f.answer("c1", "approve")
			// Two managers over one store, as two processes would be: the
			// store's conditional write decides.
			g := &Manager{Peer: f.p, Store: f.st, Pager: f.st, Now: f.clk.Now, ServiceName: f.m.ServiceName}
			ms := []*Manager{f.m, g, f.m, g}
			errs := make([]error, len(ms))
			var wg sync.WaitGroup
			for i, m := range ms {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs[i] = m.Consume(context.Background(), a.ID, tc.action, pl)
				}()
			}
			wg.Wait()
			ok := 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case codeOf(err) != CodeApprovalUsed:
					t.Errorf("%v", err)
				}
			}
			if ok != 1 {
				t.Fatalf("%d uses succeeded", ok)
			}
		})
	}
}

func TestConsumeExpired(t *testing.T) {
	f := newFixture(t, 1, "c1")
	pl := canonProposal(t, proposalInput())
	a := f.built(ActionProposalCreate, pl)
	f.answer("c1", "approve")
	f.clk.Advance(DefaultTTL + time.Second)
	if code := codeOf(f.consume(a.ID, ActionProposalCreate, pl)); code != CodeApprovalExpired {
		t.Fatalf("%q", code)
	}
	if _, used, _ := f.st.Get(context.Background(), kindUsed, a.ID); used {
		t.Fatal("used")
	}
}
