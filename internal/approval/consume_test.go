package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/vote"
)

func proposalInput() ballot.ProposalInput {
	return ballot.ProposalInput{Title: "Adopt the 2027 budget",
		Choices: []ballot.ChoiceInput{{Label: "Yes"}, {Label: "No"}},
		Quorum:  vote.Quorum{MinBallots: 1}, Binding: true, OpensAt: 1793520000, ClosesAt: 1793520000 + 86400,
		OutageRule: ballot.DefaultOutageRule}
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
	f.m.ProposalTitle = func(_ context.Context, id string) (string, bool, error) {
		return "Adopt the 2027 budget", id == extProposal, nil
	}
	return f.create(action, "", string(payload))
}

func (f *fixture) consume(id, action string, payload []byte) error {
	return f.m.Consume(context.Background(), id, action, payload, ballot.Use{ProposalID: extProposal, N: 1})
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
	if !strings.Contains(ctxt, "New vote: "+want) || !regexp.MustCompile(` — ref [0-9a-f]{16}$`).MatchString(ctxt) || !strings.HasSuffix(ctxt, c.ActionHash[:16]) {
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
	if s := f.status(h.ID).Summary; !strings.HasPrefix(s, `"Adopt the 2027 budget" (`+extProposal+`)`) || !strings.Contains(s, "new close ") ||
		!strings.Contains(f.p.last("c1").ctxt, "Extend vote: \"Adopt") {
		t.Fatalf("summary %q", s)
	}
	// No text from the application, and only an exact full-form payload.
	for name, req := range map[string]Request{
		"a summary":   {Action: ActionProposalCreate, Summary: "Routine", Payload: json.RawMessage(pl)},
		"spaced":      {Action: ActionProposalCreate, Payload: json.RawMessage(strings.ReplaceAll(string(pl), `":`, `": `))},
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
	if _, err := ChallengeContext("S", ActionAdminSetAdd, "x", "abcdef01"); err == nil {
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
			g := &Manager{Peer: f.p, Store: f.st, Pager: f.st, Now: f.clk.Now, ServiceName: f.m.ServiceName, ProposalTitle: f.m.ProposalTitle}
			ms := []*Manager{f.m, g, f.m, g}
			errs := make([]error, len(ms))
			var wg sync.WaitGroup
			for i, m := range ms {
				wg.Add(1)
				go func() {
					defer wg.Done()
					errs[i] = m.Consume(context.Background(), a.ID, tc.action, pl, ballot.Use{ProposalID: extProposal, N: 1})
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

// A summary an application writes can't start as the service's own do,
// and every context starts with the action's label.
func TestReservedSummaryStarts(t *testing.T) {
	f := newFixture(t, 1, "c1")
	for _, s := range []string{"BINDING vote", "binding", "Advisory: x", "EXTEND vote x", " extend", "New vote: x", "Add admin: c9",
		"remove admin c1", "Contract template: x", "push assignment"} {
		_, err := f.m.Create(context.Background(), Request{Action: ActionContractTemplateChange, Summary: s, Payload: json.RawMessage(`{}`)})
		if codeOf(err) != CodeInvalidSummary {
			t.Errorf("%q: %v", s, err)
		}
	}
	for action, label := range ActionLabels {
		if action == ActionProposalCreate || action == ActionVoteExtend {
			continue
		}
		g := newFixture(t, 1, "c1", "c9")
		payload := `{}`
		if strings.HasPrefix(action, "admin_set") {
			payload = `{"connection_id":"c9"}`
		}
		routine := "Routine"
		if BuiltSummary(action) {
			routine = ""
		}
		_, err := g.m.Create(context.Background(), Request{Action: action, Summary: routine, Payload: json.RawMessage(payload)})
		if err != nil && action != ActionAdminSetAdd {
			t.Fatalf("%s: %v", action, err)
		}
		if err == nil && !strings.Contains(g.p.sent[0].ctxt, ": "+label+" ") {
			t.Errorf("%s: %q", action, g.p.sent[0].ctxt)
		}
	}
}

// A field the phones would not show is refused when the approval is
// asked for, with nothing sent; so is an extension of an unknown
// proposal.
func TestFieldsNotShownRefused(t *testing.T) {
	f := newFixture(t, 1, "c1")
	f.m.ProposalTitle = func(_ context.Context, id string) (string, bool, error) { return "T", id == extProposal, nil }
	for name, mod := range map[string]func(*ballot.ProposalInput){
		"text":        func(i *ballot.ProposalInput) { i.Text = "A longer motion than the title" },
		"quorum text": func(i *ballot.ProposalInput) { i.Quorum.Text = "A third of the members" },
		"outage rule": func(i *ballot.ProposalInput) { i.OutageRule = "No extension, ever" },
	} {
		in := proposalInput()
		mod(&in)
		_, err := f.m.Create(context.Background(), Request{Action: ActionProposalCreate, Payload: json.RawMessage(canonProposal(t, in))})
		if codeOf(err) != CodeFieldNotShown {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The motion may be the title; the rule may be empty.
	in := proposalInput()
	in.Text, in.OutageRule = in.Title, ""
	f.built(ActionProposalCreate, canonProposal(t, in))
	n := len(f.p.sent)
	for name, mod := range map[string]func(*ballot.ExtensionInput){
		"source":    func(x *ballot.ExtensionInput) { x.Outage.Source = "see the relay's status page" },
		"long":      func(x *ballot.ExtensionInput) { x.Outage.Source = "https://status.vettid.org/a/very/long/path" },
		"not https": func(x *ballot.ExtensionInput) { x.Outage.Source = "http://status.vettid.org/" },
	} {
		x := extensionInput()
		mod(&x)
		_, err := f.m.Create(context.Background(), Request{Action: ActionVoteExtend, Payload: json.RawMessage(canonExtension(t, x))})
		if codeOf(err) != CodeFieldNotShown {
			t.Errorf("%s: %v", name, err)
		}
	}
	other, _ := ballot.CanonicalExtension("01JBQZ0000000000000000000B", extensionInput())
	if _, err := f.m.Create(context.Background(), Request{Action: ActionVoteExtend, Payload: json.RawMessage(other)}); codeOf(err) != CodeUnknownProposal {
		t.Errorf("unknown proposal: %v", err)
	}
	f.m.ProposalTitle = nil
	if _, err := f.m.Create(context.Background(), Request{Action: ActionVoteExtend, Payload: json.RawMessage(canonExtension(t, extensionInput()))}); codeOf(err) != CodeUnknownProposal {
		t.Errorf("no lookup: %v", err)
	}
	if len(f.p.sent) != n {
		t.Fatal("a refused approval was sent to the admins")
	}
}

// Consume counts again: with m = 2, an approval whose signatures are no
// longer m from the admins now in the set is not usable.
func TestConsumeRecounts(t *testing.T) {
	f := newFixture(t, 2, "c1", "c2", "c3")
	pl := canonProposal(t, proposalInput())
	a := f.built(ActionProposalCreate, pl)
	f.answer("c1", "approve")
	f.answer("c2", "approve")
	if s := f.status(a.ID); s.Status != StatusApproved {
		t.Fatalf("status %s", s.Status)
	}
	if err := f.m.ConnectionRemoved(context.Background(), "c1"); err != nil {
		t.Fatal(err)
	}
	if code := codeOf(f.consume(a.ID, ActionProposalCreate, pl)); code != CodeApprovalNotApproved {
		t.Fatalf("after an approver was removed: %q", code)
	}
	if _, used, _ := f.st.Get(context.Background(), kindUsed, a.ID); used {
		t.Fatal("used")
	}
	// A raised threshold counts too.
	g := newFixture(t, 1, "c1", "c2")
	b := g.built(ActionProposalCreate, pl)
	g.answer("c1", "approve")
	g.m.Threshold = 2
	if code := codeOf(g.consume(b.ID, ActionProposalCreate, pl)); code != CodeApprovalNotApproved {
		t.Fatalf("threshold raised: %q", code)
	}
	g.m.Threshold = 1
	if err := g.consume(b.ID, ActionProposalCreate, pl); err != nil {
		t.Fatal(err)
	}
}

// admin_set.* summaries are built from the payload: the name the member
// gave (marked so), when the connection was made, the key's fingerprint
// and the id. The application writes none.
func TestAdminSetSummaryBuilt(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, 1, "c1", "c2")
	f.p.names = map[string]string{"c2": "Ann \"Q\" \u00c9lise", "c1": "Bob"}
	f.p.active["c3"] = true
	f.p.active["c5"], f.p.active["c6"], f.p.active["c7"], f.p.active["c8"] = true, true, true, true
	f.p.names["c5"] = strings.Repeat("n", MaxAdminName+1)
	f.p.names["c6"] = "Ann \u0410nn"
	f.p.names["c7"] = " Ann"
	f.p.noAuth = map[string]bool{"c8": true}
	f.p.states = map[string]string{"c4": "suspended"}
	for _, a := range []string{ActionAdminSetAdd, ActionAdminSetRemove} {
		_, err := f.m.Create(ctx, Request{Action: a, Summary: "Open the vote", Payload: json.RawMessage(`{"connection_id":"c3"}`)})
		if codeOf(err) != CodeInvalidSummary {
			t.Errorf("%s with a summary: %v", a, err)
		}
	}
	n := len(f.p.sent)
	for name, p := range map[string]string{"unknown": `{"connection_id":"c9"}`, "inactive": `{"connection_id":"c4"}`,
		"already admin": `{"connection_id":"c2"}`, "quote": `{"connection_id":"c\"3"}`, "long id": `{"connection_id":"` + strings.Repeat("c", 41) + `"}`,
		"long name": `{"connection_id":"c5"}`, "cyrillic name": `{"connection_id":"c6"}`, "padded name": `{"connection_id":"c7"}`,
		"no credential key": `{"connection_id":"c8"}`} {
		if _, err := f.m.Create(ctx, Request{Action: ActionAdminSetAdd, Payload: json.RawMessage(p)}); err == nil {
			t.Errorf("add %s accepted", name)
		}
	}
	if len(f.p.sent) != n {
		t.Fatal("a refused approval was sent")
	}
	fp := sha256.Sum256(append([]byte("vettid/vms/2/ik-fp"), fakeIK("c3")...))
	h := hex.EncodeToString(fp[:8])
	want := "name not given, connected 2026-11-02, key " + h[:4] + " " + h[4:8] + " " + h[8:12] + " " + h[12:] + ", connection c3"
	c := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	if s := f.status(c.ID).Summary; s != want {
		t.Fatalf("%q, want %q", s, want)
	}
	if ctxt := f.p.last("c1").ctxt; !strings.Contains(ctxt, "Add admin: "+want+" — ref ") {
		t.Fatalf("%q", ctxt)
	}
	f.p.names["c3"] = "Jane Doe, treasurer"
	g := f.create(ActionAdminSetAdd, "", `{"connection_id":"c3"}`)
	if s := f.status(g.ID).Summary; !strings.HasPrefix(s, `name given "Jane Doe, treasurer", connected 2026-11-02, key `) {
		t.Fatalf("%q", s)
	}
	// Removing: the same, and an unknown connection names only its id.
	r := f.create(ActionAdminSetRemove, "", `{"connection_id":"c2"}`)
	if s := f.status(r.ID).Summary; !strings.HasPrefix(s, "name given \"Ann \\\"Q\\\" \u00c9lise\", connected ") || !strings.HasSuffix(s, ", connection c2") {
		t.Fatalf("%q", s)
	}
	if ctxt := f.p.last("c1").ctxt; !strings.Contains(ctxt, "Remove admin: ") {
		t.Fatalf("%q", ctxt)
	}
}

// The longest admin_set summary fits the context whole, with the longest
// service name and either label.
func TestAdminSetSummaryFitsContext(t *testing.T) {
	f := newFixture(t, 1, "c1")
	id := strings.Repeat("c", 40)
	f.p.active[id] = true
	f.p.names = map[string]string{id: strings.Repeat("n", MaxAdminName)}
	f.m.ServiceName = strings.Repeat("S", MaxServiceName)
	for _, a := range []string{ActionAdminSetAdd, ActionAdminSetRemove} {
		sum, err := f.m.adminSetSummary(a, []byte(`{"connection_id":"`+id+`"}`))
		if err != nil || len(sum) > MaxAdminSummary {
			t.Fatalf("%s: %d %v", a, len(sum), err)
		}
		if _, err := ChallengeContext(f.m.ServiceName, a, sum, strings.Repeat("a", 64)); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
}

// The use is recorded with what the approval made: in the apv_used
// record, the approval.consumed audit entry and the status.
func TestConsumeRecordsUse(t *testing.T) {
	for name, tc := range consumeCases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, "c1")
			pl := tc.payload(t)
			a := f.built(tc.action, pl)
			f.answer("c1", "approve")
			if f.status(a.ID).Used != nil {
				t.Fatal("used before")
			}
			if err := f.m.Consume(context.Background(), a.ID, tc.action, pl, ballot.Use{ProposalID: "01JBQZ0000000000000000000C", N: 3}); err != nil {
				t.Fatal(err)
			}
			u := f.status(a.ID).Used
			if u == nil || u.ProposalID != "01JBQZ0000000000000000000C" || u.N != 3 || u.At.IsZero() {
				t.Fatalf("status used %+v", u)
			}
			n := 0
			for _, e := range f.audit() {
				if e.Type == AuditConsumed && e.ProposalID == "01JBQZ0000000000000000000C" && e.N == 3 {
					n++
				}
			}
			if n != 1 {
				t.Fatalf("%d entries with the use", n)
			}
			if err := f.m.Consume(context.Background(), a.ID, tc.action, pl, ballot.Use{}); err == nil {
				t.Fatal("a use with no proposal")
			}
		})
	}
}

// An approval whose summary is not the one the service builds from the
// payload (made before the summary was the service's) is refused; so is an
// extension whose proposal's title is no longer what the admins read.
func TestConsumeChecksSummary(t *testing.T) {
	for name, tc := range consumeCases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1, "c1")
			pl := tc.payload(t)
			a := f.built(tc.action, pl)
			f.answer("c1", "approve")
			ctx := context.Background()
			r, err := f.m.load(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			r.Summary = "Routine budget vote"
			b := f.m.batch(f.clk.Now())
			if err := errors.Join(b.save(r), b.apply(ctx)); err != nil {
				t.Fatal(err)
			}
			if code := codeOf(f.consume(a.ID, tc.action, pl)); code != CodeApprovalMismatch {
				t.Fatalf("app-written summary: %q", code)
			}
			if _, used, _ := f.st.Get(ctx, kindUsed, a.ID); used {
				t.Fatal("used")
			}
		})
	}
	f := newFixture(t, 1, "c1")
	pl := canonExtension(t, extensionInput())
	a := f.built(ActionVoteExtend, pl)
	f.answer("c1", "approve")
	f.m.ProposalTitle = func(context.Context, string) (string, bool, error) { return "Another title", true, nil }
	if code := codeOf(f.consume(a.ID, ActionVoteExtend, pl)); code != CodeApprovalMismatch {
		t.Fatalf("another title: %q", code)
	}
}

// An extension's summary shows the stored title whole or is refused.
func TestExtensionTitleWholeOrRefused(t *testing.T) {
	f := newFixture(t, 1, "c1")
	pl := canonExtension(t, extensionInput())
	for name, title := range map[string]string{"long": strings.Repeat("T", 80), "cyrillic": "Budg\u0435t"} {
		f.m.ProposalTitle = func(context.Context, string) (string, bool, error) { return title, true, nil }
		_, err := f.m.Create(context.Background(), Request{Action: ActionVoteExtend, Payload: json.RawMessage(pl)})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(f.p.sent) != 0 {
		t.Fatal("sent")
	}
}
