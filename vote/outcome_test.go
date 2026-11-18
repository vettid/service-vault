package vote

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

// outcomeCase is one §11 item 5 vector: a decision, the proposal fields
// it is judged with, a tally and the outcome Decide gives (nil: refused).
type outcomeCase struct {
	Case           string           `json:"case"`
	Decision       Decision         `json:"decision"`
	RemovedMayVote bool             `json:"removed_may_vote"`
	MinBallots     int64            `json:"min_ballots"`
	Eligible       int64            `json:"eligible"`
	Choices        []string         `json:"choices"`
	Tally          map[string]int64 `json:"tally"`
	Ballots        int64            `json:"ballots"`
	Outcome        *Outcome         `json:"outcome"`
}

// decisionCase is a decision, judged in a proposal with its
// removed_may_vote (always false from 0.14.1), and whether a proposal may
// carry it.
type decisionCase struct {
	Case           string          `json:"case"`
	Decision       json.RawMessage `json:"decision"`
	RemovedMayVote bool            `json:"removed_may_vote"`
	Valid          bool            `json:"valid"`
}

// outcomeShape is an outcome object, and whether a results document may
// carry it whatever the tally (§8.5).
type outcomeShape struct {
	Case    string          `json:"case"`
	Outcome json.RawMessage `json:"outcome"`
	Valid   bool            `json:"valid"`
}

func sp(s string) *string { return &s }

func decided(id string) *Outcome {
	return &Outcome{QuorumMet: true, Status: StatusDecided, Choice: sp(id)}
}

var (
	notDecided = &Outcome{QuorumMet: true, Status: StatusNotDecided}
	tied       = &Outcome{QuorumMet: true, Status: StatusTied}
	noQuorum   = &Outcome{Status: StatusNoQuorum}
	majCast    = Decision{Rule: RuleMajority, Base: BaseOf(BaseCast)}
	majVoted   = Decision{Rule: RuleMajority, Base: BaseOf(BaseVoted)}
	majElig    = Decision{Rule: RuleMajority, Base: BaseOf(BaseElig)}
	plurality  = Decision{Rule: RulePlurality}
	two        = []string{"c1", "c2", AbstainID}
	three      = []string{"c1", "c2", "c3", AbstainID}
)

func thr(num, den int64, base string) Decision {
	return Decision{Rule: RuleThreshold, Base: BaseOf(base), Threshold: &Threshold{Num: num, Den: den}}
}

func outcomeCases() []outcomeCase {
	c := func(name string, d Decision, rmv bool, minB, elig int64, ch []string, tally map[string]int64, ballots int64, want *Outcome) outcomeCase {
		return outcomeCase{name, d, rmv, minB, elig, ch, tally, ballots, want}
	}
	t2 := func(a, b, ab int64) map[string]int64 { return map[string]int64{"c1": a, "c2": b, AbstainID: ab} }
	t3 := func(a, b, d, ab int64) map[string]int64 {
		return map[string]int64{"c1": a, "c2": b, "c3": d, AbstainID: ab}
	}
	return []outcomeCase{
		c("majority of cast", majCast, false, 1, 20, two, t2(6, 4, 5), 15, decided("c1")),
		c("majority of cast, exactly half", majCast, false, 1, 20, two, t2(5, 5, 0), 10, notDecided),
		c("majority of cast, every ballot abstains (base 0)", majCast, false, 1, 20, two, t2(0, 0, 4), 4, notDecided),
		c("majority of voted, abstain holds the majority", majVoted, false, 1, 20, two, t2(2, 1, 10), 13, notDecided),
		c("majority of voted", majVoted, false, 1, 20, two, t2(7, 1, 5), 13, decided("c1")),
		c("majority of elig, exactly half", majElig, false, 1, 20, two, t2(10, 0, 0), 10, notDecided),
		c("majority of elig", majElig, false, 1, 20, two, t2(11, 0, 0), 11, decided("c1")),
		c("threshold 2/3 of cast, at the boundary", thr(2, 3, BaseCast), false, 1, 20, two, t2(6, 3, 0), 9, decided("c1")),
		c("threshold 2/3 of cast, just below", thr(2, 3, BaseCast), false, 1, 20, two, t2(5, 3, 0), 8, notDecided),
		c("threshold 2/3 of voted, abstain counts", thr(2, 3, BaseVoted), false, 1, 20, two, t2(6, 0, 4), 10, notDecided),
		c("threshold 2/3 of voted", thr(2, 3, BaseVoted), false, 1, 20, two, t2(6, 0, 3), 9, decided("c1")),
		c("threshold 3/4 of elig", thr(3, 4, BaseElig), false, 1, 8, two, t2(6, 1, 0), 7, decided("c1")),
		c("threshold 1/1 of cast", thr(1, 1, BaseCast), false, 1, 20, two, t2(4, 0, 2), 6, decided("c1")),
		c("threshold 1/1 of cast, one against", thr(1, 1, BaseCast), false, 1, 20, two, t2(4, 1, 0), 5, notDecided),
		c("threshold 2/3 of cast, base 0", thr(2, 3, BaseCast), false, 0, 20, two, t2(0, 0, 0), 0, notDecided),
		c("majority of cast, three choices, none over half", majCast, false, 1, 20, three, t3(4, 3, 3, 0), 10, notDecided),
		c("plurality", plurality, false, 1, 20, three, t3(3, 2, 1, 0), 6, decided("c1")),
		c("plurality, three-way tie", plurality, false, 1, 20, three, t3(2, 2, 2, 0), 6, tied),
		c("plurality, a tie below the top", plurality, false, 1, 20, three, t3(3, 1, 1, 0), 5, decided("c1")),
		c("plurality, abstain the most ballots", plurality, false, 1, 20, three, t3(0, 1, 0, 9), 10, decided("c2")),
		c("plurality, every real choice at 0", plurality, false, 1, 20, three, t3(0, 0, 0, 3), 3, notDecided),
		c("zero ballots, min_ballots 0", majCast, false, 0, 20, two, t2(0, 0, 0), 0, notDecided),
		c("no_quorum over a majority", majCast, false, 10, 20, two, t2(5, 0, 0), 5, noQuorum),
		c("no_quorum over a plurality tie", plurality, false, 10, 20, three, t3(1, 1, 0, 0), 2, noQuorum),
		c("quorum met exactly, abstain counts toward it", majCast, false, 3, 20, two, t2(1, 0, 2), 3, decided("c1")),
		c("quorum one ballot short", majCast, false, 3, 20, two, t2(1, 0, 1), 2, noQuorum),
		c("zero ballots, min_ballots 1, cast: no_quorum before base 0", majCast, false, 1, 20, two, t2(0, 0, 0), 0, noQuorum),
		c("zero ballots, min_ballots 1, voted: no_quorum before base 0", majVoted, false, 1, 20, two, t2(0, 0, 0), 0, noQuorum),
		c("every ballot abstains below quorum, cast", majCast, false, 5, 20, two, t2(0, 0, 4), 4, noQuorum),
		c("every ballot abstains below quorum, voted", thr(2, 3, BaseVoted), false, 5, 20, two, t2(0, 0, 4), 4, noQuorum),
		c("threshold 2/3 of voted, abstain alone meets the fraction", thr(2, 3, BaseVoted), false, 1, 20, two, t2(1, 0, 8), 9, notDecided),
		c("threshold 3/4 of elig, just below", thr(3, 4, BaseElig), false, 1, 8, two, t2(5, 1, 0), 6, notDecided),
		c("majority of elig, three choices", majElig, false, 1, 10, three, t3(6, 2, 1, 0), 9, decided("c1")),
		c("threshold 2/3 of elig, three choices, none", thr(2, 3, BaseElig), false, 1, 9, three, t3(5, 2, 1, 0), 8, notDecided),
		c("plurality, a top tie over a lower third", plurality, false, 1, 20, three, t3(3, 3, 1, 0), 7, tied),
		c("refused: tally doesn't sum to ballots", majCast, false, 1, 20, two, t2(3, 1, 0), 5, nil),
		c("refused: a negative count", majCast, false, 1, 20, two, t2(10, -3, 0), 7, nil),
		c("refused: tally lacks a choice", majCast, false, 1, 20, two, map[string]int64{"c1": 1, AbstainID: 0}, 1, nil),
		c("refused: tally names another choice", majCast, false, 1, 20, two, map[string]int64{"c1": 1, "c9": 0, AbstainID: 0}, 1, nil),
		c("refused: more ballots than eligible", majCast, false, 1, 2, two, t2(2, 1, 0), 3, nil),
	}
}

func decisionCases() []decisionCase {
	c := func(name, d string, rmv, valid bool) decisionCase {
		return decisionCase{name, json.RawMessage(d), rmv, valid}
	}
	return []decisionCase{
		c("majority of cast", `{"base":"cast","rule":"majority","threshold":null}`, false, true),
		c("majority of voted", `{"base":"voted","rule":"majority","threshold":null}`, false, true),
		c("majority of elig", `{"base":"elig","rule":"majority","threshold":null}`, false, true),
		c("threshold 2/3 of cast", `{"base":"cast","rule":"threshold","threshold":{"den":3,"num":2}}`, false, true),
		c("threshold 9/10 of elig", `{"base":"elig","rule":"threshold","threshold":{"den":10,"num":9}}`, false, true),
		c("threshold 1/1 of voted", `{"base":"voted","rule":"threshold","threshold":{"den":1,"num":1}}`, false, true),
		c("plurality", `{"base":null,"rule":"plurality","threshold":null}`, false, true),
		c("elig with removed_may_vote false (0.14.1)", `{"base":"elig","rule":"majority","threshold":null}`, false, true),
		c("plurality with a base", `{"base":"cast","rule":"plurality","threshold":null}`, false, false),
		c("majority without a base", `{"base":null,"rule":"majority","threshold":null}`, false, false),
		c("threshold without its fraction", `{"base":"cast","rule":"threshold","threshold":null}`, false, false),
		c("a fraction with majority", `{"base":"cast","rule":"majority","threshold":{"den":3,"num":2}}`, false, false),
		c("not in lowest terms (4/6)", `{"base":"cast","rule":"threshold","threshold":{"den":6,"num":4}}`, false, false),
		c("one half is not above one half", `{"base":"cast","rule":"threshold","threshold":{"den":2,"num":1}}`, false, false),
		c("den over 10", `{"base":"cast","rule":"threshold","threshold":{"den":11,"num":10}}`, false, false),
		c("num over den", `{"base":"cast","rule":"threshold","threshold":{"den":2,"num":3}}`, false, false),
		c("den 0", `{"base":"cast","rule":"threshold","threshold":{"den":0,"num":0}}`, false, false),
		c("an unknown rule", `{"base":"cast","rule":"unanimity","threshold":null}`, false, false),
		c("an unknown base", `{"base":"all","rule":"majority","threshold":null}`, false, false),
		c("plurality with a threshold", `{"base":null,"rule":"plurality","threshold":{"den":3,"num":2}}`, false, false),
		c("majority, a null base and a threshold", `{"base":null,"rule":"majority","threshold":{"den":3,"num":2}}`, false, false),
		c("base absent", `{"rule":"plurality","threshold":null}`, false, false),
		c("threshold absent", `{"base":"cast","rule":"majority"}`, false, false),
		c("an unknown member", `{"base":"cast","extra":null,"rule":"majority","threshold":null}`, false, false),
	}
}

func outcomeShapes() []outcomeShape {
	c := func(name, o string, valid bool) outcomeShape { return outcomeShape{name, json.RawMessage(o), valid} }
	return []outcomeShape{
		c("decided", `{"choice":"c1","quorum_met":true,"status":"decided"}`, true),
		c("not_decided", `{"choice":null,"quorum_met":true,"status":"not_decided"}`, true),
		c("tied", `{"choice":null,"quorum_met":true,"status":"tied"}`, true),
		c("no_quorum", `{"choice":null,"quorum_met":false,"status":"no_quorum"}`, true),
		c("quorum not met but decided", `{"choice":"c1","quorum_met":false,"status":"decided"}`, false),
		c("quorum met but no_quorum", `{"choice":null,"quorum_met":true,"status":"no_quorum"}`, false),
		c("decided without a choice", `{"choice":null,"quorum_met":true,"status":"decided"}`, false),
		c("not_decided with a choice", `{"choice":"c1","quorum_met":true,"status":"not_decided"}`, false),
		c("tied with a choice", `{"choice":"c1","quorum_met":true,"status":"tied"}`, false),
		c("abstain decided", `{"choice":"abstain","quorum_met":true,"status":"decided"}`, false),
		c("an unknown status", `{"choice":null,"quorum_met":true,"status":"passed"}`, false),
		c("decided, a choice id outside the grammar", `{"choice":"C1","quorum_met":true,"status":"decided"}`, false),
		c("decided, an empty choice", `{"choice":"","quorum_met":true,"status":"decided"}`, false),
		c("no_quorum with a choice", `{"choice":"c1","quorum_met":false,"status":"no_quorum"}`, false),
		c("quorum not met, not_decided", `{"choice":null,"quorum_met":false,"status":"not_decided"}`, false),
		c("quorum not met, tied", `{"choice":null,"quorum_met":false,"status":"tied"}`, false),
	}
}

func (c *outcomeCase) proposal() *Proposal {
	p := &Proposal{Decision: c.Decision, RemovedMayVote: c.RemovedMayVote, Quorum: Quorum{MinBallots: c.MinBallots}, Eligible: c.Eligible}
	for _, id := range c.Choices {
		p.Choices = append(p.Choices, Choice{ID: id, Label: id})
	}
	return p
}

func TestDecide(t *testing.T) {
	for _, c := range outcomeCases() {
		if err := c.Decision.Validate(); err != nil {
			t.Fatalf("%s: decision: %v", c.Case, err)
		}
		got, err := Decide(c.proposal(), c.Tally, c.Ballots)
		switch {
		case c.Outcome == nil && err == nil:
			t.Errorf("%s: accepted, %+v", c.Case, got)
		case c.Outcome != nil && err != nil:
			t.Errorf("%s: %v", c.Case, err)
		case c.Outcome != nil && !sameOutcome(got, *c.Outcome):
			t.Errorf("%s: got %+v, want %+v", c.Case, got, *c.Outcome)
		case c.Outcome != nil:
			if err := got.validate(); err != nil {
				t.Errorf("%s: Decide gave an inconsistent outcome: %v", c.Case, err)
			}
		}
	}
}

// TestDecisionValidate judges each decision as a proposal's member: in a
// proposal document of its own.
func TestDecisionValidate(t *testing.T) {
	ik := ed25519.NewKeyFromSeed(digest("ik")).Public().(ed25519.PublicKey)
	for _, c := range decisionCases() {
		p := testProposal(t, ik, [][]byte{digest("t1"), digest("t2")})
		p.RemovedMayVote = c.RemovedMayVote
		doc, err := encodeCanonical(p)
		if err != nil {
			t.Fatal(err)
		}
		was := `"decision":{"base":"cast","rule":"majority","threshold":null}`
		if !bytes.Contains(doc, []byte(was)) {
			t.Fatalf("%s: no decision in %s", c.Case, doc)
		}
		doc = bytes.Replace(doc, []byte(was), []byte(`"decision":`+string(c.Decision)), 1)
		if _, err := ParseProposal(doc); (err == nil) != c.Valid {
			t.Errorf("%s: valid %v, err %v", c.Case, c.Valid, err)
		}
	}
}

func TestOutcomeShapes(t *testing.T) {
	for _, c := range outcomeShapes() {
		var o Outcome
		if err := json.Unmarshal(c.Outcome, &o); err != nil {
			t.Fatal(err)
		}
		if err := o.validate(); (err == nil) != c.Valid {
			t.Errorf("%s: valid %v, err %v", c.Case, c.Valid, err)
		}
	}
}

// TestCheckRefusesOutcome: an observer refuses results whose outcome
// doesn't recompute, even when every signature holds.
func TestCheckRefusesOutcome(t *testing.T) {
	// Four ballots: yes, no, abstain, yes. Majority of cast: yes, 2 of 3.
	v := newVote(t, 4, 4)
	rows, results, _ := v.count(t)
	r, err := ParseResults(results)
	if err != nil {
		t.Fatal(err)
	}
	if !sameOutcome(r.Outcome, *decided("yes")) {
		t.Fatalf("fixture outcome %+v", r.Outcome)
	}
	for _, o := range []Outcome{
		{QuorumMet: true, Status: StatusNotDecided},
		{QuorumMet: true, Status: StatusTied},
		{Status: StatusNoQuorum},
		{QuorumMet: true, Status: StatusDecided, Choice: sp("no")},
	} {
		// Compared field by field, not with sameOutcome, which Check uses.
		if o.Status == r.Outcome.Status && o.QuorumMet == r.Outcome.QuorumMet &&
			(o.Choice == nil) == (r.Outcome.Choice == nil) && (o.Choice == nil || *o.Choice == *r.Outcome.Choice) {
			continue
		}
		bad := *r
		bad.Outcome = o
		doc, err := EncodeResults(&bad)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := DocSigMsg(v.ph, doc)
		if _, _, err := Check(v.ik.Public().(ed25519.PublicKey), doc, v.sign(t, LabelResults, m), rows); err == nil {
			t.Errorf("results with outcome %+v accepted", o)
		}
	}
}

// A results document with a negative count is refused as a document,
// before any recount.
func TestResultsRefuseNegativeCounts(t *testing.T) {
	v := newVote(t, 3, 2)
	_, results, _ := v.count(t)
	for name, mod := range map[string]func(*Results){
		"tally":    func(r *Results) { r.Tally["no"] = -1 },
		"ballots":  func(r *Results) { r.Counts.Ballots = -1 },
		"eligible": func(r *Results) { r.Counts.Eligible = -1 },
	} {
		r, err := ParseResults(results)
		if err != nil {
			t.Fatal(err)
		}
		mod(r)
		if _, err := EncodeResults(r); err == nil {
			t.Errorf("%s: encoded", name)
		}
		doc, err := encodeCanonical(r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseResults(doc); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// A proposal whose quorum is more than its eligible members, or whose
// decision is malformed, is refused as a document (a member vault refuses
// it on arrival).
func TestProposalRefusesQuorumAndDecision(t *testing.T) {
	ik := ed25519.NewKeyFromSeed(digest("ik")).Public().(ed25519.PublicKey)
	for name, mod := range map[string]func(*Proposal){
		"quorum over eligible":  func(p *Proposal) { p.Quorum.MinBallots = p.Eligible + 1 },
		"no decision":           func(p *Proposal) { p.Decision = Decision{} },
		"plurality with a base": func(p *Proposal) { p.Decision.Rule = RulePlurality },
		"removed_may_vote true": func(p *Proposal) { p.RemovedMayVote = true },
	} {
		p := testProposal(t, ik, [][]byte{digest("t1"), digest("t2")})
		if _, err := EncodeProposal(p); err != nil {
			t.Fatal(err)
		}
		mod(p)
		if _, err := EncodeProposal(p); err == nil {
			t.Errorf("%s: encoded", name)
		}
		doc, err := encodeCanonical(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseProposal(doc); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	p := testProposal(t, ik, [][]byte{digest("t1"), digest("t2")})
	p.Quorum.MinBallots = p.Eligible
	if _, err := EncodeProposal(p); err != nil {
		t.Errorf("quorum of every eligible member: %v", err)
	}
}

// Decide refuses a decision it can't apply, rather than panic on a nil
// base or read an unknown rule as not_decided.
func TestDecideRefusesDecision(t *testing.T) {
	for name, d := range map[string]Decision{
		"majority, null base": {Rule: RuleMajority},
		"an unknown rule":     {Rule: "unanimity", Base: BaseOf(BaseCast)},
		"an unknown base":     {Rule: RuleMajority, Base: BaseOf("all")},
	} {
		c := outcomeCase{Decision: d, MinBallots: 1, Eligible: 20, Choices: two, Tally: map[string]int64{"c1": 2, "c2": 1, AbstainID: 0}, Ballots: 3}
		if o, err := Decide(c.proposal(), c.Tally, c.Ballots); err == nil {
			t.Errorf("%s: %+v", name, o)
		}
	}
}
