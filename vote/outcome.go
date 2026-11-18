package vote

import (
	"errors"
	"fmt"
)

// The decision rule a proposal states and the outcome its results state
// (BALLOT-PROTOCOL §3.5, §7.1).

// Rules.
const (
	RuleMajority  = "majority"
	RuleThreshold = "threshold"
	RulePlurality = "plurality"
)

// Bases: what a majority or a threshold is of.
const (
	BaseCast  = "cast"  // ballots for a real choice (abstain left out)
	BaseVoted = "voted" // every ballot, abstain included
	BaseElig  = "elig"  // the proposal's eligible members
)

// MaxThresholdDen is the largest denominator of a threshold.
const MaxThresholdDen = 10

// Outcome statuses.
const (
	StatusDecided    = "decided"
	StatusNotDecided = "not_decided"
	StatusTied       = "tied"
	StatusNoQuorum   = "no_quorum"
)

// BaseOf is a base, as Decision.Base takes it.
func BaseOf(b string) *string { return &b }

// Threshold is a fraction num/den of the base.
type Threshold struct {
	Num int64 `json:"num"`
	Den int64 `json:"den"`
}

// Decision is how a vote is decided: a rule, the base it is of (null for
// plurality), and the threshold (only for the threshold rule, else null).
type Decision struct {
	Rule      string     `json:"rule"`
	Base      *string    `json:"base"`
	Threshold *Threshold `json:"threshold"`
}

// Outcome is the results' outcome: whether the quorum was met, the status,
// and the decided choice (only when decided, else null).
type Outcome struct {
	QuorumMet bool    `json:"quorum_met"`
	Status    string  `json:"status"`
	Choice    *string `json:"choice"`
}

func gcd(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Validate checks a decision (§3.5). removedMayVote is the proposal's:
// the base elig is allowed only when removed members may still vote.
func (d *Decision) Validate(removedMayVote bool) error {
	bad := func(what string) error { return fmt.Errorf("ballot: decision %s", what) }
	switch d.Rule {
	case RulePlurality:
		if d.Base != nil {
			return bad("base with plurality")
		}
	case RuleMajority, RuleThreshold:
		if d.Base == nil {
			return bad("without a base")
		}
		switch *d.Base {
		case BaseCast, BaseVoted:
		case BaseElig:
			if !removedMayVote {
				return bad("base elig without removed_may_vote")
			}
		default:
			return bad("base")
		}
	default:
		return bad("rule")
	}
	if (d.Rule == RuleThreshold) != (d.Threshold != nil) {
		return bad("threshold")
	}
	if t := d.Threshold; t != nil {
		if t.Den < 1 || t.Den > MaxThresholdDen || t.Num < 1 || t.Num > t.Den || 2*t.Num <= t.Den || gcd(t.Num, t.Den) != 1 {
			return bad("threshold fraction")
		}
	}
	return nil
}

// Decide computes the outcome (§7.1) from a valid proposal, the tally and
// the number of ballots. It refuses a tally that doesn't name exactly the
// proposal's choices, a negative count, a sum other than ballots, or more
// ballots than eligible members.
func Decide(p *Proposal, tally map[string]int64, ballots int64) (Outcome, error) {
	if len(tally) != len(p.Choices) || ballots < 0 || ballots > p.Eligible {
		return Outcome{}, errors.New("ballot: tally doesn't match the proposal")
	}
	var sum, cast int64
	for _, c := range p.Choices {
		n, ok := tally[c.ID]
		if !ok || n < 0 {
			return Outcome{}, errors.New("ballot: tally doesn't match the proposal")
		}
		sum += n
		if c.ID != AbstainID {
			cast += n
		}
	}
	if sum != ballots {
		return Outcome{}, errors.New("ballot: tally doesn't sum to the ballots")
	}
	// 1. The quorum.
	if ballots < p.Quorum.MinBallots {
		return Outcome{Status: StatusNoQuorum}, nil
	}
	decided := func(id string) Outcome { return Outcome{QuorumMet: true, Status: StatusDecided, Choice: &id} }
	none := Outcome{QuorumMet: true, Status: StatusNotDecided}
	d := p.Decision
	if d.Rule == RulePlurality {
		var top int64
		var at []string
		for _, c := range p.Choices {
			if c.ID == AbstainID {
				continue
			}
			switch n := tally[c.ID]; {
			case n > top:
				top, at = n, []string{c.ID}
			case n == top:
				at = append(at, c.ID)
			}
		}
		switch {
		case top == 0:
			return none, nil
		case len(at) == 1:
			return decided(at[0]), nil
		default:
			return Outcome{QuorumMet: true, Status: StatusTied}, nil
		}
	}
	// 2. The base; a base of 0 decides nothing.
	var base int64
	switch *d.Base {
	case BaseCast:
		base = cast
	case BaseVoted:
		base = ballots
	case BaseElig:
		base = p.Eligible
	}
	if base == 0 {
		return none, nil
	}
	// 3. The rule, over the real choices only. At most one can qualify,
	// since a threshold is above one half.
	var won []string
	for _, c := range p.Choices {
		if c.ID == AbstainID {
			continue
		}
		n := tally[c.ID]
		if d.Rule == RuleMajority && 2*n > base || d.Rule == RuleThreshold && n*d.Threshold.Den >= base*d.Threshold.Num {
			won = append(won, c.ID)
		}
	}
	switch len(won) {
	case 0:
		return none, nil
	case 1:
		return decided(won[0]), nil
	default:
		return Outcome{}, errors.New("ballot: two choices decided")
	}
}

// validate checks an outcome's own consistency (§8.5).
func (o *Outcome) validate() error {
	switch o.Status {
	case StatusDecided, StatusNotDecided, StatusTied, StatusNoQuorum:
	default:
		return errors.New("ballot: outcome status")
	}
	if o.QuorumMet == (o.Status == StatusNoQuorum) || (o.Choice != nil) != (o.Status == StatusDecided) ||
		o.Choice != nil && (!ValidChoiceID(*o.Choice) || *o.Choice == AbstainID) {
		return errors.New("ballot: outcome inconsistent")
	}
	return nil
}
