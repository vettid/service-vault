package ballot

import (
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"
)

// The documents of BALLOT-PROTOCOL §8.5. Each is encoded as JCS
// (Encode*), and parsed only from its exact canonical bytes, with every
// field present and no other (Parse*). Binary fields are []byte, which
// encoding/json writes as standard base64 with padding.

// MaxWindow is the longest voting window, opens_at to closes_at (§3.1;
// owner decision).
const MaxWindow = 7 * 24 * 3600

// MaxExtension is the most that extensions may add, in total (§10.2).
const MaxExtension = 24 * 3600

// AbstainID is the reserved choice present in every proposal (§3.1).
const AbstainID = "abstain"

// Choice is one of a proposal's choices.
type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Quorum is a proposal's quorum rule.
type Quorum struct {
	Text       string `json:"text"`
	MinBallots int64  `json:"min_ballots"`
}

// Proposal is the proposal document (§3.1, §8.5).
type Proposal struct {
	V              int64    `json:"v"`
	ProposalID     string   `json:"proposal_id"`
	Service        []byte   `json:"service"`
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	Choices        []Choice `json:"choices"`
	Quorum         Quorum   `json:"quorum"`
	Binding        bool     `json:"binding"`
	RemovedMayVote bool     `json:"removed_may_vote"`
	RecordAt       int64    `json:"record_at"`
	OpensAt        int64    `json:"opens_at"`
	ClosesAt       int64    `json:"closes_at"`
	Eligible       int64    `json:"eligible"`
	RecordRoot     []byte   `json:"record_root"`
	OutageRule     string   `json:"outage_rule"`
}

// Outage is the outage an extension is for.
type Outage struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Source string `json:"source"`
}

// Extension is an extension document (§10.2, §8.5).
type Extension struct {
	V          int64  `json:"v"`
	ProposalID string `json:"proposal_id"`
	N          int64  `json:"n"`
	ClosesAt   int64  `json:"closes_at"`
	Outage     Outage `json:"outage"`
}

// RowBallot is a row's ballot as published (§7).
type RowBallot struct {
	VK        []byte `json:"vk"`
	ChoiceID  string `json:"choice_id"`
	BallotSig []byte `json:"ballot_sig"`
}

// Row is one tag of the rows document, with its ballot or nil.
type Row struct {
	RecordTag []byte     `json:"record_tag"`
	Ballot    *RowBallot `json:"ballot"`
}

// Rows is the rows document (§7, §8.5).
type Rows struct {
	V          int64  `json:"v"`
	ProposalID string `json:"proposal_id"`
	Rows       []Row  `json:"rows"`
}

// Signed is a document's bytes with its detached signature.
type Signed struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// Counts are the results' counts.
type Counts struct {
	Eligible int64 `json:"eligible"`
	Ballots  int64 `json:"ballots"`
	Removed  int64 `json:"removed"`
}

// Results is the results document (§7, §8.5).
type Results struct {
	V          int64            `json:"v"`
	ProposalID string           `json:"proposal_id"`
	Proposal   Signed           `json:"proposal"`
	Extensions []Signed         `json:"extensions"`
	RowsHash   []byte           `json:"rows_hash"`
	RowsRoot   []byte           `json:"rows_root"`
	Tally      map[string]int64 `json:"tally"`
	Counts     Counts           `json:"counts"`
}

// schema is the exact member names of a document's objects: a key maps to
// nested names for an object, "[]" plus names for an array of objects, or
// nil for a leaf. "?" marks a member that may be null.
type schema map[string]any

var (
	signedSchema   = schema{"doc": nil, "sig": nil}
	proposalSchema = schema{
		"v": nil, "proposal_id": nil, "service": nil, "title": nil, "text": nil,
		"choices": []any{schema{"id": nil, "label": nil}},
		"quorum":  schema{"text": nil, "min_ballots": nil},
		"binding": nil, "removed_may_vote": nil, "record_at": nil, "opens_at": nil,
		"closes_at": nil, "eligible": nil, "record_root": nil, "outage_rule": nil,
	}
	extensionSchema = schema{
		"v": nil, "proposal_id": nil, "n": nil, "closes_at": nil,
		"outage": schema{"from": nil, "to": nil, "source": nil},
	}
	rowsSchema = schema{
		"v": nil, "proposal_id": nil,
		"rows": []any{schema{"record_tag": nil, "ballot?": schema{"vk": nil, "choice_id": nil, "ballot_sig": nil}}},
	}
	resultsSchema = schema{
		"v": nil, "proposal_id": nil, "proposal": signedSchema,
		"extensions": []any{signedSchema}, "rows_hash": nil, "rows_root": nil,
		"tally":  "map",
		"counts": schema{"eligible": nil, "ballots": nil, "removed": nil},
	}
)

// checkSchema refuses an object whose members aren't exactly the
// schema's.
func checkSchema(m map[string]any, s schema, path string) error {
	want := map[string]bool{}
	for k, sub := range s {
		nullable := k[len(k)-1] == '?'
		name := k
		if nullable {
			name = k[:len(k)-1]
		}
		want[name] = true
		v, ok := m[name]
		if !ok {
			return fmt.Errorf("%w: %s%s missing", errJCS, path, name)
		}
		if v == nil {
			if nullable {
				continue
			}
			return fmt.Errorf("%w: %s%s is null", errJCS, path, name)
		}
		switch t := sub.(type) {
		case schema:
			o, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: %s%s not an object", errJCS, path, name)
			}
			if err := checkSchema(o, t, path+name+"."); err != nil {
				return err
			}
		case []any:
			a, ok := v.([]any)
			if !ok {
				return fmt.Errorf("%w: %s%s not an array", errJCS, path, name)
			}
			for i, e := range a {
				o, ok := e.(map[string]any)
				if !ok {
					return fmt.Errorf("%w: %s%s[%d] not an object", errJCS, path, name, i)
				}
				if err := checkSchema(o, t[0].(schema), fmt.Sprintf("%s%s[%d].", path, name, i)); err != nil {
					return err
				}
			}
		case string: // "map": an object of integers
			o, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("%w: %s%s not an object", errJCS, path, name)
			}
			for k, e := range o {
				if _, ok := e.(int64); !ok {
					return fmt.Errorf("%w: %s%s.%s not an integer", errJCS, path, name, k)
				}
			}
		}
	}
	for k := range m {
		if !want[k] {
			return fmt.Errorf("%w: %s%s unknown", errJCS, path, k)
		}
	}
	return nil
}

// parseDoc checks data's canonical form and schema, then decodes it.
// Leaf types are checked by the decode (a string where an integer belongs
// fails) and by each document's Validate.
func parseDoc(data []byte, s schema, out any) error {
	m, err := checkCanonical(data)
	if err != nil {
		return err
	}
	if err := checkSchema(m, s, ""); err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: %v", errJCS, err)
	}
	// encoding/json accepts some forms a re-encode would change (for
	// example base64 without padding); the round trip refuses them.
	again, err := encodeCanonical(out)
	if err != nil || string(again) != string(data) {
		return fmt.Errorf("%w: a field is not in its canonical form", errJCS)
	}
	return nil
}

// EncodeProposal validates p and returns its canonical bytes.
func EncodeProposal(p *Proposal) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return encodeCanonical(p)
}

// ParseProposal parses and validates a proposal's exact bytes.
func ParseProposal(data []byte) (*Proposal, error) {
	var p Proposal
	if err := parseDoc(data, proposalSchema, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks a proposal's fields (§3.1).
func (p *Proposal) Validate() error {
	bad := func(what string) error { return fmt.Errorf("ballot: proposal %s", what) }
	switch {
	case p.V != 1:
		return bad("version")
	case !ValidProposalID(p.ProposalID):
		return bad("id")
	case len(p.Service) != VKLen:
		return bad("service key")
	case len(p.Title) == 0 || len(p.Title) > 200:
		return bad("title")
	case len(p.Text) > 16<<10:
		return bad("text")
	case len(p.Choices) < 3 || len(p.Choices) > 17:
		return bad("number of choices")
	case p.Quorum.MinBallots < 0:
		return bad("quorum")
	case p.RecordAt > p.OpensAt || p.OpensAt >= p.ClosesAt || p.ClosesAt-p.OpensAt > MaxWindow:
		return bad("times")
	case p.Eligible < 0 || len(p.RecordRoot) != HashLen:
		return bad("record")
	}
	seen, abstain := map[string]bool{}, false
	for _, c := range p.Choices {
		if !ValidChoiceID(c.ID) || seen[c.ID] || c.Label == "" {
			return bad("choice")
		}
		seen[c.ID] = true
		abstain = abstain || c.ID == AbstainID
	}
	if !abstain {
		return bad("without abstain")
	}
	for _, s := range []string{p.Title, p.Text, p.Quorum.Text, p.OutageRule} {
		if !utf8.ValidString(s) {
			return bad("text encoding")
		}
	}
	return nil
}

// HasChoice reports whether id is one of the proposal's choices.
func (p *Proposal) HasChoice(id string) bool {
	for _, c := range p.Choices {
		if c.ID == id {
			return true
		}
	}
	return false
}

// EncodeExtension validates e and returns its canonical bytes.
func EncodeExtension(e *Extension) ([]byte, error) {
	if err := e.validate(); err != nil {
		return nil, err
	}
	return encodeCanonical(e)
}

// ParseExtension parses an extension's exact bytes.
func ParseExtension(data []byte) (*Extension, error) {
	var e Extension
	if err := parseDoc(data, extensionSchema, &e); err != nil {
		return nil, err
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	return &e, nil
}

func (e *Extension) validate() error {
	if e.V != 1 || !ValidProposalID(e.ProposalID) || e.N < 1 || e.Outage.From > e.Outage.To || e.Outage.Source == "" {
		return fmt.Errorf("ballot: extension fields")
	}
	return nil
}

// EncodeRows returns the rows document's canonical bytes; rows must be
// sorted by tag.
func EncodeRows(r *Rows) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return encodeCanonical(r)
}

// ParseRows parses a rows document's exact bytes.
func ParseRows(data []byte) (*Rows, error) {
	var r Rows
	if err := parseDoc(data, rowsSchema, &r); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Rows) validate() error {
	if r.V != 1 || !ValidProposalID(r.ProposalID) {
		return fmt.Errorf("ballot: rows fields")
	}
	for i, row := range r.Rows {
		if len(row.RecordTag) != HashLen {
			return fmt.Errorf("ballot: row %d tag", i)
		}
		if i > 0 && string(r.Rows[i-1].RecordTag) >= string(row.RecordTag) {
			return fmt.Errorf("ballot: rows not sorted, or a tag repeated, at %d", i)
		}
		if b := row.Ballot; b != nil && (len(b.VK) != VKLen || !ValidChoiceID(b.ChoiceID) || len(b.BallotSig) != SigLen) {
			return fmt.Errorf("ballot: row %d ballot", i)
		}
	}
	return nil
}

// EncodeResults returns the results document's canonical bytes.
func EncodeResults(r *Results) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	return encodeCanonical(r)
}

// ParseResults parses a results document's exact bytes.
func ParseResults(data []byte) (*Results, error) {
	var r Results
	if err := parseDoc(data, resultsSchema, &r); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *Results) validate() error {
	if r.V != 1 || !ValidProposalID(r.ProposalID) || len(r.RowsHash) != HashLen || len(r.RowsRoot) != HashLen ||
		len(r.Proposal.Sig) != SigLen || r.Tally == nil || r.Extensions == nil {
		return fmt.Errorf("ballot: results fields")
	}
	for _, e := range r.Extensions {
		if len(e.Sig) != SigLen {
			return fmt.Errorf("ballot: results extension signature")
		}
	}
	return nil
}

// sortRows sorts rows by tag.
func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool { return string(rows[i].RecordTag) < string(rows[j].RecordTag) })
}
