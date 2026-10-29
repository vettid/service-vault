package ballot

import (
	"bytes"
	"errors"
	"fmt"
)

// RowLeaf is a row's Merkle leaf: its ballot's leaf, or the tag alone
// (§8.2).
func (r *Row) Leaf() ([]byte, error) {
	if r.Ballot == nil {
		return EmptyRowLeaf(r.RecordTag)
	}
	return (&Ballot{RecordTag: r.RecordTag, VK: r.Ballot.VK, ChoiceID: r.Ballot.ChoiceID, BallotSig: r.Ballot.BallotSig}).Leaf()
}

func rowLeaves(rows []Row) ([][]byte, error) {
	leaves := make([][]byte, len(rows))
	for i := range rows {
		l, err := rows[i].Leaf()
		if err != nil {
			return nil, err
		}
		leaves[i] = l
	}
	return leaves, nil
}

// Count is what the results are built from: the signed proposal and
// extensions, every eligible tag, the accepted ballots by tag, and the
// number of members removed or suspended during the vote.
type Count struct {
	Proposal   Signed
	Extensions []Signed
	Tags       [][]byte
	Ballots    map[string]Ballot // by string(record_tag)
	Removed    int64
}

// Build makes the rows and results documents (§7). It refuses a ballot
// whose tag isn't eligible or whose choice isn't the proposal's.
func (c *Count) Build() (rowsBytes, resultsBytes []byte, err error) {
	p, err := ParseProposal(c.Proposal.Doc)
	if err != nil {
		return nil, nil, err
	}
	rows := make([]Row, len(c.Tags))
	eligible := map[string]bool{}
	for i, t := range c.Tags {
		rows[i] = Row{RecordTag: t}
		eligible[string(t)] = true
	}
	sortRows(rows)
	tally := map[string]int64{}
	for _, ch := range p.Choices {
		tally[ch.ID] = 0
	}
	var n int64
	for i := range rows {
		b, ok := c.Ballots[string(rows[i].RecordTag)]
		if !ok {
			continue
		}
		if !p.HasChoice(b.ChoiceID) {
			return nil, nil, fmt.Errorf("ballot: choice %q isn't the proposal's", b.ChoiceID)
		}
		rows[i].Ballot = &RowBallot{VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
		tally[b.ChoiceID]++
		n++
	}
	for t := range c.Ballots {
		if !eligible[t] {
			return nil, nil, errors.New("ballot: a ballot under a tag that isn't eligible")
		}
	}
	rowsBytes, err = EncodeRows(&Rows{V: 1, ProposalID: p.ProposalID, Rows: rows})
	if err != nil {
		return nil, nil, err
	}
	leaves, err := rowLeaves(rows)
	if err != nil {
		return nil, nil, err
	}
	exts := c.Extensions
	if exts == nil {
		exts = []Signed{}
	}
	resultsBytes, err = EncodeResults(&Results{
		V: 1, ProposalID: p.ProposalID, Proposal: c.Proposal, Extensions: exts,
		RowsHash: sum(rowsBytes), RowsRoot: Root(leaves), Tally: tally,
		Counts: Counts{Eligible: int64(len(c.Tags)), Ballots: n, Removed: c.Removed},
	})
	return rowsBytes, resultsBytes, err
}

// RowProof returns the row of tag in rows, with its inclusion proof to
// rows_root (§8.3: the app hands the vault its row and this proof).
func RowProof(rowsBytes, tag []byte) (*Row, [][]byte, error) {
	r, err := ParseRows(rowsBytes)
	if err != nil {
		return nil, nil, err
	}
	leaves, err := rowLeaves(r.Rows)
	if err != nil {
		return nil, nil, err
	}
	for i := range r.Rows {
		if bytes.Equal(r.Rows[i].RecordTag, tag) {
			proof, err := Proof(leaves, i)
			return &r.Rows[i], proof, err
		}
	}
	return nil, nil, errors.New("ballot: no row for this tag")
}

// Check is an observer's check of a vote's results (§8.4), from the
// service's identity key and the published bytes. It returns the parsed
// proposal and results. The Rekor bundles are checked separately.
func Check(serviceIK, resultsBytes, resultsSig, rowsBytes []byte) (*Proposal, *Results, error) {
	res, err := ParseResults(resultsBytes)
	if err != nil {
		return nil, nil, err
	}
	p, err := ParseProposal(res.Proposal.Doc)
	if err != nil {
		return nil, nil, err
	}
	ph := sum(res.Proposal.Doc)
	fail := func(f string, a ...any) error { return fmt.Errorf("ballot: results: "+f, a...) }
	// 1. Signatures, under the key the proposal names, which is the
	// service's.
	if !bytes.Equal(p.Service, serviceIK) || p.ProposalID != res.ProposalID {
		return nil, nil, fail("not this service's proposal")
	}
	if Verify(serviceIK, LabelProposal, ProposalSigMsg(res.Proposal.Doc), res.Proposal.Sig) != nil {
		return nil, nil, fail("proposal signature")
	}
	m, _ := DocSigMsg(ph, resultsBytes)
	if Verify(serviceIK, LabelResults, m, resultsSig) != nil {
		return nil, nil, fail("results signature")
	}
	closes, added := p.ClosesAt, int64(0)
	for i, s := range res.Extensions {
		e, err := ParseExtension(s.Doc)
		if err != nil {
			return nil, nil, err
		}
		m, _ := DocSigMsg(ph, s.Doc)
		if Verify(serviceIK, LabelExtended, m, s.Sig) != nil {
			return nil, nil, fail("extension %d signature", i+1)
		}
		// 5. Each extends the close in force, in order, within 24 h in all.
		if e.ProposalID != p.ProposalID || e.N != int64(i+1) || e.ClosesAt <= closes {
			return nil, nil, fail("extension %d out of order", i+1)
		}
		added += e.ClosesAt - closes
		closes = e.ClosesAt
	}
	if added > MaxExtension {
		return nil, nil, fail("extensions exceed 24 h")
	}
	// 2. The rows: their hash, the tags against record_root, the root.
	if !bytes.Equal(sum(rowsBytes), res.RowsHash) {
		return nil, nil, fail("rows hash")
	}
	rows, err := ParseRows(rowsBytes)
	if err != nil {
		return nil, nil, err
	}
	if rows.ProposalID != p.ProposalID || int64(len(rows.Rows)) != p.Eligible || res.Counts.Eligible != p.Eligible {
		return nil, nil, fail("rows don't match the proposal")
	}
	tags := make([][]byte, len(rows.Rows))
	for i := range rows.Rows {
		tags[i] = rows.Rows[i].RecordTag
	}
	if !bytes.Equal(Root(tags), p.RecordRoot) {
		return nil, nil, fail("tags don't reach record_root")
	}
	leaves, err := rowLeaves(rows.Rows)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(Root(leaves), res.RowsRoot) {
		return nil, nil, fail("rows root")
	}
	// 3 and 4. Every ballot, and the tally.
	tally := map[string]int64{}
	for _, c := range p.Choices {
		tally[c.ID] = 0
	}
	var n int64
	for i, row := range rows.Rows {
		if row.Ballot == nil {
			continue
		}
		b := Ballot{RecordTag: row.RecordTag, VK: row.Ballot.VK, ChoiceID: row.Ballot.ChoiceID, BallotSig: row.Ballot.BallotSig}
		if !p.HasChoice(b.ChoiceID) {
			return nil, nil, fail("row %d: choice", i)
		}
		msg, err := b.Msg(ph)
		if err != nil || Verify(b.VK, LabelBallot, msg, b.BallotSig) != nil {
			return nil, nil, fail("row %d: ballot signature", i)
		}
		tally[b.ChoiceID]++
		n++
	}
	if len(tally) != len(res.Tally) || res.Counts.Ballots != n {
		return nil, nil, fail("tally")
	}
	for k, v := range tally {
		if res.Tally[k] != v {
			return nil, nil, fail("tally for %q", k)
		}
	}
	return p, res, nil
}
