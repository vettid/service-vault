package vote

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/suite"
)

func TestCanonicalize(t *testing.T) {
	for in, want := range map[string]string{
		// Members sorted by UTF-16 code units: U+1F600 (a surrogate pair,
		// 0xD83D…) sorts before U+FFFD, unlike by code point.
		`{"b":1,"a":[true,false,null],"😀":"x","�":"y"}`: `{"a":[true,false,null],"b":1,"😀":"x","�":"y"}`,
		"{\"s\":\"a\\u0001\\n\\\"\\\\/é<>&\"}":          "{\"s\":\"a\\u0001\\n\\\"\\\\/é<>&\"}",
		` { "n" : -12 , "z" : 9007199254740991 } `:      `{"n":-12,"z":9007199254740991}`,
	} {
		got, err := Canonicalize([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("Canonicalize(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
	// Nesting is bounded: a deep input is refused, not a stack overflow.
	deep := strings.Repeat("[", 1<<20) + strings.Repeat("]", 1<<20)
	if _, err := Canonicalize([]byte(deep)); err == nil {
		t.Error("a deeply nested input accepted")
	}
	ok := `{"a":` + strings.Repeat("[", MaxDepth-1) + strings.Repeat("]", MaxDepth-1) + `}`
	if _, err := Canonicalize([]byte(ok)); err != nil {
		t.Errorf("nesting of %d refused: %v", MaxDepth, err)
	}
	for _, in := range []string{
		`{"a":1,"a":2}`, `{"a":{"b":1,"b":1}}`, `{"a":1.5}`, `{"a":1e3}`, `{"a":-0}`,
		`{"a":9007199254740992}`, `{"a":1} x`, "{\"a\":\"\xff\"}", `[1,]`,
	} {
		if _, err := Canonicalize([]byte(in)); err == nil {
			t.Errorf("Canonicalize(%s) accepted", in)
		}
	}
}

func testProposal(t *testing.T, ik ed25519.PublicKey, tags [][]byte) *Proposal {
	t.Helper()
	return &Proposal{
		V: 1, ProposalID: "01JBQZ0000000000000000000A", Service: ik,
		Title: "Adopt the 2027 budget", Text: "The budget as circulated on 1 November.",
		Choices: []Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}, {ID: AbstainID, Label: "Abstain"}},
		Quorum:  Quorum{Text: "A third of the members", MinBallots: 1},
		Binding: false, RecordAt: 1793500000, OpensAt: 1793520000, ClosesAt: 1793520000 + 3*86400,
		Eligible: int64(len(tags)), RecordRoot: Root(tags), OutageRule: "Extended by a relay outage over 1 hour, 24 h at most.",
	}
}

func TestProposalRoundTrip(t *testing.T) {
	ik := ed25519.NewKeyFromSeed(digest("ik")).Public().(ed25519.PublicKey)
	p := testProposal(t, ik, [][]byte{digest("t1"), digest("t2")})
	b, err := EncodeProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseProposal(b)
	if err != nil || got.Title != p.Title || !bytes.Equal(got.RecordRoot, p.RecordRoot) {
		t.Fatalf("round trip: %v", err)
	}
	// Not the exact canonical bytes.
	for name, bad := range map[string][]byte{
		"whitespace":      append([]byte(" "), b...),
		"unknown field":   bytes.Replace(b, []byte(`{"binding"`), []byte(`{"extra":1,"binding"`), 1),
		"missing field":   bytes.Replace(b, []byte(`"binding":false,`), nil, 1),
		"null field":      bytes.Replace(b, []byte(`"binding":false`), []byte(`"binding":null`), 1),
		"mistyped field":  bytes.Replace(b, []byte(`"binding":false`), []byte(`"binding":"false"`), 1),
		"unpadded base64": unpad(t, b),
	} {
		if _, err := ParseProposal(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Field rules.
	for name, mut := range map[string]func(*Proposal){
		"no abstain":     func(p *Proposal) { p.Choices[2].ID = "maybe" },
		"two choices":    func(p *Proposal) { p.Choices = p.Choices[:2] },
		"repeated id":    func(p *Proposal) { p.Choices[1].ID = "yes" },
		"long window":    func(p *Proposal) { p.ClosesAt = p.OpensAt + MaxWindow + 1 },
		"record after":   func(p *Proposal) { p.RecordAt = p.OpensAt + 1 },
		"empty title":    func(p *Proposal) { p.Title = "" },
		"bad id":         func(p *Proposal) { p.ProposalID = "x" },
		"short root":     func(p *Proposal) { p.RecordRoot = p.RecordRoot[:31] },
		"short service":  func(p *Proposal) { p.Service = p.Service[:31] },
		"version":        func(p *Proposal) { p.V = 2 },
		"negative quota": func(p *Proposal) { p.Quorum.MinBallots = -1 },
	} {
		q := *testProposal(t, ik, [][]byte{digest("t1")})
		q.Choices = append([]Choice{}, q.Choices...)
		mut(&q)
		if _, err := EncodeProposal(&q); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// unpad strips the padding of the proposal's service key, a form
// encoding/json would decode.
func unpad(t *testing.T, b []byte) []byte {
	t.Helper()
	i := bytes.Index(b, []byte(`"service":"`))
	j := bytes.IndexByte(b[i+11:], '"')
	key := b[i+11 : i+11+j]
	if !bytes.HasSuffix(key, []byte("=")) {
		t.Fatal("test key has no padding")
	}
	return bytes.Replace(b, key, bytes.TrimRight(key, "="), 1)
}

// vote builds a signed proposal, n eligible tags, and ballots for the
// first k of them, as the service would.
type vote struct {
	ik      ed25519.PrivateKey
	propDoc []byte
	ph      []byte
	tags    [][]byte
	ballots map[string]Ballot
}

func newVote(t *testing.T, n, k int) *vote {
	t.Helper()
	v := &vote{ik: ed25519.NewKeyFromSeed(digest("service ik")), ballots: map[string]Ballot{}}
	for i := range n {
		tag, _ := RecordTag("01JBQZ0000000000000000000A", digest(string(rune('a'+i))))
		v.tags = append(v.tags, tag)
	}
	sorted := append([][]byte{}, v.tags...)
	sortTags(sorted)
	p := testProposal(t, v.ik.Public().(ed25519.PublicKey), sorted)
	var err error
	if v.propDoc, err = EncodeProposal(p); err != nil {
		t.Fatal(err)
	}
	v.ph = sum(v.propDoc)
	choices := []string{"yes", "no", AbstainID}
	for i := range k {
		sk := ed25519.NewKeyFromSeed(digest("voter " + string(rune('a'+i))))
		b := Ballot{RecordTag: v.tags[i], VK: sk.Public().(ed25519.PublicKey), ChoiceID: choices[i%3]}
		msg, _ := b.Msg(v.ph)
		b.BallotSig, _ = suite.Sign(sk, LabelBallot, msg)
		v.ballots[string(b.RecordTag)] = b
	}
	return v
}

func (v *vote) sign(t *testing.T, label string, msg []byte) []byte {
	t.Helper()
	s, err := suite.Sign(v.ik, label, msg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (v *vote) count(t *testing.T, exts ...[]byte) (rows, results, sig []byte) {
	t.Helper()
	c := &Count{
		Proposal: Signed{Doc: v.propDoc, Sig: v.sign(t, LabelProposal, ProposalSigMsg(v.propDoc))},
		Tags:     v.tags, Ballots: v.ballots, Removed: 1,
	}
	for _, e := range exts {
		m, _ := DocSigMsg(v.ph, e)
		c.Extensions = append(c.Extensions, Signed{Doc: e, Sig: v.sign(t, LabelExtended, m)})
	}
	rows, results, err := c.Build()
	if err != nil {
		t.Fatal(err)
	}
	m, _ := DocSigMsg(v.ph, results)
	return rows, results, v.sign(t, LabelResults, m)
}

func TestResultsCheck(t *testing.T) {
	v := newVote(t, 7, 5)
	ik := v.ik.Public().(ed25519.PublicKey)
	rows, results, sig := v.count(t)
	p, res, err := Check(ik, results, sig, rows)
	if err != nil {
		t.Fatal(err)
	}
	if res.Counts.Ballots != 5 || res.Counts.Eligible != 7 || res.Tally["yes"] != 2 || res.Tally["no"] != 2 || res.Tally[AbstainID] != 1 {
		t.Fatalf("counts %+v tally %v", res.Counts, res.Tally)
	}
	// The vault's view: its row and proof reach rows_root.
	row, proof, err := RowProof(rows, v.tags[0])
	if err != nil || row.Ballot == nil {
		t.Fatalf("row proof: %v", err)
	}
	leaf, _ := row.Leaf()
	if !VerifyProof(res.RowsRoot, leaf, indexOf(t, rows, v.tags[0]), int(p.Eligible), proof) {
		t.Fatal("row proof doesn't reach rows_root")
	}
	empty, _, err := RowProof(rows, v.tags[6])
	if err != nil || empty.Ballot != nil {
		t.Fatal("a tag that didn't vote has a ballot")
	}

	// Tampering is caught.
	other := ed25519.NewKeyFromSeed(digest("other")).Public().(ed25519.PublicKey)
	if _, _, err := Check(other, results, sig, rows); err == nil {
		t.Error("another service's key accepted")
	}
	if _, _, err := Check(ik, results, append([]byte{sig[0] ^ 1}, sig[1:]...), rows); err == nil {
		t.Error("bad results signature accepted")
	}
	changed := bytes.Replace(rows, []byte(`"choice_id":"yes"`), []byte(`"choice_id":"no"`), 1)
	if _, _, err := Check(ik, results, sig, changed); err == nil {
		t.Error("changed rows accepted")
	}
	// A recount of changed rows, re-signed: the ballot signature fails.
	b := v.ballots[string(v.tags[0])]
	b.ChoiceID = "no"
	v.ballots[string(v.tags[0])] = b
	rows2, results2, sig2 := v.count(t)
	if _, _, err := Check(ik, results2, sig2, rows2); err == nil || !strings.Contains(err.Error(), "ballot signature") {
		t.Errorf("a changed ballot: %v", err)
	}
}

func TestResultsExtensions(t *testing.T) {
	v := newVote(t, 3, 2)
	ik := v.ik.Public().(ed25519.PublicKey)
	p, _ := ParseProposal(v.propDoc)
	ext := func(n, closes int64) []byte {
		b, err := EncodeExtension(&Extension{V: 1, ProposalID: p.ProposalID, N: n, ClosesAt: closes,
			Outage: Outage{From: p.ClosesAt - 7200, To: p.ClosesAt - 3600, Source: "https://status.vettid.org/"}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rows, results, sig := v.count(t, ext(1, p.ClosesAt+3600), ext(2, p.ClosesAt+7200))
	if _, _, err := Check(ik, results, sig, rows); err != nil {
		t.Fatal(err)
	}
	rows, results, sig = v.count(t, ext(1, p.ClosesAt+MaxExtension+3600))
	if _, _, err := Check(ik, results, sig, rows); err == nil {
		t.Error("extensions over 24 h accepted")
	}
	rows, results, sig = v.count(t, ext(2, p.ClosesAt+3600))
	if _, _, err := Check(ik, results, sig, rows); err == nil {
		t.Error("an extension out of order accepted")
	}
}

func TestBuildRefuses(t *testing.T) {
	v := newVote(t, 3, 1)
	stray, _ := RecordTag("01JBQZ0000000000000000000A", digest("stray"))
	b := v.ballots[string(v.tags[0])]
	b.RecordTag = stray
	v.ballots[string(stray)] = b
	c := &Count{Proposal: Signed{Doc: v.propDoc, Sig: make([]byte, SigLen)}, Tags: v.tags, Ballots: v.ballots}
	if _, _, err := c.Build(); err == nil {
		t.Fatal("a ballot under a tag that isn't eligible was counted")
	}
}

func indexOf(t *testing.T, rowsBytes, tag []byte) int {
	t.Helper()
	r, err := ParseRows(rowsBytes)
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Rows {
		if bytes.Equal(r.Rows[i].RecordTag, tag) {
			return i
		}
	}
	t.Fatal("tag not found")
	return -1
}
