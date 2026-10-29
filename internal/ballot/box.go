package ballot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/vettid/service-vault/internal/peer"
)

// The ballot box's side of the members' requests (BALLOT-PROTOCOL §4.2,
// §6): vote.cast and vote.status, answered with signed receipts, status
// answers and refusals.

// Message types (§4).
const (
	TypeProposal = "vote.proposal"
	TypeExtended = "vote.extended"
	TypeClosed   = "vote.closed"
	TypeCast     = "vote.cast"
	TypeStatus   = "vote.status"
)

// Refusal codes (§4.2).
const (
	CodeNotEligible     = "not_eligible"
	CodeNotOpen         = "not_open"
	CodeClosed          = "closed"
	CodeNotActive       = "not_active"
	CodeAlreadyVoted    = "already_voted"
	CodeBadBallot       = "bad_ballot"
	CodeLate            = "late"
	CodeUnknownProposal = "unknown_proposal"
)

// Member is an eligible connection's tag for one proposal (§3.2).
type Member struct {
	Tag    []byte   `json:"tag"`
	Secret []byte   `json:"secret"`
	Index  int      `json:"index"` // among the sorted tags
	Proof  [][]byte `json:"proof"` // to record_root
}

// OpenProposal is what the box holds of a proposal while it runs.
type OpenProposal struct {
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle"`
	// ClosesAt is the close in force, after any extensions.
	ClosesAt int64 `json:"closes_at"`
	// Members are the eligible connections, by connection id.
	Members map[string]Member `json:"members"`
	// Published is set once the results are published (§7).
	Published bool `json:"published"`

	p *Proposal
}

// Parsed returns the proposal document.
func (o *OpenProposal) Parsed() (*Proposal, error) {
	if o.p == nil {
		p, err := ParseProposal(o.Doc)
		if err != nil {
			return nil, err
		}
		o.p = p
	}
	return o.p, nil
}

// BallotRecord is an accepted ballot as the service keeps it (§6): the
// ballot, the member's credential signature and key, the relay's time and
// the receipt, and the connection, for the organisation's record.
type BallotRecord struct {
	Ballot        Ballot `json:"ballot"`
	ConnectionID  string `json:"connection_id"`
	CredentialKey []byte `json:"credential_key"`
	CastSig       []byte `json:"cast_sig"`
	MsgMS         uint64 `json:"msg_ms"`
	ReceiptSig    []byte `json:"receipt_sig"`
}

// BoxStore is the box's storage.
type BoxStore interface {
	// OpenProposal returns a proposal by id, or nil if there is none.
	OpenProposal(ctx context.Context, id string) (*OpenProposal, error)
	// Ballot returns the ballot recorded for a tag, or nil.
	Ballot(ctx context.Context, proposalID string, tag []byte) (*BallotRecord, error)
	// PutBallot records rec only if its tag has no ballot yet (a
	// conditional write, also kept write-once outside the table, §6). It
	// returns the ballot recorded for the tag: rec, or the earlier one.
	PutBallot(ctx context.Context, proposalID string, rec *BallotRecord) (*BallotRecord, error)
}

// Box answers vote.* requests (peer.Votes).
type Box struct {
	Store BoxStore
	// Sign signs label ‖ msg with the service identity key.
	Sign func(label string, msg []byte) ([]byte, error)
}

var _ peer.Votes = (*Box)(nil)

// Vote answers a request.
func (b *Box) Vote(ctx context.Context, r *peer.VoteRequest) (peer.VoteAnswer, error) {
	switch r.Type {
	case TypeCast:
		return b.cast(ctx, r)
	case TypeStatus:
		return b.status(ctx, r)
	}
	return peer.VoteAnswer{Code: "unsupported_type"}, nil
}

type castBody struct {
	ProposalID    string `json:"proposal_id"`
	RecordTag     string `json:"record_tag"`
	VK            string `json:"vk"`
	ChoiceID      string `json:"choice_id"`
	BallotSig     string `json:"ballot_sig"`
	CastSig       string `json:"cast_sig"`
	CredentialKey string `json:"credential_key"`
}

// decodeB64 is VAULT-MESSAGING §5.3's base64: standard, padded,
// canonical, with no CR or LF; n > 0 requires that many bytes.
func decodeB64(s string, n int) ([]byte, bool) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || (n > 0 && len(b) != n) {
		return nil, false
	}
	return b, true
}

func (b *Box) cast(ctx context.Context, r *peer.VoteRequest) (peer.VoteAnswer, error) {
	var body castBody
	reqHash := sum(r.Body) // until the ballot's leaf is known
	if json.Unmarshal(r.Body, &body) != nil || !ValidProposalID(body.ProposalID) {
		return b.refuse(nil, r, nil, CodeBadBallot, reqHash)
	}
	o, err := b.Store.OpenProposal(ctx, body.ProposalID)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	if o == nil {
		return b.refuse(nil, r, nil, CodeNotEligible, reqHash, body.ProposalID)
	}
	p, err := o.Parsed()
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	m, eligible := o.Members[r.ConnectionID]
	tag, ok1 := decodeB64(body.RecordTag, HashLen)
	vk, ok2 := decodeB64(body.VK, VKLen)
	bsig, ok3 := decodeB64(body.BallotSig, SigLen)
	csig, ok4 := decodeB64(body.CastSig, SigLen)
	bal := Ballot{RecordTag: tag, VK: vk, ChoiceID: body.ChoiceID, BallotSig: bsig}
	leaf, lerr := bal.Leaf()
	if lerr == nil {
		reqHash = sum(leaf)
	}
	var myTag []byte
	if eligible {
		myTag = m.Tag
	}
	if !eligible {
		return b.refuse(o, r, nil, CodeNotEligible, reqHash)
	}
	if !ok1 || !ok2 || !ok3 || !ok4 || lerr != nil {
		return b.refuse(o, r, myTag, CodeBadBallot, reqHash)
	}
	// 1. Idempotency: the same ballot again gets its receipt again.
	prev, err := b.Store.Ballot(ctx, p.ProposalID, m.Tag)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	if prev != nil {
		if sameBallot(&prev.Ballot, &bal) {
			return b.receiptAnswer(p.ProposalID, prev)
		}
		return b.alreadyVoted(o, r, m.Tag, prev, reqHash)
	}
	if o.Published {
		return b.refuse(o, r, m.Tag, CodeLate, reqHash)
	}
	// 2. The window, by the relay's time.
	switch {
	case r.MsgMS < uint64(p.OpensAt)*1000:
		return b.refuse(o, r, m.Tag, CodeNotOpen, reqHash)
	case r.MsgMS >= uint64(o.ClosesAt)*1000:
		return b.refuse(o, r, m.Tag, CodeClosed, reqHash)
	}
	// 3. Eligibility.
	if !bytes.Equal(tag, m.Tag) {
		return b.refuse(o, r, m.Tag, CodeBadBallot, reqHash)
	}
	if !r.Active && !p.RemovedMayVote {
		return b.refuse(o, r, m.Tag, CodeNotActive, reqHash)
	}
	// 4. The ballot and the credential signature. The credential key is
	// the one pinned at sign-in; a member who never signed in names it
	// here, and it is kept with the ballot.
	cred := r.CredentialKey
	if len(cred) == 0 {
		k, ok := decodeB64(body.CredentialKey, VKLen)
		if !ok {
			return b.refuse(o, r, m.Tag, CodeBadBallot, reqHash)
		}
		cred = k
	}
	msg, _ := bal.Msg(sum(o.Doc))
	cmsg, _ := CastMsg(sum(o.Doc), leaf)
	if !p.HasChoice(bal.ChoiceID) || Verify(vk, LabelBallot, msg, bsig) != nil || Verify(cred, LabelCast, cmsg, csig) != nil {
		return b.refuse(o, r, m.Tag, CodeBadBallot, reqHash)
	}
	// 5. One per tag, then 6. the receipt.
	rmsg, _ := ReceiptMsg(sum(o.Doc), leaf, r.MsgMS)
	rsig, err := b.Sign(LabelReceipt, rmsg)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	rec := &BallotRecord{Ballot: bal, ConnectionID: r.ConnectionID, CredentialKey: cred, CastSig: csig, MsgMS: r.MsgMS, ReceiptSig: rsig}
	got, err := b.Store.PutBallot(ctx, p.ProposalID, rec)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	if !sameBallot(&got.Ballot, &bal) {
		return b.alreadyVoted(o, r, m.Tag, got, reqHash) // a concurrent cast won
	}
	return b.receiptAnswer(p.ProposalID, got)
}

func sameBallot(a, b *Ballot) bool {
	return bytes.Equal(a.RecordTag, b.RecordTag) && bytes.Equal(a.VK, b.VK) && a.ChoiceID == b.ChoiceID && bytes.Equal(a.BallotSig, b.BallotSig)
}

type rowBallotJSON struct {
	VK        []byte `json:"vk"`
	ChoiceID  string `json:"choice_id"`
	BallotSig []byte `json:"ballot_sig"`
}

func toRowBallot(b *Ballot) *rowBallotJSON {
	return &rowBallotJSON{VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
}

func (b *Box) receiptAnswer(proposalID string, rec *BallotRecord) (peer.VoteAnswer, error) {
	body, err := json.Marshal(struct {
		ProposalID string `json:"proposal_id"`
		MsgMS      uint64 `json:"msg_ms"`
		ReceiptSig []byte `json:"receipt_sig"`
	}{proposalID, rec.MsgMS, rec.ReceiptSig})
	return peer.VoteAnswer{Body: body}, err
}

type refusalBody struct {
	RefusalSig []byte `json:"refusal_sig"`
	MsgMS      uint64 `json:"msg_ms"`
	Connection []byte `json:"connection"`
	RecordTag  []byte `json:"record_tag"`
	// already_voted only: the recorded ballot and its receipt.
	Ballot      *rowBallotJSON `json:"ballot,omitempty"`
	BallotMsgMS uint64         `json:"ballot_msg_ms,omitempty"`
	ReceiptSig  []byte         `json:"receipt_sig,omitempty"`
}

// refuse answers a signed refusal (§4.2). proposalID overrides o's when o
// is nil (an unknown proposal).
func (b *Box) refuse(o *OpenProposal, r *peer.VoteRequest, tag []byte, code string, reqHash []byte, proposalID ...string) (peer.VoteAnswer, error) {
	body, err := b.refusal(o, r, tag, code, reqHash, proposalID...)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	return b.encodeRefusal(code, body)
}

func (b *Box) refusal(o *OpenProposal, r *peer.VoteRequest, tag []byte, code string, reqHash []byte, proposalID ...string) (*refusalBody, error) {
	id := ""
	if o != nil {
		if p, err := o.Parsed(); err == nil {
			id = p.ProposalID
		}
	} else if len(proposalID) > 0 {
		id = proposalID[0]
	}
	conn := sha256.Sum256(r.PeerIK)
	if !ValidProposalID(id) {
		// A request naming no valid proposal: nothing to bind the refusal
		// to, so it goes unsigned (§4.2: the vault treats it as no answer).
		return &refusalBody{MsgMS: r.MsgMS, Connection: conn[:], RecordTag: tag}, nil
	}
	msg, err := RefusalMsg(id, conn[:], tag, r.Type, code, r.MsgMS, reqHash)
	if err != nil {
		return nil, err
	}
	sig, err := b.Sign(LabelRefusal, msg)
	if err != nil {
		return nil, err
	}
	return &refusalBody{RefusalSig: sig, MsgMS: r.MsgMS, Connection: conn[:], RecordTag: tag}, nil
}

func (b *Box) encodeRefusal(code string, body *refusalBody) (peer.VoteAnswer, error) {
	if body.RecordTag == nil {
		body.RecordTag = []byte{}
	}
	j, err := json.Marshal(body)
	return peer.VoteAnswer{Code: code, Body: j}, err
}

func (b *Box) alreadyVoted(o *OpenProposal, r *peer.VoteRequest, tag []byte, prev *BallotRecord, reqHash []byte) (peer.VoteAnswer, error) {
	body, err := b.refusal(o, r, tag, CodeAlreadyVoted, reqHash)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	body.Ballot, body.BallotMsgMS, body.ReceiptSig = toRowBallot(&prev.Ballot), prev.MsgMS, prev.ReceiptSig
	return b.encodeRefusal(CodeAlreadyVoted, body)
}

type statusBody struct {
	ProposalID   string          `json:"proposal_id"`
	Proposal     []byte          `json:"proposal"`
	ProposalSig  []byte          `json:"proposal_sig"`
	Bundle       json.RawMessage `json:"bundle,omitempty"`
	RecordSecret []byte          `json:"record_secret"`
	RecordProof  recordProof     `json:"record_proof"`
	Ballot       *rowBallotJSON  `json:"ballot,omitempty"`
	MsgMS        uint64          `json:"msg_ms,omitempty"`
	ReceiptSig   []byte          `json:"receipt_sig,omitempty"`
	StatusSig    []byte          `json:"status_sig"`
}

type recordProof struct {
	Index    int      `json:"index"`
	TreeSize int64    `json:"tree_size"`
	Path     [][]byte `json:"path"`
}

func (b *Box) status(ctx context.Context, r *peer.VoteRequest) (peer.VoteAnswer, error) {
	var body struct {
		ProposalID string `json:"proposal_id"`
	}
	if json.Unmarshal(r.Body, &body) != nil || !ValidProposalID(body.ProposalID) {
		return b.refuse(nil, r, nil, CodeUnknownProposal, sum(r.Body))
	}
	reqHash := sum([]byte(body.ProposalID))
	o, err := b.Store.OpenProposal(ctx, body.ProposalID)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	if o == nil {
		return b.refuse(nil, r, nil, CodeUnknownProposal, reqHash, body.ProposalID)
	}
	p, err := o.Parsed()
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	m, ok := o.Members[r.ConnectionID]
	if !ok {
		return b.refuse(o, r, nil, CodeNotEligible, reqHash)
	}
	rec, err := b.Store.Ballot(ctx, p.ProposalID, m.Tag)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	out := statusBody{ProposalID: p.ProposalID, Proposal: o.Doc, ProposalSig: o.Sig, Bundle: o.Bundle,
		RecordSecret: m.Secret, RecordProof: recordProof{Index: m.Index, TreeSize: p.Eligible, Path: m.Proof}}
	var leaf []byte
	if rec != nil {
		if leaf, err = rec.Ballot.Leaf(); err != nil {
			return peer.VoteAnswer{}, err
		}
		out.Ballot, out.MsgMS, out.ReceiptSig = toRowBallot(&rec.Ballot), rec.MsgMS, rec.ReceiptSig
	}
	if out.RecordProof.Path == nil {
		out.RecordProof.Path = [][]byte{}
	}
	smsg, err := StatusMsg(p.ProposalID, m.Tag, leaf)
	if err != nil {
		return peer.VoteAnswer{}, err
	}
	if out.StatusSig, err = b.Sign(LabelStatus, smsg); err != nil {
		return peer.VoteAnswer{}, err
	}
	j, err := json.Marshal(out)
	return peer.VoteAnswer{Body: j}, err
}
