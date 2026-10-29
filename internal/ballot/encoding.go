// Package ballot is the service vault's side of the vote
// (docs/BALLOT-PROTOCOL.md): the signed encodings, the Merkle trees, the
// cast handling and the results.
package ballot

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"regexp"
)

// Labels (BALLOT-PROTOCOL §2): the VMS convention, each ending in its own
// 0x00, which separates it from the message (suite.Sign signs label ‖ m).
const (
	LabelProposal    = "vettid/vote/1/proposal\x00"
	LabelExtended    = "vettid/vote/1/extended\x00"
	LabelResults     = "vettid/vote/1/results\x00"
	LabelBallot      = "vettid/vote/1/ballot\x00"
	LabelCast        = "vettid/vote/1/cast\x00"
	LabelReceipt     = "vettid/vote/1/receipt\x00"
	LabelStatus      = "vettid/vote/1/status\x00"
	LabelRefusal     = "vettid/vote/1/refusal\x00"
	LabelAnchorKey   = "vettid/vote/1/anchor-key\x00"
	LabelServiceList = "vettid/vote/1/service-list\x00"
	labelRecord      = "vettid/vote/1/record\x00"
)

// Sizes of the fixed fields.
const (
	ProposalIDLen = 26 // a canonical ULID
	HashLen       = sha256.Size
	VKLen         = 32 // an Ed25519 public key
	SigLen        = 64 // an Ed25519 signature
	SecretLen     = 32 // record_secret
)

var (
	ulidRe     = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	choiceIDRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	errField   = errors.New("ballot: field out of bounds")
)

// ValidProposalID reports whether id is a canonical upper-case ULID
// (BALLOT-PROTOCOL §2).
func ValidProposalID(id string) bool { return ulidRe.MatchString(id) }

// ValidChoiceID reports whether id is a choice id (BALLOT-PROTOCOL §3.1).
func ValidChoiceID(id string) bool { return choiceIDRe.MatchString(id) }

// lp is u16(len(x)) ‖ x (BALLOT-PROTOCOL §2).
func lp(b []byte, x []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(x)))
	return append(b, x...)
}

func sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// RecordTag is H("vettid/vote/1/record\x00" ‖ proposal_id ‖ record_secret)
// (§3.2).
func RecordTag(proposalID string, secret []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(secret) != SecretLen {
		return nil, errField
	}
	return sum([]byte(labelRecord), []byte(proposalID), secret), nil
}

// BallotMsg is proposal_hash ‖ record_tag ‖ lp(choice_id), signed under
// LabelBallot with the voting key (§5).
func BallotMsg(proposalHash, recordTag []byte, choiceID string) ([]byte, error) {
	if len(proposalHash) != HashLen || len(recordTag) != HashLen || !ValidChoiceID(choiceID) {
		return nil, errField
	}
	b := append(append([]byte{}, proposalHash...), recordTag...)
	return lp(b, []byte(choiceID)), nil
}

// Ballot is a ballot as the service keeps and publishes it (§5, §7).
type Ballot struct {
	RecordTag []byte
	VK        []byte
	ChoiceID  string
	BallotSig []byte
}

// Leaf is ballot_leaf, record_tag ‖ lp(vk) ‖ lp(choice_id) ‖
// lp(ballot_sig) (§5, §8.2): the row leaf of a ballot, and what the
// credential signature and the receipt cover.
func (b *Ballot) Leaf() ([]byte, error) {
	if len(b.RecordTag) != HashLen || len(b.VK) != VKLen || !ValidChoiceID(b.ChoiceID) || len(b.BallotSig) != SigLen {
		return nil, errField
	}
	out := append([]byte{}, b.RecordTag...)
	out = lp(out, b.VK)
	out = lp(out, []byte(b.ChoiceID))
	return lp(out, b.BallotSig), nil
}

// Msg is the ballot's signed message (BallotMsg) under proposalHash.
func (b *Ballot) Msg(proposalHash []byte) ([]byte, error) {
	return BallotMsg(proposalHash, b.RecordTag, b.ChoiceID)
}

// EmptyRowLeaf is the row leaf of a tag that didn't vote: the tag alone
// (§8.2).
func EmptyRowLeaf(recordTag []byte) ([]byte, error) {
	if len(recordTag) != HashLen {
		return nil, errField
	}
	return append([]byte{}, recordTag...), nil
}

// CastMsg is proposal_hash ‖ H(ballot_leaf), signed under LabelCast with
// the member's credential key (§5).
func CastMsg(proposalHash, ballotLeaf []byte) ([]byte, error) {
	if len(proposalHash) != HashLen {
		return nil, errField
	}
	return append(append([]byte{}, proposalHash...), sum(ballotLeaf)...), nil
}

// ReceiptMsg is proposal_hash ‖ H(ballot_leaf) ‖ u64(msg_ms), signed under
// LabelReceipt with the service identity key (§5).
func ReceiptMsg(proposalHash, ballotLeaf []byte, msgMS uint64) ([]byte, error) {
	b, err := CastMsg(proposalHash, ballotLeaf)
	if err != nil {
		return nil, err
	}
	return binary.BigEndian.AppendUint64(b, msgMS), nil
}

// StatusMsg is lp(proposal_id) ‖ lp(record_tag) ‖ H(ballot_leaf or empty),
// signed under LabelStatus (§4.2). recordTag and ballotLeaf may be empty.
func StatusMsg(proposalID string, recordTag, ballotLeaf []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || (len(recordTag) != 0 && len(recordTag) != HashLen) {
		return nil, errField
	}
	b := lp(nil, []byte(proposalID))
	b = lp(b, recordTag)
	return append(b, sum(ballotLeaf)...), nil
}

// RefusalMsg is lp(proposal_id) ‖ lp(connection) ‖ lp(record_tag) ‖
// lp(type) ‖ lp(code) ‖ u64(msg_ms) ‖ request_hash, signed under
// LabelRefusal (§4.2). connection is H(the connection's peer identity
// key); recordTag may be empty.
func RefusalMsg(proposalID string, connection, recordTag []byte, typ, code string, msgMS uint64, requestHash []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(connection) != HashLen || (len(recordTag) != 0 && len(recordTag) != HashLen) ||
		typ == "" || len(typ) > 64 || code == "" || len(code) > 64 || len(requestHash) != HashLen {
		return nil, errField
	}
	b := lp(nil, []byte(proposalID))
	b = lp(b, connection)
	b = lp(b, recordTag)
	b = lp(b, []byte(typ))
	b = lp(b, []byte(code))
	b = binary.BigEndian.AppendUint64(b, msgMS)
	return append(b, requestHash...), nil
}

// ProposalSigMsg is H(proposal_bytes), signed under LabelProposal (§3.1).
func ProposalSigMsg(doc []byte) []byte { return sum(doc) }

// DocSigMsg is proposal_hash ‖ H(document bytes), the signed message of an
// extension or the results (§7, §8.5).
func DocSigMsg(proposalHash, doc []byte) ([]byte, error) {
	if len(proposalHash) != HashLen {
		return nil, errField
	}
	return append(append([]byte{}, proposalHash...), sum(doc)...), nil
}
