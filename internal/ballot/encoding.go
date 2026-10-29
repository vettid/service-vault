// Package ballot is the service vault's side of the secret ballot
// (docs/BALLOT-PROTOCOL.md): the signed encodings, the Merkle trees, the
// certification and the ballot box.
package ballot

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"regexp"
)

// Labels (BALLOT-PROTOCOL §2): the VMS convention, each followed by 0x00
// where it starts a hashed or signed string.
const (
	labelProposal = "vettid/vote/1/proposal\x00"
	labelPool     = "vettid/vote/1/pool\x00"
	labelExtended = "vettid/vote/1/extended\x00"
	labelResults  = "vettid/vote/1/results\x00"
	labelBallot   = "vettid/vote/1/ballot\x00"
	labelCert     = "vettid/vote/1/cert\x00"
	labelRecord   = "vettid/vote/1/record\x00"
	labelIssued   = "vettid/vote/1/issued\x00"
)

// Sizes of the fixed fields.
const (
	ProposalIDLen = 26 // a canonical ULID
	HashLen       = sha256.Size
	VKLen         = 32 // an Ed25519 public key
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

// CertMsg is the certified message, "vettid/vote/1/cert" ‖ 0x00 ‖
// proposal_hash ‖ vk (§5.1). The randomized variant signs
// cert_prefix ‖ CertMsg.
func CertMsg(proposalHash, vk []byte) ([]byte, error) {
	if len(proposalHash) != HashLen || len(vk) != VKLen {
		return nil, errField
	}
	b := append([]byte(labelCert), proposalHash...)
	return append(b, vk...), nil
}

// BallotMsg is the signed ballot, proposal_hash ‖ u32(seq) ‖
// u32(pool_seq) ‖ pool_hash ‖ lp(choice_id) (§6.1); it is signed under
// BallotLabel.
func BallotMsg(proposalHash []byte, seq, poolSeq uint32, poolHash []byte, choiceID string) ([]byte, error) {
	if len(proposalHash) != HashLen || len(poolHash) != HashLen || seq == 0 || !ValidChoiceID(choiceID) {
		return nil, errField
	}
	b := append([]byte{}, proposalHash...)
	b = binary.BigEndian.AppendUint32(b, seq)
	b = binary.BigEndian.AppendUint32(b, poolSeq)
	b = append(b, poolHash...)
	return lp(b, []byte(choiceID)), nil
}

// BallotLabel is the label a ballot is signed under (suite.Sign).
const BallotLabel = labelBallot

// RecordTag is H("vettid/vote/1/record" ‖ 0x00 ‖ proposal_id ‖
// record_secret) (§3.2).
func RecordTag(proposalID string, secret []byte) ([]byte, error) {
	return tag(labelRecord, proposalID, secret)
}

// IssuedTag is H("vettid/vote/1/issued" ‖ 0x00 ‖ proposal_id ‖
// record_secret) (§3.2, §5.3).
func IssuedTag(proposalID string, secret []byte) ([]byte, error) {
	return tag(labelIssued, proposalID, secret)
}

func tag(label, proposalID string, secret []byte) ([]byte, error) {
	if !ValidProposalID(proposalID) || len(secret) != SecretLen {
		return nil, errField
	}
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte(proposalID))
	h.Write(secret)
	return h.Sum(nil), nil
}

// Ballot is a counted ballot as the ballot box keeps and publishes it
// (§7.2, §8.2).
type Ballot struct {
	VK         []byte
	CertPrefix []byte
	CertSig    []byte
	Seq        uint32
	PoolSeq    uint32
	PoolHash   []byte
	ChoiceID   string
	BallotSig  []byte
	Day        string // YYYY-MM-DD, UTC
}

var dayRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// Leaf is the ballot's Merkle leaf: lp(vk) ‖ lp(cert_prefix) ‖
// lp(cert_sig) ‖ u32(seq) ‖ u32(pool_seq) ‖ pool_hash ‖ lp(choice_id) ‖
// lp(ballot_sig) ‖ lp(day) (§8.2).
func (b *Ballot) Leaf() ([]byte, error) {
	if len(b.VK) != VKLen || len(b.PoolHash) != HashLen || !ValidChoiceID(b.ChoiceID) || !dayRe.MatchString(b.Day) ||
		len(b.CertPrefix) > 0xffff || len(b.CertSig) > 0xffff || len(b.BallotSig) > 0xffff {
		return nil, errField
	}
	out := lp(nil, b.VK)
	out = lp(out, b.CertPrefix)
	out = lp(out, b.CertSig)
	out = binary.BigEndian.AppendUint32(out, b.Seq)
	out = binary.BigEndian.AppendUint32(out, b.PoolSeq)
	out = append(out, b.PoolHash...)
	out = lp(out, []byte(b.ChoiceID))
	out = lp(out, b.BallotSig)
	return lp(out, []byte(b.Day)), nil
}
