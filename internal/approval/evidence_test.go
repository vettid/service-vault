package approval

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/peerwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// An approval.response entry verifies on its own, with or without a
// purpose; one missing a part, or altered, does not.
func TestAuditEntryVerify(t *testing.T) {
	seed := func(b byte) ed25519.PrivateKey { k := make([]byte, 32); k[0] = b; return ed25519.NewKeyFromSeed(k) }
	svc, mem, cred := seed(1), seed(2), seed(3)
	for _, purpose := range []string{peerwire.PurposeApproval, ""} {
		ch := &peerwire.ConnAuthChallenge{RequestID: "01JBQZ0000000000000000000A", Nonce: make([]byte, 32),
			Context: "Approve: open the vote", Purpose: purpose}
		ch.Nonce[0] = 9
		label, msg := ch.Signed(svc.Public().(ed25519.PublicKey), mem.Public().(ed25519.PublicKey))
		sig, err := suite.Sign(cred, label, msg)
		if err != nil {
			t.Fatal(err)
		}
		e := &AuditEntry{Type: AuditResponse, RequestID: ch.RequestID, Context: ch.Context, Answer: AnswerApproved,
			Key: cred.Public().(ed25519.PublicKey), Signature: sig, Purpose: purpose, SignedAt: &time.Time{},
			Nonce: ch.Nonce, ServiceIK: svc.Public().(ed25519.PublicKey), MemberIK: mem.Public().(ed25519.PublicKey)}
		if err := e.Verify(); err != nil {
			t.Fatalf("purpose %q: %v", purpose, err)
		}
		bad := *e
		bad.Nonce = append([]byte{1}, e.Nonce[1:]...)
		if bad.Verify() == nil {
			t.Fatalf("purpose %q: an altered nonce verified", purpose)
		}
		bad = *e
		bad.Context += "!"
		if bad.Verify() == nil {
			t.Fatalf("purpose %q: an altered context verified", purpose)
		}
		bad = *e
		bad.Nonce = nil
		if !errors.Is(bad.Verify(), ErrNoEvidence) {
			t.Fatalf("purpose %q: an entry without its nonce", purpose)
		}
	}
	// A purpose-less signature isn't one with a purpose, nor the reverse.
	ch := &peerwire.ConnAuthChallenge{RequestID: "01JBQZ0000000000000000000B", Nonce: []byte{1, 2, 3}, Context: "x", Purpose: peerwire.PurposeApproval}
	label, msg := ch.Signed(svc.Public().(ed25519.PublicKey), mem.Public().(ed25519.PublicKey))
	sig, _ := suite.Sign(cred, label, msg)
	e := &AuditEntry{Type: AuditResponse, RequestID: ch.RequestID, Context: ch.Context, Key: cred.Public().(ed25519.PublicKey),
		Signature: sig, Nonce: ch.Nonce, ServiceIK: svc.Public().(ed25519.PublicKey), MemberIK: mem.Public().(ed25519.PublicKey)}
	if e.Verify() == nil {
		t.Fatal("a signature with a purpose verified as one without")
	}
}
