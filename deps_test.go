package servicevault_test

// The pinned dependencies (docs/SOURCE.md): the service vault speaks VMS v2
// with vettid-vault's wire packages and reaches the relay with
// vettid-relay's relayclient, at the commits pinned in go.mod. This test
// fails to compile if either moves or its exported API changes shape.

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

func TestPinnedPackagesCompile(t *testing.T) {
	// vms/suite: a labelled signature from a fixed test seed verifies.
	ik, err := suite.IdentityFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("IdentityFromSeed: %v", err)
	}
	msg := []byte("service-vault compile test")
	sig, err := suite.Sign(ik, "vettid/test", msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := suite.Verify(ik.Public().(ed25519.PublicKey), "vettid/test", msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// vms/invite: a malformed link is refused.
	if _, err := invite.ParseLink("not a link"); err == nil {
		t.Fatal("invite.ParseLink accepted a malformed link")
	}

	// relayclient: a client from the same key reports a mailbox id.
	c := relayclient.New("https://relay.vettid.test", ik)
	if c.MailboxID() == "" {
		t.Fatal("relayclient: empty mailbox id")
	}
}
