package approval

import (
	"bytes"
	"testing"
)

// TestCredentialKeyFingerprintVector pins the fingerprint to the vector of
// VAULT-MESSAGING §16 ("§10.8 credential-key fingerprint", 0.83.8), the
// string the member's app shows in Settings → Vault status.
func TestCredentialKeyFingerprintVector(t *testing.T) {
	if got, want := CredentialKeyFingerprint(bytes.Repeat([]byte{0x09}, 32)), "e939 754d 09aa a93a"; got != want {
		t.Fatalf("CredentialKeyFingerprint = %q, want %q", got, want)
	}
}
