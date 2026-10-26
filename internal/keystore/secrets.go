package keystore

import (
	"crypto/rand"

	"github.com/vettid/service-vault/internal/peer"
	"github.com/vettid/service-vault/internal/tlsid"
)

// SecretsName is the record holding the service's secrets.
const SecretsName = "service-secrets"

// Secrets are everything the service vault must keep across restarts and
// share between tasks: its VMS keys, the email-index pepper, and the TLS
// key of its private API (PKCS #8 DER; its pin is published).
type Secrets struct {
	Peer        peer.Seeds `json:"peer"`
	EmailPepper []byte     `json:"email_pepper"`
	TLSKey      []byte     `json:"tls_key"`
}

// NewSecrets makes fresh secrets: new VMS keys, a 32-byte pepper and a
// TLS key.
func NewSecrets() (*Secrets, error) {
	k, err := peer.GenerateKeys()
	if err != nil {
		return nil, err
	}
	seeds, err := k.Seeds()
	if err != nil {
		return nil, err
	}
	pepper := make([]byte, 32)
	if _, err := rand.Read(pepper); err != nil {
		return nil, err
	}
	tk, err := tlsid.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Secrets{Peer: seeds, EmailPepper: pepper, TLSKey: tk}, nil
}
