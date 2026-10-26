package keystore

import (
	"crypto/rand"

	"github.com/vettid/service-vault/internal/peer"
)

// SecretsName is the record holding the service's secrets.
const SecretsName = "service-secrets"

// Secrets are everything the service vault must keep across restarts and
// share between tasks: its VMS keys and the email-index pepper.
type Secrets struct {
	Peer        peer.Seeds `json:"peer"`
	EmailPepper []byte     `json:"email_pepper"`
}

// NewSecrets makes fresh secrets: new VMS keys and a 32-byte pepper.
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
	return &Secrets{Peer: seeds, EmailPepper: pepper}, nil
}
