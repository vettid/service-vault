// Package peer is the service vault's side of the VMS v2 connection
// protocol: to a member's vault it is an ordinary connection
// (VAULT-MESSAGING §1.1, §6). It owns the service's relay mailbox and VMS
// sessions; nothing else in the service vault touches either.
package peer

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Keys are the service's long-lived keys (§6.1): the identity key that
// connections know it by, the static KEM key a member's vault encrypts
// hs.init to, and the relay key that owns the service's mailbox.
type Keys struct {
	IK    ed25519.PrivateKey
	KEM   *suite.PrivateKey
	Relay ed25519.PrivateKey
}

// GenerateKeys makes a fresh set of keys.
func GenerateKeys() (*Keys, error) {
	ik, err := suite.GenerateIdentity()
	if err != nil {
		return nil, fmt.Errorf("peer: identity key: %w", err)
	}
	kem, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("peer: KEM key: %w", err)
	}
	_, rk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("peer: relay key: %w", err)
	}
	return &Keys{IK: ik, KEM: kem, Relay: rk}, nil
}

// Seeds are the keys' seeds, the form the keystore persists.
type Seeds struct {
	IK    []byte
	KEM   []byte
	Relay []byte
}

// Seeds returns copies of the keys' seeds.
func (k *Keys) Seeds() (Seeds, error) {
	kem, err := k.KEM.Seed()
	if err != nil {
		return Seeds{}, fmt.Errorf("peer: KEM seed: %w", err)
	}
	return Seeds{
		IK:    append([]byte(nil), k.IK.Seed()...),
		KEM:   kem,
		Relay: append([]byte(nil), k.Relay.Seed()...),
	}, nil
}

// KeysFromSeeds rebuilds keys from their seeds.
func KeysFromSeeds(s Seeds) (*Keys, error) {
	if len(s.IK) != ed25519.SeedSize || len(s.Relay) != ed25519.SeedSize {
		return nil, errors.New("peer: bad seed length")
	}
	ik, err := suite.IdentityFromSeed(s.IK)
	if err != nil {
		return nil, fmt.Errorf("peer: identity key: %w", err)
	}
	kem, err := suite.NewPrivateKey(s.KEM)
	if err != nil {
		return nil, fmt.Errorf("peer: KEM key: %w", err)
	}
	return &Keys{IK: ik, KEM: kem, Relay: ed25519.NewKeyFromSeed(s.Relay)}, nil
}

// IKPublic is the service's identity public key.
func (k *Keys) IKPublic() ed25519.PublicKey { return k.IK.Public().(ed25519.PublicKey) }

// RelayPublic is the public half of the relay key.
func (k *Keys) RelayPublic() ed25519.PublicKey { return k.Relay.Public().(ed25519.PublicKey) }

// Mailbox is the service's mailbox id on the relay (RELAY-PROTOCOL §4).
func (k *Keys) Mailbox() string { return relayauth.MailboxID(k.RelayPublic()) }

// Principal is how the service appears in a claim bundle and in hs.init
// (§6.2, §6.4) for a relay at relayURL.
func (k *Keys) Principal(relayURL string) handshake.Principal {
	return handshake.Principal{
		IK:  k.IKPublic(),
		KEM: k.KEM.Public(),
		Relay: handshake.RelayAddr{
			URL:     relayURL,
			Mailbox: k.Mailbox(),
			PK:      k.RelayPublic(),
		},
	}
}
