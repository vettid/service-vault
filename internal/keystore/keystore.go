// Package keystore keeps the service vault's secrets at rest: one record,
// sealed with AES-256-GCM under a data key that KMS generates and wraps
// (envelope encryption). KMS holds the only key that can unwrap it; the
// sealed record can live in any store.
//
// Only this package touches the service's private keys at rest
// (CLAUDE.md "Conventions").
package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// KMS is the part of a key management service the keystore uses.
type KMS interface {
	// GenerateDataKey returns a fresh 32-byte data key in plaintext and
	// wrapped under keyID.
	GenerateDataKey(ctx context.Context, keyID string) (plaintext, wrapped []byte, err error)
	// Decrypt unwraps a data key wrapped by GenerateDataKey.
	Decrypt(ctx context.Context, keyID string, wrapped []byte) ([]byte, error)
}

// Sealed is a record sealed under a wrapped data key.
type Sealed struct {
	Version    int    `json:"v"`
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

const sealedVersion = 1

// ErrOpen is returned when a sealed record does not open: wrong KMS key,
// tampered record, or a different record name.
var ErrOpen = errors.New("keystore: sealed record does not open")

func aad(name string) []byte { return []byte("vettid/service-vault/keystore/v1\x00" + name) }

// Seal seals plaintext under a fresh data key from kms. name binds the
// record to its purpose: a record sealed as one name does not open as
// another.
func Seal(ctx context.Context, kms KMS, keyID, name string, plaintext []byte) (*Sealed, error) {
	dk, wrapped, err := kms.GenerateDataKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("keystore: data key: %w", err)
	}
	defer clear(dk)
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Sealed{Version: sealedVersion, KeyID: keyID, WrappedKey: wrapped, Nonce: nonce,
		Ciphertext: g.Seal(nil, nonce, plaintext, aad(name))}, nil
}

// Open opens a record sealed by Seal under the same name.
func Open(ctx context.Context, kms KMS, name string, s *Sealed) ([]byte, error) {
	if s == nil || s.Version != sealedVersion {
		return nil, ErrOpen
	}
	dk, err := kms.Decrypt(ctx, s.KeyID, s.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: unwrap data key: %w", err)
	}
	defer clear(dk)
	g, err := gcm(dk)
	if err != nil {
		return nil, err
	}
	if len(s.Nonce) != g.NonceSize() {
		return nil, ErrOpen
	}
	pt, err := g.Open(nil, s.Nonce, s.Ciphertext, aad(name))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("keystore: data key is not 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Blobs stores sealed records by name.
type Blobs interface {
	// Get returns the record, or ErrNotFound.
	Get(ctx context.Context, name string) ([]byte, error)
	// Create stores the record only if none exists under name, else
	// returns ErrExists.
	Create(ctx context.Context, name string, data []byte) error
	// Delete removes the record; a missing one is not an error.
	Delete(ctx context.Context, name string) error
}

// Errors from Blobs.
var (
	ErrNotFound = errors.New("keystore: not found")
	ErrExists   = errors.New("keystore: already exists")
)

// LoadOrCreate returns the secrets stored under name, opening them with
// kms; if none exist it makes them with create, seals and stores them.
// When two tasks race on first start, the loser discards its secrets and
// loads the winner's, so every task ends up with the same identity.
func LoadOrCreate[T any](ctx context.Context, kms KMS, keyID string, blobs Blobs, name string, create func() (*T, error)) (*T, error) {
	for range 2 {
		raw, err := blobs.Get(ctx, name)
		if err == nil {
			var s Sealed
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, ErrOpen
			}
			pt, err := Open(ctx, kms, name, &s)
			if err != nil {
				return nil, err
			}
			defer clear(pt)
			var v T
			if err := json.Unmarshal(pt, &v); err != nil {
				return nil, fmt.Errorf("keystore: %s: %w", name, err)
			}
			return &v, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, err
		}
		v, err := create()
		if err != nil {
			return nil, err
		}
		pt, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		s, err := Seal(ctx, kms, keyID, name, pt)
		clear(pt)
		if err != nil {
			return nil, err
		}
		raw, err = json.Marshal(s)
		if err != nil {
			return nil, err
		}
		switch err := blobs.Create(ctx, name, raw); {
		case err == nil:
			return v, nil
		case errors.Is(err, ErrExists):
			continue // lost the race: load the winner's
		default:
			return nil, err
		}
	}
	return nil, fmt.Errorf("keystore: %s: could not create or load", name)
}
