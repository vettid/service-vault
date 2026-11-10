// Package keystore keeps the service vault's secrets at rest: one record,
// sealed with AES-256-GCM under a data key that KMS generates and wraps
// (envelope encryption). KMS holds the only key that can unwrap it; the
// sealed record can live in any store.
//
// Only this package touches the service's private keys at rest
// (CLAUDE.md "Conventions").
package keystore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
)

// KMS is the part of a key management service the keystore uses. encCtx
// is the KMS encryption context the data key is bound to (nil: none): it
// must be the same to unwrap the key as it was to make it, and a key
// policy can require it (key protection, GC #7406 §7).
type KMS interface {
	// GenerateDataKey returns a fresh 32-byte data key in plaintext and
	// wrapped under keyID, bound to encCtx.
	GenerateDataKey(ctx context.Context, keyID string, encCtx map[string]string) (plaintext, wrapped []byte, err error)
	// Decrypt unwraps a data key wrapped by GenerateDataKey with the same
	// encCtx.
	Decrypt(ctx context.Context, keyID string, wrapped []byte, encCtx map[string]string) ([]byte, error)
}

// ContextKey is the encryption context's one key; its value is the
// record's name. The CMK's policy allows Decrypt only with it, over the
// names it lists.
const ContextKey = "blob"

// Sealed is a record sealed under a wrapped data key.
type Sealed struct {
	Version    int    `json:"v"`
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
	// Context: the data key is bound to the encryption context
	// {ContextKey: name}. A record without it is from before (it opens
	// until the CMK's policy requires the context; Reseal moves it).
	Context bool `json:"ctx,omitempty"`
	// Sum is the SHA-256 of the plaintext, which a re-seal keeps: a table
	// restore tells the same deployment by it rather than by the sealed
	// bytes (SameSecrets), and Open checks it. The plaintexts are
	// high-entropy keys (never a password, a PIN or another guessable
	// value: see Seal), so the sum gives nothing of them away.
	Sum []byte `json:"sum,omitempty"`
}

// SameSecrets reports whether two stored records hold the same secrets:
// by their sums when both have one, else by their bytes. It trusts the
// sums as stored, unopened: it is for telling deployments apart in a
// restore (whose operator can write the table anyway), never for deciding
// what a secret is.
func SameSecrets(a, b []byte) bool {
	var sa, sb Sealed
	if json.Unmarshal(a, &sa) == nil && json.Unmarshal(b, &sb) == nil && len(sa.Sum) == sha256.Size && len(sb.Sum) == sha256.Size {
		return bytes.Equal(sa.Sum, sb.Sum)
	}
	return bytes.Equal(a, b)
}

// encContext is a record's encryption context.
func encContext(name string) map[string]string { return map[string]string{ContextKey: name} }

const sealedVersion = 1

// ErrOpen is returned when a sealed record does not open: wrong KMS key,
// tampered record, or a different record name.
var ErrOpen = errors.New("keystore: sealed record does not open")

func aad(name string) []byte { return []byte("vettid/service-vault/keystore/v1\x00" + name) }

// Seal seals plaintext under a fresh data key from kms, bound to the
// encryption context {ContextKey: name}. name binds the record to its
// purpose: a record sealed as one name does not open as another. The
// plaintext must be a high-entropy key, never a password, a PIN or any
// other low-entropy value: the record carries its SHA-256 (Sum).
func Seal(ctx context.Context, kms KMS, keyID, name string, plaintext []byte) (*Sealed, error) {
	dk, wrapped, err := kms.GenerateDataKey(ctx, keyID, encContext(name))
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
	sum := sha256.Sum256(plaintext)
	return &Sealed{Version: sealedVersion, KeyID: keyID, WrappedKey: wrapped, Nonce: nonce,
		Ciphertext: g.Seal(nil, nonce, plaintext, aad(name)), Context: true, Sum: sum[:]}, nil
}

// Open opens a record sealed by Seal under the same name: with its
// encryption context, or, for a record from before contexts, without.
func Open(ctx context.Context, kms KMS, name string, s *Sealed) ([]byte, error) {
	if s == nil || s.Version != sealedVersion {
		return nil, ErrOpen
	}
	var ec map[string]string
	if s.Context {
		ec = encContext(name)
	}
	dk, err := kms.Decrypt(ctx, s.KeyID, s.WrappedKey, ec)
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
	if s.Sum != nil {
		if sum := sha256.Sum256(pt); !bytes.Equal(sum[:], s.Sum) {
			clear(pt)
			return nil, ErrOpen
		}
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
	// Replace stores data under name only if the record is exactly old
	// (ErrChanged if it differs, ErrNotFound if there is none): a record
	// is never deleted and created again, so a failure loses nothing.
	Replace(ctx context.Context, name string, old, data []byte) error
	// List returns every record's name.
	List(ctx context.Context) ([]string, error)
	// Delete removes the record; a missing one is not an error.
	Delete(ctx context.Context, name string) error
}

// Errors from Blobs.
var (
	ErrNotFound = errors.New("keystore: not found")
	ErrExists   = errors.New("keystore: already exists")
	ErrChanged  = errors.New("keystore: the record changed")
)

// LoadOrCreate returns the secrets stored under name, opening them with
// kms; if none exist it makes them with create, seals and stores them.
// create makes high-entropy keys, never a password, a PIN or another
// low-entropy value (Seal).
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
