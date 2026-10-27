// Package sealstore encrypts the peer's records at rest. The peer keeps
// session keys, handshake secrets and the tokens members issued to the
// service in its records (internal/peer); stored as they are, anyone who
// could read the table or a backup of it could read and forge
// member↔service traffic without the keystore key. Store seals each
// record with AES-256-GCM under a record key that the keystore holds
// sealed by the KMS key only the task may use, so the table alone gives
// nothing away.
package sealstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/vettid/service-vault/internal/peer"
)

// KeyName is the keystore name of the record key.
const KeyName = "record-key"

// Migration: records written before sealing are accepted, and sealed in
// place, only on the start that creates the record key, or when the
// operator sets MigrateEnv (a migration that was cut short). Otherwise an
// unsealed record is refused: a marker in the table could be deleted by
// whoever can write it, to slip in forged plaintext records.
const MigrateEnv = "SV_RECORD_SEAL_MIGRATE"

// prefix starts every sealed record. Plaintext records are JSON or a
// single byte, so they never start with it.
var prefix = []byte("vsr1")

// ErrPlaintext is a record that is not sealed, read after the migration.
var ErrPlaintext = errors.New("sealstore: record is not sealed")

// ErrOpen is a sealed record that does not open: another key, another
// record's place, or tampered.
var ErrOpen = errors.New("sealstore: record does not open")

// RecordKey is the record key as the keystore keeps it.
type RecordKey struct {
	Key []byte `json:"key"`
}

// NewRecordKey makes a fresh 32-byte record key.
func NewRecordKey() (*RecordKey, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &RecordKey{Key: k}, nil
}

// Store is a peer.Store that seals what it writes to Inner and opens what
// it reads. With Legacy, a record that is not sealed is accepted and
// sealed in place as it is loaded (the migration of a store written
// before sealing); without it, such a record is an error.
type Store struct {
	Inner  peer.Store
	Legacy bool
	aead   cipher.AEAD
}

// New returns a Store sealing under key (32 bytes).
func New(inner peer.Store, key []byte, legacy bool) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("sealstore: the record key must be 32 bytes")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &Store{Inner: inner, Legacy: legacy, aead: g}, nil
}

// aad binds a record to its place, so that a sealed record cannot be
// moved to another kind or id.
func aad(kind, id string) []byte {
	return []byte("vettid/service-vault/record/v1\x00" + kind + "\x00" + id)
}

func (s *Store) seal(kind, id string, data []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefix)+len(nonce)+len(data)+s.aead.Overhead())
	out = append(out, prefix...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, data, aad(kind, id)), nil
}

// open returns a record's plaintext and whether it was sealed.
func (s *Store) open(kind, id string, data []byte) ([]byte, bool, error) {
	if !bytes.HasPrefix(data, prefix) {
		if !s.Legacy {
			return nil, false, fmt.Errorf("%w: %s %s", ErrPlaintext, kind, id)
		}
		return data, false, nil
	}
	rest := data[len(prefix):]
	n := s.aead.NonceSize()
	if len(rest) < n+s.aead.Overhead() {
		return nil, true, fmt.Errorf("%w: %s %s", ErrOpen, kind, id)
	}
	pt, err := s.aead.Open(nil, rest[:n], rest[n:], aad(kind, id))
	if err != nil {
		return nil, true, fmt.Errorf("%w: %s %s", ErrOpen, kind, id)
	}
	return pt, true, nil
}

// Load implements peer.Store. With Legacy, records found unsealed are
// rewritten sealed (each conditional on its version) and returned with
// their new version.
func (s *Store) Load(ctx context.Context, kind string) ([]peer.Record, error) {
	recs, err := s.Inner.Load(ctx, kind)
	if err != nil {
		return nil, err
	}
	var reseal []peer.Change
	var at []int
	for i := range recs {
		pt, sealed, err := s.open(kind, recs[i].ID, recs[i].Data)
		if err != nil {
			return nil, err
		}
		if !sealed {
			ct, err := s.seal(kind, recs[i].ID, pt)
			if err != nil {
				return nil, err
			}
			reseal = append(reseal, peer.Change{Kind: kind, ID: recs[i].ID, Data: ct, Expires: recs[i].Expires, IfVersion: recs[i].Version})
			at = append(at, i)
		}
		recs[i].Data = pt
	}
	if len(reseal) > 0 {
		if err := s.Inner.Apply(ctx, reseal); err != nil {
			return nil, fmt.Errorf("sealstore: reseal %s: %w", kind, err)
		}
		for _, i := range at {
			recs[i].Version++
		}
	}
	return recs, nil
}

// Get implements peer.Store.
func (s *Store) Get(ctx context.Context, kind, id string) ([]byte, bool, error) {
	data, ok, err := s.Inner.Get(ctx, kind, id)
	if err != nil || !ok {
		return nil, ok, err
	}
	pt, _, err := s.open(kind, id, data)
	if err != nil {
		return nil, false, err
	}
	return pt, true, nil
}

// Apply implements peer.Store: every write is sealed; deletes pass.
func (s *Store) Apply(ctx context.Context, changes []peer.Change) error {
	out := make([]peer.Change, len(changes))
	for i, c := range changes {
		if c.Data != nil {
			ct, err := s.seal(c.Kind, c.ID, c.Data)
			if err != nil {
				return err
			}
			c.Data = ct
		}
		out[i] = c
	}
	return s.Inner.Apply(ctx, out)
}

// Migrate loads every record of the kinds, so that each one found
// unsealed is sealed in place (Legacy must be set).
func (s *Store) Migrate(ctx context.Context, kinds []string) error {
	if !s.Legacy {
		return nil
	}
	for _, k := range kinds {
		if _, err := s.Load(ctx, k); err != nil {
			return err
		}
	}
	return nil
}
