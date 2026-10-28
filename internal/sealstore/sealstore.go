// Package sealstore encrypts the service vault's records at rest. The
// peer keeps session keys, handshake secrets and the tokens members
// issued to the service in its records (internal/peer); the service, the
// approvals and the webhook outboxes keep sign-ins, the admin set and the
// audit log. Stored as they are, anyone who could read the table or a
// backup of it could read member↔service traffic, and anyone who could
// write it could forge any of them (an admin, a connection) without the
// keystore key. Store seals each record with AES-256-GCM under a record
// key that the keystore holds sealed by the KMS key only the task may
// use. The record key is versioned so that it can be replaced: a record
// names the version it is sealed under, and Reseal moves every record to
// the current one. A sealed record is bound to its kind and id; it is not bound to a
// version, so a table writer can still put back an older sealed copy of
// a record, or delete one.
package sealstore

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	"github.com/vettid/service-vault/internal/peer"
)

// KeyName is the keystore name of the record key's version 1.
const KeyName = "record-key"

// KeyNameOf is the keystore name of a version of the record key: KeyName
// for version 1, KeyName+".v<n>" for a later one.
func KeyNameOf(version uint32) string {
	if version == 1 {
		return KeyName
	}
	return KeyName + ".v" + strconv.FormatUint(uint64(version), 10)
}

// MaxVersion bounds the record key's version (chosen; not in the spec).
const MaxVersion = 1 << 20

// Migration: records written before sealing are accepted, and sealed in
// place, only when the operator sets MigrateEnv, for the one deploy that
// upgrades a deployment from before sealing (it may be repeated: a
// migration cut short goes on). Otherwise an unsealed record is refused.
// Nothing in the table turns it on: whoever can write the table must not
// be able to slip in forged plaintext records, whether by deleting a
// marker or the record key.
const MigrateEnv = "SV_RECORD_SEAL_MIGRATE"

// Sealed layouts. Under version 1 of the record key a record is
// prefix || nonce || ciphertext, the layout from before versions, so an
// image from then still reads it; under a later version it is prefixV ||
// version (4 bytes, big-endian) || nonce || ciphertext, the version also
// in the associated data. Plaintext records are JSON or a single byte, so
// they never start with either.
var (
	prefix  = []byte("vsr1")
	prefixV = []byte("vsr2")
)

// ErrPlaintext is a record that is not sealed, read after the migration.
var ErrPlaintext = errors.New("sealstore: record is not sealed")

// ErrOpen is a sealed record that does not open: another key, a version
// whose key is gone, another record's place, or tampered.
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

// Store is a peer.Store that seals what it writes to Inner under the
// current version of the record key and opens what it reads under the
// version it names. A record loaded under an older version is resealed
// in place under the current one. With Legacy, a record that is not
// sealed is accepted and sealed in place as it is loaded (the migration
// of a store written before sealing); without it, such a record is an
// error.
type Store struct {
	Inner   peer.Store
	Pages   Pager // optional: Page reads through it
	Legacy  bool
	current uint32
	aeads   map[uint32]cipher.AEAD
}

// Pager is the paged read of an append-only kind (the audit log).
type Pager interface {
	Page(ctx context.Context, kind, after string, limit int) ([]peer.Record, error)
}

// New returns a Store with the record key's versions in keys (each 32
// bytes), sealing under version current, which keys must hold.
func New(inner peer.Store, keys map[uint32][]byte, current uint32, legacy bool) (*Store, error) {
	if _, ok := keys[current]; !ok || current == 0 || current > MaxVersion {
		return nil, errors.New("sealstore: no key of the current version")
	}
	s := &Store{Inner: inner, Legacy: legacy, current: current, aeads: map[uint32]cipher.AEAD{}}
	for v, key := range keys {
		if len(key) != 32 {
			return nil, errors.New("sealstore: the record key must be 32 bytes")
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if s.aeads[v], err = cipher.NewGCM(b); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// aad binds a record to its place, so that a sealed record cannot be
// moved to another kind or id, and, after version 1, to the version.
func aad(version uint32, kind, id string) []byte {
	if version == 1 {
		return []byte("vettid/service-vault/record/v1\x00" + kind + "\x00" + id)
	}
	return []byte("vettid/service-vault/record/v2\x00" + strconv.FormatUint(uint64(version), 10) + "\x00" + kind + "\x00" + id)
}

func (s *Store) seal(kind, id string, data []byte) ([]byte, error) {
	g := s.aeads[s.current]
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(prefixV)+4+len(nonce)+len(data)+g.Overhead())
	if s.current == 1 {
		out = append(out, prefix...)
	} else {
		out = append(out, prefixV...)
		out = binary.BigEndian.AppendUint32(out, s.current)
	}
	out = append(out, nonce...)
	return g.Seal(out, nonce, data, aad(s.current, kind, id)), nil
}

// open returns a record's plaintext and the version it was sealed under
// (0: not sealed).
func (s *Store) open(kind, id string, data []byte) ([]byte, uint32, error) {
	var version uint32
	var rest []byte
	switch {
	case bytes.HasPrefix(data, prefix):
		version, rest = 1, data[len(prefix):]
	case bytes.HasPrefix(data, prefixV) && len(data) >= len(prefixV)+4:
		version, rest = binary.BigEndian.Uint32(data[len(prefixV):]), data[len(prefixV)+4:]
	case s.Legacy:
		return data, 0, nil
	default:
		return nil, 0, fmt.Errorf("%w: %s %s", ErrPlaintext, kind, id)
	}
	g, ok := s.aeads[version]
	if !ok || version == 0 {
		return nil, version, fmt.Errorf("%w: %s %s: no key of version %d", ErrOpen, kind, id, version)
	}
	n := g.NonceSize()
	if len(rest) < n+g.Overhead() {
		return nil, version, fmt.Errorf("%w: %s %s", ErrOpen, kind, id)
	}
	pt, err := g.Open(nil, rest[:n], rest[n:], aad(version, kind, id))
	if err != nil {
		return nil, version, fmt.Errorf("%w: %s %s", ErrOpen, kind, id)
	}
	return pt, version, nil
}

// Load implements peer.Store. Records found unsealed (with Legacy) or
// under an older version of the key are rewritten under the current one
// (each conditional on its version) and returned with their new version.
func (s *Store) Load(ctx context.Context, kind string) ([]peer.Record, error) {
	recs, err := s.Inner.Load(ctx, kind)
	if err != nil {
		return nil, err
	}
	var reseal []peer.Change
	var at []int
	for i := range recs {
		pt, version, err := s.open(kind, recs[i].ID, recs[i].Data)
		if err != nil {
			return nil, err
		}
		if version != s.current {
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

// Page reads a page of a kind through Pages and opens it.
func (s *Store) Page(ctx context.Context, kind, after string, limit int) ([]peer.Record, error) {
	if s.Pages == nil {
		return nil, errors.New("sealstore: no pager")
	}
	recs, err := s.Pages.Page(ctx, kind, after, limit)
	if err != nil {
		return nil, err
	}
	for i := range recs {
		pt, _, err := s.open(kind, recs[i].ID, recs[i].Data)
		if err != nil {
			return nil, err
		}
		recs[i].Data = pt
	}
	return recs, nil
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

// Reseal loads every record of the kinds, so that each one found
// unsealed (with Legacy) or under an older version of the key is sealed
// in place under the current one. Expired records are not read, and stay
// as they are until the table deletes them.
func (s *Store) Reseal(ctx context.Context, kinds []string) error {
	for _, k := range kinds {
		if _, err := s.Load(ctx, k); err != nil {
			return err
		}
	}
	return nil
}
