package peer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// kindIdentity holds one record per table: the identity key the table's
// records were made under (GC #9109). The service never rotates its
// identity key (§3.4 is a member vault's), so a configured key that
// differs from it means the keys and the records don't belong together:
// wrong secrets, a wrong or partial restore, or another service's table.
const (
	kindIdentity = "identity"
	identityID   = "ik"
)

type identityRecord struct {
	IK ed25519.PublicKey `json:"ik"`
}

// ErrIdentityMismatch is CheckIdentity's answer when the configured
// identity key is not the table's. Nothing was read into a Peer, changed
// or sent: the caller holds or stops.
var ErrIdentityMismatch = errors.New("peer: the configured identity key is not the one this table's records were made under")

// IdentityMismatch details ErrIdentityMismatch (errors.As).
type IdentityMismatch struct {
	// Recorded is the table's key; nil when the table has no record and a
	// stored handshake's key was not readable (only that it differs).
	Recorded   ed25519.PublicKey
	Configured ed25519.PublicKey
	// From says where the table's key came from: "record", or "state" for
	// a table without the record whose stored handshakes name another key.
	From string
}

func (e *IdentityMismatch) Error() string {
	return fmt.Sprintf("%v (from the %s: table %s, configured %s)", ErrIdentityMismatch, e.From, keyText(e.Recorded), keyText(e.Configured))
}

func (e *IdentityMismatch) Unwrap() error { return ErrIdentityMismatch }

// keyText is a public key for a log line: its base64, or "unknown".
func keyText(k ed25519.PublicKey) string {
	if len(k) == 0 {
		return "unknown"
	}
	return base64.StdEncoding.EncodeToString(k)
}

// CheckIdentity compares the configured identity key with the table's
// before anything reads the table into a Peer (GC #9109). With the record:
// equal is nil, different is an *IdentityMismatch. Without it (a table
// from before the record, or restored from a backup taken before it), the
// stored state decides: if a stored handshake of the service's (a pending
// epoch's own key, an hs.init it started) names another key, that is a
// mismatch and nothing is written; otherwise the record is written with
// the configured key. Nothing else is read into memory or changed.
func CheckIdentity(ctx context.Context, st Store, ik ed25519.PrivateKey) error {
	own := ik.Public().(ed25519.PublicKey)
	for range 2 {
		data, ok, err := st.Get(ctx, kindIdentity, identityID)
		if err != nil {
			return fmt.Errorf("peer: identity record: %w", err)
		}
		if ok {
			var r identityRecord
			if err := json.Unmarshal(data, &r); err != nil || len(r.IK) != ed25519.PublicKeySize {
				return fmt.Errorf("peer: identity record unreadable")
			}
			if !bytes.Equal(r.IK, own) {
				return &IdentityMismatch{Recorded: r.IK, Configured: own, From: "record"}
			}
			return nil
		}
		if m, err := stateIdentity(ctx, st, ik); err != nil || m != nil {
			if err != nil {
				return err
			}
			return m
		}
		b, _ := json.Marshal(identityRecord{IK: own})
		err = st.Apply(ctx, []Change{{Kind: kindIdentity, ID: identityID, Data: b, IfAbsent: true}})
		if errors.Is(err, ErrConflict) {
			continue // written meanwhile: compare with it
		}
		if err != nil {
			return fmt.Errorf("peer: write the identity record: %w", err)
		}
		return nil
	}
	return errors.New("peer: identity record: written and gone")
}

// stateIdentity looks for the service's own key in a table without the
// record: the pending epochs of its connections and the hs.init of the
// handshakes it started. It returns a mismatch when one names another key.
func stateIdentity(ctx context.Context, st Store, ik ed25519.PrivateKey) (*IdentityMismatch, error) {
	own := ik.Public().(ed25519.PublicKey)
	conns, err := st.Load(ctx, kindConn)
	if err != nil {
		return nil, fmt.Errorf("peer: identity: load %s: %w", kindConn, err)
	}
	for _, r := range conns {
		var c struct {
			Pending *struct {
				OwnIK ed25519.PublicKey `json:"own_ik"`
			} `json:"pending"`
		}
		if json.Unmarshal(r.Data, &c) == nil && c.Pending != nil && len(c.Pending.OwnIK) > 0 && !bytes.Equal(c.Pending.OwnIK, own) {
			return &IdentityMismatch{Recorded: c.Pending.OwnIK, Configured: own, From: "state"}, nil
		}
	}
	outs, err := st.Load(ctx, kindOutgoing)
	if err != nil {
		return nil, fmt.Errorf("peer: identity: load %s: %w", kindOutgoing, err)
	}
	for _, r := range outs {
		var og outgoing
		if json.Unmarshal(r.Data, &og) != nil {
			continue // load reports it
		}
		if _, err := handshake.RestoreInitiator(og.Init, ik); errors.Is(err, handshake.ErrIdentity) {
			return &IdentityMismatch{Configured: own, From: "state"}, nil
		}
	}
	return nil, nil
}
