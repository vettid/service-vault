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
// equal is nil, different is an *IdentityMismatch, and a record that can't
// be read is one too (From "unreadable": held, not trusted). Without it (a
// table from before the record, or restored from a backup taken before
// it), the stored state decides: if a record that names the service's own
// key (a pending epoch's, an hs.init it started, a stored event's, or what
// the caller's evidence finds, such as the approvals' audit log) names
// another key, that is a mismatch and nothing is written; otherwise the
// record is written with the configured key. A record of those kinds that
// can't be read fails the check, and nothing is written. Nothing else is
// read into memory or changed.
func CheckIdentity(ctx context.Context, st Store, ik ed25519.PrivateKey, evidence ...Evidence) error {
	own := ik.Public().(ed25519.PublicKey)
	for range 2 {
		data, ok, err := st.Get(ctx, kindIdentity, identityID)
		if err != nil {
			return fmt.Errorf("peer: identity record: %w", err)
		}
		if ok {
			var r identityRecord
			if err := json.Unmarshal(data, &r); err != nil || len(r.IK) != ed25519.PublicKeySize {
				return &IdentityMismatch{Configured: own, From: "unreadable"}
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
		for _, ev := range evidence {
			k, err := ev(ctx)
			if err != nil {
				return fmt.Errorf("peer: identity evidence: %w", err)
			}
			if len(k) > 0 && !bytes.Equal(k, own) {
				return &IdentityMismatch{Recorded: k, Configured: own, From: "state"}
			}
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

// Evidence finds the service's own identity key in stored records the peer
// doesn't own (nil: none found), for CheckIdentity on a table without the
// record.
type Evidence func(ctx context.Context) (ed25519.PublicKey, error)

// Pager reads the records of a kind a page at a time, in id order.
type Pager interface {
	Page(ctx context.Context, kind, after string, limit int) ([]Record, error)
}

// ServiceIKIn is Evidence from the records of a kind whose JSON has a
// "service_ik" (the approvals' audit log, kept for good): the first record
// that has one, read a page at a time.
func ServiceIKIn(pg Pager, kind string) Evidence {
	return func(ctx context.Context) (ed25519.PublicKey, error) {
		after := ""
		for {
			recs, err := pg.Page(ctx, kind, after, 100)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", kind, err)
			}
			for _, r := range recs {
				var e struct {
					ServiceIK []byte `json:"service_ik"`
				}
				if err := json.Unmarshal(r.Data, &e); err != nil {
					return nil, fmt.Errorf("%s %s: %w", kind, r.ID, err)
				}
				if len(e.ServiceIK) > 0 {
					return e.ServiceIK, nil
				}
			}
			if len(recs) < 100 {
				return nil, nil
			}
			after = recs[len(recs)-1].ID
		}
	}
}

// stateIdentity looks for the service's own key in the peer's records of
// a table without the record: the pending epochs of its connections, the
// hs.init of the handshakes it started, and the events it stored (a
// sign-in's carries the challenger's key). It returns a mismatch when one
// names another key, and an error when one of them can't be read.
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
		if err := json.Unmarshal(r.Data, &c); err != nil {
			return nil, fmt.Errorf("peer: identity: %s %s: %w", kindConn, r.ID, err)
		}
		if c.Pending != nil && len(c.Pending.OwnIK) > 0 && !bytes.Equal(c.Pending.OwnIK, own) {
			return &IdentityMismatch{Recorded: c.Pending.OwnIK, Configured: own, From: "state"}, nil
		}
	}
	outs, err := st.Load(ctx, kindOutgoing)
	if err != nil {
		return nil, fmt.Errorf("peer: identity: load %s: %w", kindOutgoing, err)
	}
	for _, r := range outs {
		var og outgoing
		if err := json.Unmarshal(r.Data, &og); err != nil {
			return nil, fmt.Errorf("peer: identity: %s %s: %w", kindOutgoing, r.ID, err)
		}
		ini, err := handshake.RestoreInitiator(og.Init, ik)
		if errors.Is(err, handshake.ErrIdentity) {
			return &IdentityMismatch{Configured: own, From: "state"}, nil
		}
		if err != nil {
			return nil, fmt.Errorf("peer: identity: %s %s: %w", kindOutgoing, r.ID, err)
		}
		ini.Abort() // only read: its ephemeral secret goes now
	}
	events, err := st.Load(ctx, kindEvent)
	if err != nil {
		return nil, fmt.Errorf("peer: identity: load %s: %w", kindEvent, err)
	}
	for _, r := range events {
		var e struct {
			ServiceIK []byte `json:"service_ik"`
		}
		if err := json.Unmarshal(r.Data, &e); err != nil {
			return nil, fmt.Errorf("peer: identity: %s %s: %w", kindEvent, r.ID, err)
		}
		if len(e.ServiceIK) > 0 && !bytes.Equal(e.ServiceIK, own) {
			return &IdentityMismatch{Recorded: e.ServiceIK, Configured: own, From: "state"}, nil
		}
	}
	return nil, nil
}
