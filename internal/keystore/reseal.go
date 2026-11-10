package keystore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// ResealReport is what Reseal did.
type ResealReport struct {
	// Resealed are the records moved to an encryption context; Already
	// those that had one.
	Resealed, Already []string
}

// Reseal moves every record in blobs to its encryption context (key
// protection, GC #7406 §7 step 2): each record without one is opened,
// sealed again under the same KMS key with {ContextKey: name}, and put in
// place of its exact old bytes (Blobs.Replace), never deleted and made
// again. Then every record is read back and opened with its context. A
// record that doesn't open, or changed meanwhile, stops it with an error;
// what it moved stays moved, and a run again picks up the rest. It runs
// with the service stopped, as an owner-run one-off.
func Reseal(ctx context.Context, kms KMS, blobs Blobs) (*ResealReport, error) {
	names, err := blobs.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("keystore: list: %w", err)
	}
	sort.Strings(names)
	rep := &ResealReport{}
	for _, name := range names {
		raw, err := blobs.Get(ctx, name)
		if err != nil {
			return rep, fmt.Errorf("keystore: %s: %w", name, err)
		}
		var s Sealed
		if err := json.Unmarshal(raw, &s); err != nil {
			return rep, fmt.Errorf("keystore: %s: %w", name, ErrOpen)
		}
		if s.Context {
			rep.Already = append(rep.Already, name)
			continue
		}
		pt, err := Open(ctx, kms, name, &s)
		if err != nil {
			return rep, fmt.Errorf("keystore: %s: %w", name, err)
		}
		ns, err := Seal(ctx, kms, s.KeyID, name, pt)
		clear(pt)
		if err != nil {
			return rep, fmt.Errorf("keystore: %s: %w", name, err)
		}
		data, err := json.Marshal(ns)
		if err != nil {
			return rep, err
		}
		if err := blobs.Replace(ctx, name, raw, data); err != nil {
			return rep, fmt.Errorf("keystore: %s: %w", name, err)
		}
		rep.Resealed = append(rep.Resealed, name)
	}
	// Every record opens with its context.
	for _, name := range names {
		raw, err := blobs.Get(ctx, name)
		if err != nil {
			return rep, fmt.Errorf("keystore: check %s: %w", name, err)
		}
		var s Sealed
		if err := json.Unmarshal(raw, &s); err != nil || !s.Context {
			return rep, fmt.Errorf("keystore: check %s: not sealed with its context", name)
		}
		pt, err := Open(ctx, kms, name, &s)
		if err != nil {
			return rep, fmt.Errorf("keystore: check %s: %w", name, err)
		}
		clear(pt)
	}
	return rep, nil
}
