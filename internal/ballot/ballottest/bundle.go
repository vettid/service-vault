// Package ballottest stands in for Sigstore bundles in tests of the ballot
// manager: a bundle that carries its two times as plain fields, and the
// Manager.Timestamp function that reads them. The real check is
// anchor.TimestampTime.
package ballottest

import (
	"encoding/json"
	"errors"
)

// Bundle returns a test bundle with timestamp time tsa and Rekor entry
// time integrated (Unix seconds).
func Bundle(tsa, integrated int64) json.RawMessage {
	b, _ := json.Marshal(map[string]int64{"test_tsa": tsa, "test_integrated": integrated})
	return b
}

// Time reads a test bundle's timestamp (Manager.Timestamp in tests).
func Time(bundle json.RawMessage, _ []byte) (int64, error) {
	var b struct {
		TSA int64 `json:"test_tsa"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil || b.TSA <= 0 {
		return 0, errors.New("ballottest: no timestamp in the bundle")
	}
	return b.TSA, nil
}
