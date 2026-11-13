package vaultroots

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"testing/fstest"
	"time"
)

// vector is BALLOT-PROTOCOL §11 item 3: a real staging proposal and the
// bundle the service anchored for it.
type vector struct {
	AnchorKey string          `json:"anchor_key"`
	Proposal  string          `json:"proposal"`
	Timestamp int64           `json:"timestamp"`
	Bundle    json.RawMessage `json:"bundle"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("../../vote/testdata/anchor-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v vector) key(t *testing.T) []byte {
	t.Helper()
	k, err := base64.StdEncoding.DecodeString(v.AnchorKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The real staging bundle verifies against every pinned staging release.
func TestCheckRealStagingBundle(t *testing.T) {
	v := loadVector(t)
	now := time.Unix(v.Timestamp, 0).Add(time.Minute)
	if err := Check("staging", [][]byte{v.key(t)}, []byte(v.Proposal), v.Bundle, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	sets, err := Sets("staging")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range sets {
		n += len(s.Releases)
	}
	if n < 5 || len(sets) != 1 {
		t.Fatalf("%d sets over %d releases (want the identical roots of 25-29 as one set)", len(sets), n)
	}
}

// What a member vault refuses, this refuses: another document, another
// anchor key, a timestamp more than 300 s after this clock, and an
// instance with no pinned roots.
func TestCheckRefuses(t *testing.T) {
	v := loadVector(t)
	key := v.key(t)
	now := time.Unix(v.Timestamp, 0).Add(time.Minute)
	if Check("staging", [][]byte{key}, []byte(v.Proposal+" "), v.Bundle, now, time.Time{}) == nil {
		t.Fatal("another document verified")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if Check("staging", [][]byte{spki}, []byte(v.Proposal), v.Bundle, now, time.Time{}) == nil {
		t.Fatal("another anchor key verified")
	}
	early := time.Unix(v.Timestamp, 0).Add(-Slack - time.Second)
	if Check("staging", [][]byte{key}, []byte(v.Proposal), v.Bundle, early, time.Time{}) == nil {
		t.Fatal("a timestamp past this clock plus 300 s verified")
	}
	if err := Check("production", [][]byte{key}, []byte(v.Proposal), v.Bundle, now, time.Time{}); !errors.Is(err, ErrNoRoots) {
		t.Fatalf("production: %v", err)
	}
	if Check("elsewhere", [][]byte{key}, []byte(v.Proposal), v.Bundle, now, time.Time{}) == nil {
		t.Fatal("an unknown instance checked")
	}
	// An extension's limit, the close it extends, when earlier than the
	// clock's: a stamp after it is refused, one before it passes.
	stamp := time.Unix(v.Timestamp, 0)
	if Check("staging", [][]byte{key}, []byte(v.Proposal), v.Bundle, now, stamp.Add(-time.Second)) == nil {
		t.Fatal("a timestamp after notAfter verified")
	}
	if err := Check("staging", [][]byte{key}, []byte(v.Proposal), v.Bundle, now, stamp.Add(time.Second)); err != nil {
		t.Fatalf("a timestamp before notAfter: %v", err)
	}
	// A later notAfter doesn't relax the clock's limit.
	if Check("staging", [][]byte{key}, []byte(v.Proposal), v.Bundle, early, stamp.Add(time.Hour)) == nil {
		t.Fatal("a later notAfter relaxed the clock's limit")
	}
}

// A bundle must pass every set: one that fails one release's roots is
// refused even if another's accept it.
func TestCheckEverySet(t *testing.T) {
	v := loadVector(t)
	good, err := Sets("staging")
	if err != nil {
		t.Fatal(err)
	}
	empty := Set{Releases: []string{"99"}}
	now := time.Unix(v.Timestamp, 0).Add(time.Minute)
	if check(append([]Set{good[0]}, empty), [][]byte{v.key(t)}, []byte(v.Proposal), v.Bundle, now, time.Time{}) == nil {
		t.Fatal("a bundle passed though one release's roots refuse it")
	}
	if !errors.Is(check(nil, nil, nil, nil, now, time.Time{}), ErrNoRoots) {
		t.Fatal("no sets checked")
	}
}

// A file that isn't release-<n>.json, or roots that don't parse, fail
// the load: nothing is checked against a set that isn't the release's.
func TestParseRefusesStrayFiles(t *testing.T) {
	good, err := files.ReadFile("roots/staging/release-25.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parse(fstest.MapFS{"roots/staging/release-25.json": {Data: good}}); err != nil {
		t.Fatalf("a good file: %v", err)
	}
	for name, f := range map[string]fstest.MapFS{
		"stray":         {"roots/staging/notes.txt": {Data: []byte("x")}},
		"garbage":       {"roots/staging/release-1.json": {Data: []byte("[{}]")}},
		"no number":     {"roots/staging/release-.json": {Data: good}},
		"not a number":  {"roots/staging/release-abc.json": {Data: good}},
		"leading zero":  {"roots/staging/release-025.json": {Data: good}},
		"signed number": {"roots/staging/release-+25.json": {Data: good}},
	} {
		if _, err := parse(f); err == nil {
			t.Fatalf("%s: loaded", name)
		}
	}
}
