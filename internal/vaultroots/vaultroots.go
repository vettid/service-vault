// Package vaultroots checks a proposal's or an extension's Sigstore
// bundle as a member vault will (VAULT-MESSAGING §10.19.4 step 6),
// before the service publishes and sends it: with vettid-vault's own
// verifier (vms/votewire) and the trusted roots pinned in each vault
// release that may receive it.
//
// roots/<instance>/release-<n>.json is a copy of release n's
// vote_trust_roots (vettid-vault enclave/releasecfg/<channel>.json at
// tag release/<channel>/<n>), for every release of that channel that is
// active, deprecated or a candidate in its manifest and registers the
// vote feature (BALLOT-PROTOCOL §3.3). A bundle must verify against each
// of them, so a vault that dropped a root still accepts it. The copies
// are checked against the releases and the manifest by the rootscheck
// test (go test -tags rootscheck).
package vaultroots

import (
	"crypto/sha256"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/votewire"
)

//go:embed roots
var files embed.FS

// Instances maps a Sigstore instance (SV_SIGSTORE) to its vault channel.
var Instances = map[string]string{"staging": "staging", "production": "prod"}

// Slack is how far past this service's clock a bundle's timestamp may
// be: a member vault refuses one later than the relay's time of the
// message plus 300 s (VAULT-MESSAGING §10.19.4 step 6), and the relay's
// time is at or after the send.
const Slack = 300 * time.Second

// ErrNoRoots is an instance with no pinned roots: no vault release of it
// takes votes, so nothing can be checked, and nothing is sent.
var ErrNoRoots = errors.New("vaultroots: no vault release of this instance pins vote trust roots")

// Set is one distinct set of pinned roots and the releases that pin it.
type Set struct {
	Releases []string
	Roots    []*votewire.TrustRoot
}

var (
	once  sync.Once
	sets  map[string][]Set
	setsE error
)

func load() (map[string][]Set, error) {
	once.Do(func() { sets, setsE = parse(files) })
	return sets, setsE
}

// parse reads every roots/<instance>/release-<n>.json, grouping
// identical files into one set.
func parse(fsys fs.FS) (map[string][]Set, error) {
	out := map[string][]Set{}
	for inst, channel := range Instances {
		dir := path.Join("roots", channel)
		ents, err := fs.ReadDir(fsys, dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		byHash := map[[32]byte]int{}
		var list []Set
		for _, e := range ents {
			name := e.Name()
			rel, ok := strings.CutPrefix(name, "release-")
			if !ok || !strings.HasSuffix(rel, ".json") || e.IsDir() {
				return nil, fmt.Errorf("vaultroots: unexpected file %s/%s", dir, name)
			}
			rel = strings.TrimSuffix(rel, ".json")
			raw, err := fs.ReadFile(fsys, path.Join(dir, name))
			if err != nil {
				return nil, err
			}
			roots, err := votewire.ParseTrustRoots(raw)
			if err != nil {
				return nil, fmt.Errorf("vaultroots: %s/%s: %w", dir, name, err)
			}
			h := sha256.Sum256(raw)
			if i, ok := byHash[h]; ok {
				list[i].Releases = append(list[i].Releases, rel)
				continue
			}
			byHash[h] = len(list)
			list = append(list, Set{Releases: []string{rel}, Roots: roots})
		}
		for i := range list {
			sort.Strings(list[i].Releases)
		}
		out[inst] = list
	}
	return out, nil
}

// Sets returns the distinct root sets of a Sigstore instance.
func Sets(instance string) ([]Set, error) {
	all, err := load()
	if err != nil {
		return nil, err
	}
	if _, ok := Instances[instance]; !ok {
		return nil, fmt.Errorf("vaultroots: unknown Sigstore instance %q", instance)
	}
	if len(all[instance]) == 0 {
		return nil, ErrNoRoots
	}
	return all[instance], nil
}

// Check verifies bundle for doc against every root set of instance, as
// a member vault does: under one of the accepted anchor keys (SPKI DER),
// timestamped at most Slack after now.
func Check(instance string, accepted [][]byte, doc, bundle []byte, now time.Time) error {
	list, err := Sets(instance)
	if err != nil {
		return err
	}
	return check(list, accepted, doc, bundle, now)
}

func check(list []Set, accepted [][]byte, doc, bundle []byte, now time.Time) error {
	if len(list) == 0 {
		return ErrNoRoots
	}
	for _, s := range list {
		if _, err := votewire.VerifyBundle(doc, bundle, accepted, s.Roots, now.Add(Slack), now); err != nil {
			return fmt.Errorf("vaultroots: the roots of vault release %s: %w", strings.Join(s.Releases, ", "), err)
		}
	}
	return nil
}
