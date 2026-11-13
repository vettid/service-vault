// Command rootwatch compares Sigstore's current trusted root with the
// newest trusted root each member-vault release pins
// (internal/vaultroots/roots), and exits 1 when they differ in what a vault reads of them: the Rekor
// logs (tlogs) and the timestamp authorities (vms/votewire reads nothing
// else). A difference means Sigstore added, ended or changed a key: until a
// vault release pins the new roots, a bundle under a new key is refused by
// members' vaults and by this service before sending (alarm
// proposal_bundle_unverified). The scheduled workflow vault-roots.yml runs
// it and opens an issue on a difference.
//
// Sigstore's trusted root is fetched through TUF (sigstore-go), verified
// from the TUF root embedded in sigstore-go.
//
//	go run . -roots ../../internal/vaultroots/roots
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// instance is a Sigstore instance and the vault channel whose releases
// pin roots from it (vaultroots.Instances).
type instance struct {
	name    string
	channel string
	mirror  string
	root    func() []byte
}

var instances = []instance{
	{"staging", "staging", tuf.StagingMirror, tuf.StagingRoot},
	{"production", "prod", tuf.DefaultMirror, tuf.DefaultRoot},
}

// members are the trusted-root members a vault reads.
var members = []string{"tlogs", "timestampAuthorities"}

func main() {
	rootsDir := flag.String("roots", "../../internal/vaultroots/roots", "the pinned copies, roots/<channel>/release-<n>.json")
	flag.Parse()
	diff := false
	for _, in := range instances {
		d, err := check(in, *rootsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", in.name, err)
			os.Exit(2)
		}
		diff = diff || d
	}
	if diff {
		os.Exit(1)
	}
}

func check(in instance, rootsDir string) (bool, error) {
	dir := filepath.Join(rootsDir, in.channel)
	copies, err := filepath.Glob(filepath.Join(dir, "release-*.json"))
	if err != nil {
		return false, err
	}
	if len(copies) == 0 {
		if _, err := os.Stat(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		fmt.Printf("%s: no vault release pins roots for this instance; nothing to compare\n", in.name)
		return false, nil
	}
	sort.Strings(copies)

	c, err := tuf.New(tuf.DefaultOptions().WithRoot(in.root()).WithRepositoryBaseURL(in.mirror).WithDisableLocalCache())
	if err != nil {
		return false, fmt.Errorf("TUF %s: %w", in.mirror, err)
	}
	raw, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return false, fmt.Errorf("TUF %s trusted_root.json: %w", in.mirror, err)
	}
	current, err := entries(raw)
	if err != nil {
		return false, fmt.Errorf("trusted_root.json from %s: %w", in.mirror, err)
	}

	diff := false
	for _, p := range copies {
		b, err := os.ReadFile(p)
		if err != nil {
			return false, err
		}
		var roots []json.RawMessage
		if err := json.Unmarshal(b, &roots); err != nil {
			return false, fmt.Errorf("%s: %w", p, err)
		}
		if len(roots) == 0 {
			return false, fmt.Errorf("%s: no trusted root", p)
		}
		// The newest root only: a release may keep an older one beside
		// it (a bundle verifies under any), and that one differs from
		// Sigstore's current root by design.
		pinned, err := entries(roots[len(roots)-1])
		if err != nil {
			return false, fmt.Errorf("%s: %w", p, err)
		}
		name := filepath.Base(p)
		for _, k := range sortedKeys(current) {
			if !pinned[k] {
				diff = true
				fmt.Printf("%s %s: in Sigstore's trusted root, not pinned: %s\n", in.name, name, k)
			}
		}
		for _, k := range sortedKeys(pinned) {
			if !current[k] {
				diff = true
				fmt.Printf("%s %s: pinned, not (or no longer the same) in Sigstore's trusted root: %s\n", in.name, name, k)
			}
		}
	}
	if !diff {
		fmt.Printf("%s: Sigstore's trusted root matches the %d pinned copies\n", in.name, len(copies))
	}
	return diff, nil
}

// entries returns each tlogs and timestampAuthorities entry of a trusted
// root as canonical JSON (member names sorted), prefixed by its member.
func entries(raw []byte) (map[string]bool, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range members {
		if len(root[m]) == 0 {
			continue
		}
		var list []any
		if err := json.Unmarshal(root[m], &list); err != nil {
			return nil, fmt.Errorf("%s: %w", m, err)
		}
		for _, e := range list {
			b, err := json.Marshal(e) // map keys sorted
			if err != nil {
				return nil, err
			}
			out[m+" "+string(b)] = true
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no " + strings.Join(members, " or ") + " entries")
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
