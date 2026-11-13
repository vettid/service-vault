//go:build rootscheck

package vaultroots

// The rootscheck test (go test -tags rootscheck ./internal/vaultroots/)
// compares the copies under roots/ with the vault releases they copy. It
// needs the network and a clone of vettid-vault with its release tags:
//
//	VAULTROOTS_VAULT_REPO=/path/to/vettid-vault go test -tags rootscheck ./internal/vaultroots/
//
// For each channel it reads the signed manifest (verified under the
// manifest keys of the channel's newest release tag) and requires a copy,
// byte for byte equal to the release's vote_trust_roots, for every
// release that registers the vote feature and is supported: listed
// active or deprecated, or a candidate (tagged, numbered above every
// listed release). A copy of any other release fails too: it would hold
// the service to roots no supported vault pins. A channel whose manifest
// is not published (HTTP 404) has every tagged release counted as
// supported, so nothing is missed while it is absent.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/manifest"
)

// manifestURLs are the channels' served manifests (VAULT-RELEASES §11.10.1).
var manifestURLs = map[string]string{
	"staging": "https://staging.vettid.org/.well-known/vettid/pcr-manifest.json",
	"prod":    "https://vettid.org/.well-known/vettid/pcr-manifest.json",
}

func TestCopiesMatchReleases(t *testing.T) {
	repo := os.Getenv("VAULTROOTS_VAULT_REPO")
	if repo == "" {
		t.Fatal("VAULTROOTS_VAULT_REPO is not set (a vettid-vault clone with its release tags)")
	}
	for _, channel := range Instances {
		t.Run(channel, func(t *testing.T) { checkChannel(t, repo, channel) })
	}
}

// releaseCfg is what the check reads of enclave/releasecfg/<channel>.json.
type releaseCfg struct {
	ManifestKeys   []string        `json:"manifest_keys"`
	Features       []string        `json:"features"`
	VoteTrustRoots json.RawMessage `json:"vote_trust_roots"`
}

func checkChannel(t *testing.T, repo, channel string) {
	url, ok := manifestURLs[channel]
	if !ok {
		t.Fatalf("no manifest URL for channel %s", channel)
	}
	tags := releaseTags(t, repo, channel)
	cfgs := map[uint64]releaseCfg{}
	for _, n := range tags {
		cfgs[n] = readCfg(t, repo, channel, n)
	}

	supported := supportedReleases(t, url, tags, cfgs)
	want := map[uint64]bool{}
	for _, n := range supported {
		if slices.Contains(cfgs[n].Features, "vote") {
			want[n] = true
		}
	}

	have := map[uint64][]byte{}
	dir := path.Join("roots", channel)
	ents, err := fs.ReadDir(files, dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	for _, e := range ents {
		n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(e.Name(), "release-"), ".json"), 10, 64)
		if err != nil {
			t.Fatalf("%s/%s: not release-<n>.json", dir, e.Name())
		}
		b, err := fs.ReadFile(files, path.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		have[n] = b
	}

	for n := range want {
		copyBytes, ok := have[n]
		if !ok {
			t.Errorf("release %s/%d registers vote and is supported, but %s/release-%d.json is missing", channel, n, dir, n)
			continue
		}
		raw := cfgs[n].VoteTrustRoots
		if len(raw) == 0 {
			t.Errorf("release %s/%d registers vote but pins no vote_trust_roots", channel, n)
			continue
		}
		var exp bytes.Buffer
		if err := json.Indent(&exp, raw, "", "  "); err != nil {
			t.Fatalf("release %s/%d: vote_trust_roots: %v", channel, n, err)
		}
		exp.WriteByte('\n')
		if !bytes.Equal(exp.Bytes(), copyBytes) {
			t.Errorf("%s/release-%d.json differs from vote_trust_roots at tag release/%s/%d", dir, n, channel, n)
		}
	}
	for n := range have {
		if !want[n] {
			t.Errorf("%s/release-%d.json: release %s/%d is not a supported release that registers vote; remove the copy", dir, n, channel, n)
		}
	}
	t.Logf("%s: supported releases registering vote %v; copies %d", channel, sortedKeys(want), len(have))
}

// supportedReleases returns the releases of a channel that vaults may run
// now or soon: active or deprecated in the signed manifest, and the
// candidates above it. With no manifest published, every tag.
func supportedReleases(t *testing.T, url string, tags []uint64, cfgs map[uint64]releaseCfg) []uint64 {
	t.Helper()
	raw, status := fetch(t, url)
	if status == http.StatusNotFound {
		t.Logf("%s: not published (404); every tagged release counts as supported", url)
		return tags
	}
	if status != http.StatusOK {
		t.Fatalf("%s: HTTP %d", url, status)
	}
	if len(tags) == 0 {
		t.Fatalf("%s is published but the channel has no release tags", url)
	}
	served, err := manifest.ParseServed(raw)
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	newest := tags[len(tags)-1]
	keys := parseKeys(t, cfgs[newest].ManifestKeys)
	m, err := manifest.Verify(served, keys)
	if err != nil {
		t.Fatalf("%s: under the manifest keys of release %d: %v", url, newest, err)
	}
	var out []uint64
	var highest uint64
	for _, r := range m.Releases {
		highest = max(highest, r.Number)
		if r.Status == manifest.StatusActive || r.Status == manifest.StatusDeprecated {
			out = append(out, r.Number)
		}
	}
	for _, n := range tags {
		if n > highest {
			out = append(out, n)
		}
	}
	for _, n := range out {
		if _, ok := cfgs[n]; !ok {
			t.Fatalf("%s lists release %d as supported, but there is no tag for it", url, n)
		}
	}
	t.Logf("%s: serial %d, highest listed %d, supported %v", url, m.Serial, highest, out)
	return out
}

func fetch(t *testing.T, url string) ([]byte, int) {
	t.Helper()
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, manifest.MaxServed+1))
	if err != nil {
		t.Fatalf("%s: %v", url, err)
	}
	return b, resp.StatusCode
}

func parseKeys(t *testing.T, b64 []string) []*ecdsa.PublicKey {
	t.Helper()
	var out []*ecdsa.PublicKey
	for _, s := range b64 {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("manifest key: %v", err)
		}
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			t.Fatalf("manifest key: %v", err)
		}
		ek, ok := k.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("manifest key: %T, not ECDSA", k)
		}
		out = append(out, ek)
	}
	if len(out) == 0 {
		t.Fatal("the newest release pins no manifest keys")
	}
	return out
}

func releaseTags(t *testing.T, repo, channel string) []uint64 {
	t.Helper()
	out := git(t, repo, "tag", "-l", "release/"+channel+"/*")
	var tags []uint64
	for _, line := range strings.Fields(string(out)) {
		n, err := strconv.ParseUint(strings.TrimPrefix(line, "release/"+channel+"/"), 10, 64)
		if err != nil {
			continue
		}
		tags = append(tags, n)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })
	return tags
}

func readCfg(t *testing.T, repo, channel string, n uint64) releaseCfg {
	t.Helper()
	raw := git(t, repo, "show", fmt.Sprintf("release/%s/%d:enclave/releasecfg/%s.json", channel, n, channel))
	var c releaseCfg
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("release %s/%d: %v", channel, n, err)
	}
	return c
}

func git(t *testing.T, repo string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

func sortedKeys(m map[uint64]bool) []uint64 {
	var out []uint64
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
