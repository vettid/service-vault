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
//
// It also requires, for each of those releases, the vault's bundle
// verifier at its tag to be the one the service runs (checkVerifier):
// votewire's bundle.go, trust.go, merkle.go and verify.go, and every
// non-test Go file of the vettid-vault packages they import (strictjson,
// suite), equal byte for byte to the vettid-vault version go.mod pins.
// strictjson's move from internal/ to vms/ (vettid-vault #237) is undone
// before comparing. A difference fails, naming the release and the file,
// unless testdata/verifier_differences.json lists it (release, path and
// the tag file's sha256, with the reason it is safe); an entry nothing
// matches fails too. The service checks a bundle with this code before
// it sends anything (BALLOT-PROTOCOL §3.3): a release whose own verifier
// refuses what the service passes would never take a proposal.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
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
	v := &verifierCheck{pkgs: pinnedVerifier(t), known: readKnownDifferences(t), used: map[knownDifference]bool{}}
	for _, channel := range Instances {
		t.Run(channel, func(t *testing.T) { checkChannel(t, repo, channel, v) })
	}
	for _, k := range v.known {
		if !v.used[k] {
			t.Errorf("testdata/verifier_differences.json: release %s, %s, sha256 %s matches no difference any more: remove it", k.Release, k.Path, k.SHA256)
		}
	}
}

// votewirePkg is the vault's bundle verifier package; votewireFiles are
// its files that verify a bundle and the roots (the rest are message
// bodies and documents).
const votewirePkg = "github.com/vettid/vettid-vault/vms/votewire"

var votewireFiles = []string{"bundle.go", "trust.go", "merkle.go", "verify.go"}

// strictjsonMove is vettid-vault #237: strictjson was internal/ before.
var strictjsonMove = [2]string{"internal/strictjson", "vms/strictjson"}

// verifierPkg is the pinned vettid-vault module's copy of part of the
// verifier: a package's module-relative directory and the compared files.
type verifierPkg struct {
	rel   string
	files map[string][]byte
}

// knownDifference is a reviewed difference between a release's verifier
// and the pinned one: path as in the pinned module, sha256 of the file at
// the tag (as committed, before any normalizing).
type knownDifference struct {
	Release string `json:"release"` // <channel>/<n>
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Reason  string `json:"reason"`
}

type verifierCheck struct {
	pkgs  []verifierPkg
	known []knownDifference
	used  map[knownDifference]bool
}

func readKnownDifferences(t *testing.T) []knownDifference {
	t.Helper()
	b, err := os.ReadFile("testdata/verifier_differences.json")
	if err != nil {
		t.Fatal(err)
	}
	var out []knownDifference
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("testdata/verifier_differences.json: %v", err)
	}
	for _, k := range out {
		if k.Release == "" || k.Path == "" || len(k.SHA256) != 64 || strings.TrimSpace(k.Reason) == "" {
			t.Fatalf("testdata/verifier_differences.json: incomplete entry %+v", k)
		}
	}
	return out
}

// pinnedVerifier reads the compared files from the vettid-vault version
// go.mod pins: votewireFiles, and every non-test Go file of the
// vettid-vault packages votewire imports (go list -deps).
func pinnedVerifier(t *testing.T) []verifierPkg {
	t.Helper()
	modDir := strings.TrimSpace(string(goCmd(t, "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/vettid-vault")))
	var out []verifierPkg
	for _, line := range strings.Split(strings.TrimSpace(string(goCmd(t, "list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}", votewirePkg))), "\n") {
		ip, dir, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasPrefix(ip, "github.com/vettid/vettid-vault/") {
			continue
		}
		rel, ok := strings.CutPrefix(dir, modDir+"/")
		if !ok {
			t.Fatalf("package %s is not under the module directory %s", ip, modDir)
		}
		p := verifierPkg{rel: rel, files: map[string][]byte{}}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if !goSource(e.Name()) || ip == votewirePkg && !slices.Contains(votewireFiles, e.Name()) {
				continue
			}
			b, err := os.ReadFile(path.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			p.files[e.Name()] = b
		}
		out = append(out, p)
	}
	for _, f := range votewireFiles {
		if !slices.ContainsFunc(out, func(p verifierPkg) bool { return p.rel == "vms/votewire" && p.files[f] != nil }) {
			t.Fatalf("vms/votewire/%s is not in the pinned vettid-vault", f)
		}
	}
	return out
}

func goSource(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// checkVerifier compares release n's verifier with the pinned one.
func (v *verifierCheck) check(t *testing.T, repo, channel string, n uint64) {
	t.Helper()
	tag := fmt.Sprintf("release/%s/%d", channel, n)
	rel := fmt.Sprintf("%s/%d", channel, n)
	differ := func(p, why string, atTag []byte) {
		sum := sha256.Sum256(atTag)
		h := hex.EncodeToString(sum[:])
		for _, k := range v.known {
			if k.Release == rel && k.Path == p && k.SHA256 == h {
				v.used[k] = true
				t.Logf("release %s: %s %s: a known difference (%s)", rel, p, why, k.Reason)
				return
			}
		}
		t.Errorf("release %s: %s %s: the release's bundle verifier differs from the service's (tag file sha256 %s; if it is safe, list it in testdata/verifier_differences.json with the reason)", rel, p, why, h)
	}
	for _, p := range v.pkgs {
		dir := p.rel
		if dir == strictjsonMove[1] && !treeHas(t, repo, tag, dir) {
			dir = strictjsonMove[0]
		}
		var atTag []string
		for _, name := range strings.Fields(string(git(t, repo, "ls-tree", "--name-only", tag, dir+"/"))) {
			name = path.Base(name)
			if goSource(name) && (p.rel != "vms/votewire" || slices.Contains(votewireFiles, name)) {
				atTag = append(atTag, name)
			}
		}
		for _, name := range atTag {
			pinned := p.rel + "/" + name
			raw := git(t, repo, "show", tag+":"+dir+"/"+name)
			want, ok := p.files[name]
			switch {
			case !ok:
				differ(pinned, "is at the tag but not in the pinned vettid-vault", raw)
			case !bytes.Equal(undoMove(raw), want):
				differ(pinned, "differs", raw)
			}
		}
		for name := range p.files {
			if !slices.Contains(atTag, name) {
				differ(p.rel+"/"+name, "is in the pinned vettid-vault but not at the tag", nil)
			}
		}
	}
}

// undoMove rewrites a tag file's import of strictjson's old place to its
// new one.
func undoMove(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte(`"github.com/vettid/vettid-vault/`+strictjsonMove[0]+`"`), []byte(`"github.com/vettid/vettid-vault/`+strictjsonMove[1]+`"`))
}

func treeHas(t *testing.T, repo, tag, dir string) bool {
	t.Helper()
	return len(bytes.TrimSpace(git(t, repo, "ls-tree", tag, dir))) > 0
}

func goCmd(t *testing.T, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("go", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

// releaseCfg is what the check reads of enclave/releasecfg/<channel>.json.
type releaseCfg struct {
	Channel        string          `json:"channel"`
	Release        uint64          `json:"release"`
	ManifestKeys   []string        `json:"manifest_keys"`
	Features       []string        `json:"features"`
	VoteTrustRoots json.RawMessage `json:"vote_trust_roots"`
}

func checkChannel(t *testing.T, repo, channel string, v *verifierCheck) {
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
	for _, n := range sortedKeys(want) {
		v.check(t, repo, channel, n)
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
	if c.Channel != channel || c.Release != n {
		t.Fatalf("tag release/%s/%d holds the config of channel %q release %d", channel, n, c.Channel, c.Release)
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
