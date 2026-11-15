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
// verifier at its tag to be the one the service runs (verifierCheck):
// every non-test Go file of votewire but votewireNotVerifier, and of the
// vettid-vault packages votewire imports (strictjson, suite), equal byte
// for byte to the vettid-vault version go.mod pins, and no import of a
// vettid-vault package at the tag that the pinned votewire doesn't have.
// strictjson's move from internal/ to vms/ (vettid-vault #237) is undone
// at a tag that has only the old place. A difference fails, naming the
// release and the file, unless testdata/verifier_differences.json lists
// it (release, path, and the sha256 of the tag's file and of the pinned
// one, with the reason it is safe): a change on either side asks for a
// new review. An entry nothing matches fails too. The service checks a
// bundle with this code before it sends anything (BALLOT-PROTOCOL §3.3):
// a release whose own verifier refuses what the service passes would
// never take a proposal. It compares code, not the vault's call site
// (features/vote/intake.go, enclave/releasecfg).

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
	"path/filepath"
	"regexp"
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
	all := true
	for _, channel := range Instances {
		all = t.Run(channel, func(t *testing.T) { checkChannel(t, repo, channel, v) }) && all
	}
	if !all {
		return // a channel failed: its entries may simply not have been reached
	}
	for _, k := range v.known {
		if !v.used[k] {
			t.Errorf("testdata/verifier_differences.json: release %s, %s (tag sha256 %s, pinned %s) matches no difference any more: remove it", k.Release, k.Path, k.SHA256, k.PinnedSHA256)
		}
	}
}

// votewirePkg is the vault's bundle verifier package; votewireNotVerifier
// are its files no bundle or root check reaches (message bodies,
// documents, JCS): every other file is compared, a new one included.
const votewirePkg = "github.com/vettid/vettid-vault/vms/votewire"

var votewireNotVerifier = []string{"body.go", "documents.go", "jcs.go"}

const vvPrefix = "github.com/vettid/vettid-vault/"

// strictjsonMove is vettid-vault #237: strictjson was internal/ before.
var strictjsonMove = [2]string{"internal/strictjson", "vms/strictjson"}

// verifierPkg is the pinned vettid-vault module's copy of part of the
// verifier: a package's module-relative directory and the compared files.
type verifierPkg struct {
	rel   string
	files map[string][]byte
}

// knownDifference is a reviewed difference between a release's verifier
// and the pinned one: path as in the pinned module, and the sha256 of the
// file at the tag (as committed, before any normalizing) and of the
// pinned one (of nothing when a side has no such file).
type knownDifference struct {
	Release      string `json:"release"` // <channel>/<n>
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	PinnedSHA256 string `json:"pinned_sha256"`
	Reason       string `json:"reason"`
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
	if dec.More() {
		t.Fatal("testdata/verifier_differences.json: data after the list")
	}
	for _, k := range out {
		if k.Release == "" || k.Path == "" || !sha256Hex(k.SHA256) || !sha256Hex(k.PinnedSHA256) || strings.TrimSpace(k.Reason) == "" {
			t.Fatalf("testdata/verifier_differences.json: incomplete entry %+v", k)
		}
	}
	return out
}

func sha256Hex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func shaOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// pinnedVerifier reads the compared files from the vettid-vault version
// go.mod pins: votewire's but votewireNotVerifier, and every non-test Go
// file of the vettid-vault packages votewire imports (go list -deps).
func pinnedVerifier(t *testing.T) []verifierPkg {
	t.Helper()
	modDir := strings.TrimSpace(string(goCmd(t, "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/vettid-vault")))
	if modDir == "" {
		t.Fatal("go list -m: no directory for github.com/vettid/vettid-vault (a vendor directory, or not downloaded)")
	}
	var out []verifierPkg
	for _, line := range strings.Split(strings.TrimSpace(string(goCmd(t, "list", "-deps", "-f", "{{.ImportPath}}\t{{.Dir}}", votewirePkg))), "\n") {
		ip, dir, ok := strings.Cut(line, "\t")
		if !ok || !strings.HasPrefix(ip, vvPrefix) {
			continue
		}
		rel, err := filepath.Rel(modDir, dir)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			t.Fatalf("package %s is not under the module directory %s", ip, modDir)
		}
		rel = filepath.ToSlash(rel)
		p := verifierPkg{rel: rel, files: map[string][]byte{}}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if !compared(rel, e.Name()) {
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
	if !slices.ContainsFunc(out, func(p verifierPkg) bool { return p.rel == "vms/votewire" && p.files["bundle.go"] != nil }) {
		t.Fatal("vms/votewire/bundle.go is not in the pinned vettid-vault")
	}
	return out
}

func goSource(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// compared reports whether a file of the package at rel is compared.
func compared(rel, name string) bool {
	return goSource(name) && (rel != "vms/votewire" || !slices.Contains(votewireNotVerifier, name))
}

// vvImport finds a file's imports of vettid-vault packages.
var vvImport = regexp.MustCompile(`"` + regexp.QuoteMeta(vvPrefix) + `([^"]+)"`)

// check compares release n's verifier with the pinned one.
func (v *verifierCheck) check(t *testing.T, repo, channel string, n uint64) {
	t.Helper()
	tag := fmt.Sprintf("release/%s/%d", channel, n)
	rel := fmt.Sprintf("%s/%d", channel, n)
	differ := func(p, why string, atTag, pinned []byte) {
		h, ph := shaOf(atTag), shaOf(pinned)
		for _, k := range v.known {
			if k.Release == rel && k.Path == p && k.SHA256 == h && k.PinnedSHA256 == ph {
				v.used[k] = true
				t.Logf("release %s: %s %s: a known difference (%s)", rel, p, why, k.Reason)
				return
			}
		}
		t.Errorf("release %s: %s %s: the release's bundle verifier differs from the service's (sha256 at the tag %s, pinned %s; if it is safe, list it in testdata/verifier_differences.json with the reason)", rel, p, why, h, ph)
	}
	// strictjson's old place only at a tag that doesn't have the new one.
	hasOld, hasNew := treeHas(t, repo, tag, strictjsonMove[0]), treeHas(t, repo, tag, strictjsonMove[1])
	if hasOld && hasNew {
		t.Errorf("release %s: both %s and %s are there: which one votewire uses isn't known here", rel, strictjsonMove[0], strictjsonMove[1])
		return
	}
	moved := hasOld
	norm := func(b []byte) []byte {
		if !moved {
			return b
		}
		return bytes.ReplaceAll(b, []byte(`"`+vvPrefix+strictjsonMove[0]+`"`), []byte(`"`+vvPrefix+strictjsonMove[1]+`"`))
	}
	// The vettid-vault imports the pinned files have (a build-tagged
	// file's included): one the tag adds is outside what is compared.
	known := map[string]bool{}
	for _, p := range v.pkgs {
		known[p.rel] = true
		for _, b := range p.files {
			for _, m := range vvImport.FindAllSubmatch(b, -1) {
				known[string(m[1])] = true
			}
		}
	}
	for _, p := range v.pkgs {
		dir := p.rel
		if moved && dir == strictjsonMove[1] {
			dir = strictjsonMove[0]
		}
		var atTag []string
		for _, name := range strings.Fields(string(git(t, repo, "ls-tree", "--name-only", tag, dir+"/"))) {
			if name = path.Base(name); compared(p.rel, name) {
				atTag = append(atTag, name)
			}
		}
		for _, name := range atTag {
			pinned := p.rel + "/" + name
			raw := git(t, repo, "show", tag+":"+dir+"/"+name)
			for _, m := range vvImport.FindAllSubmatch(norm(raw), -1) {
				if !known[string(m[1])] {
					t.Errorf("release %s: %s imports %s%s, which the pinned verifier doesn't: it isn't compared", rel, pinned, vvPrefix, m[1])
				}
			}
			want, ok := p.files[name]
			switch {
			case !ok:
				differ(pinned, "is at the tag but not in the pinned vettid-vault", raw, nil)
			case !bytes.Equal(norm(raw), want):
				differ(pinned, "differs", raw, want)
			}
		}
		for name, want := range p.files {
			if !slices.Contains(atTag, name) {
				differ(p.rel+"/"+name, "is in the pinned vettid-vault but not at the tag", nil, want)
			}
		}
	}
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
