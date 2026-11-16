package vaultroots

// The bundle verifier comparison of the rootscheck test (rootscheck_test.go,
// build tag rootscheck): for a release tag of a vettid-vault clone, its
// verifier code against the pinned one. It needs only git and the go
// command, so it is tested offline here (verifier_check_offline_test.go)
// against a fixture repo, and the pinned module's side runs in every test
// run (TestPinnedVerifier).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// votewirePkg is the vault's bundle verifier package. Every non-test Go
// file of it is compared: its message bodies, documents and JCS too, as
// code there runs in the same process and could reach the verifier in
// ways no list of rules covers (a package variable written, a GODEBUG
// set, a hash registered).
const votewirePkg = "github.com/vettid/vettid-vault/vms/votewire"

// notCompared are vettid-vault packages one compared file may import while
// they are not compared themselves: the package, the one file (as in the
// pinned module) that may import it, and why.
var notCompared = map[string]struct{ from, why string }{
	"internal/hpkederand": {"vms/suite/rand_vectors.go", "under the vmsvectors build tag: test vectors, not in a member's build"},
}

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

// buildPath is the knownDifference path of the build settings
// (buildSettings).
const buildPath = "build settings (go.mod go/toolchain/godebug, //go:debug)"

type verifierCheck struct {
	pkgs  []verifierPkg
	build string // the service's buildSettings
	known []knownDifference
	used  map[knownDifference]bool
}

// reporter is the part of *testing.T the comparison reports through (a
// recorder in the offline tests).
type reporter interface {
	Helper()
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

// parseKnownDifferences reads testdata/verifier_differences.json's
// contents.
func parseKnownDifferences(b []byte) ([]knownDifference, error) {
	var out []knownDifference
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("data after the list")
	}
	for _, k := range out {
		if k.Release == "" || k.Path == "" || !sha256Hex(k.SHA256) || !sha256Hex(k.PinnedSHA256) || strings.TrimSpace(k.Reason) == "" {
			return nil, fmt.Errorf("incomplete entry %+v", k)
		}
	}
	return out, nil
}

func sha256Hex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && s == strings.ToLower(s)
}

func shaOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// compared reports whether a file of a compared package is compared:
// every non-test Go file.
func compared(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// entryOK reports whether a compared package's directory may hold an
// entry: Go files, docs, and a testdata directory. Anything else (an
// assembly or C file, a .syso, an embedded file) could change what is
// built without a compared Go file changing.
func entryOK(name string, dir bool) bool {
	if dir {
		return name == "testdata"
	}
	return strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".md")
}

// buildSettings is what decides how a module's code is built and behaves
// by default, besides the code: go.mod's go and toolchain versions and
// godebug settings (as the go command reads them: go mod edit -json, run
// outside any module, with the local toolchain), and the tree's
// //go:debug directives (both set GODEBUG defaults, some of crypto/x509's
// and encoding/asn1's parsing among them). One per line.
func buildSettings(t *testing.T, gomod []byte, goDebug []string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "mod", "edit", "-json", "go.mod")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod edit -json: %v: %s", err, stderr.String())
	}
	var m struct {
		Go, Toolchain string
		Godebug       []struct{ Key, Value string }
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("go mod edit -json: %v", err)
	}
	lines := []string{"go " + m.Go}
	if m.Toolchain != "" {
		lines = append(lines, "toolchain "+m.Toolchain)
	}
	for _, g := range m.Godebug {
		lines = append(lines, "godebug "+g.Key+"="+g.Value)
	}
	d := slices.Clone(goDebug)
	slices.Sort(d)
	return strings.Join(append(lines, slices.Compact(d)...), "\n")
}

// goDebugLines are the //go:debug directives a git grep found (its output,
// file names left out), trimmed.
func goDebugLines(out []byte) []string {
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "//go:debug") {
			lines = append(lines, l)
		}
	}
	return lines
}

// stale reports the known differences no release matched (call it only
// once every release was checked).
func (v *verifierCheck) stale(r reporter) {
	r.Helper()
	for _, k := range v.known {
		if !v.used[k] {
			r.Errorf("testdata/verifier_differences.json: release %s, %s (tag sha256 %s, pinned %s) matches no difference any more: remove it", k.Release, k.Path, k.SHA256, k.PinnedSHA256)
		}
	}
}

// check compares release n's verifier with the pinned one.
func (v *verifierCheck) check(t *testing.T, r reporter, repo, channel string, n uint64) {
	t.Helper()
	r.Helper()
	tag := fmt.Sprintf("release/%s/%d", channel, n)
	rel := fmt.Sprintf("%s/%d", channel, n)
	differ := func(p, why string, atTag, pinned []byte) {
		h, ph := shaOf(atTag), shaOf(pinned)
		for _, k := range v.known {
			if k.Release == rel && k.Path == p && k.SHA256 == h && k.PinnedSHA256 == ph {
				v.used[k] = true
				r.Logf("release %s: %s %s: a known difference (%s)", rel, p, why, k.Reason)
				return
			}
		}
		r.Errorf("release %s: %s %s: the release's bundle verifier differs from the service's (sha256 at the tag %s, pinned %s; if it is safe, list it in testdata/verifier_differences.json with the reason)", rel, p, why, h, ph)
	}
	// How the release is built, against the service.
	if b := buildSettings(t, git(t, repo, "show", tag+":go.mod"), goDebugLines(gitGrep(t, repo, "-a", "-h", "-e", "//go:debug", tag, "--", "*.go"))); b != v.build {
		differ(buildPath, fmt.Sprintf("are %q, the service's %q", b, v.build), []byte(b), []byte(v.build))
	}
	// strictjson's old place only at a tag that doesn't have the new one.
	hasOld, hasNew := treeHas(t, repo, tag, strictjsonMove[0]), treeHas(t, repo, tag, strictjsonMove[1])
	if hasOld && hasNew {
		r.Errorf("release %s: both %s and %s are there: which one votewire uses isn't known here", rel, strictjsonMove[0], strictjsonMove[1])
		return
	}
	moved := hasOld
	norm := func(b []byte) []byte {
		if !moved {
			return b
		}
		return bytes.ReplaceAll(b, []byte(`"`+vvPrefix+strictjsonMove[0]+`"`), []byte(`"`+vvPrefix+strictjsonMove[1]+`"`))
	}
	// An import, however written (a raw string, an escape), by the place
	// the pinned module has.
	normPath := func(imp string) string {
		if moved && imp == vvPrefix+strictjsonMove[0] {
			return vvPrefix + strictjsonMove[1]
		}
		return imp
	}
	// The vettid-vault packages compared: an import of any other at the
	// tag is outside what is compared, but for notCompared's one file.
	known := map[string]bool{}
	for _, p := range v.pkgs {
		known[p.rel] = true
	}
	for _, p := range v.pkgs {
		dir := p.rel
		if moved && dir == strictjsonMove[1] {
			dir = strictjsonMove[0]
		}
		var atTag []string
		for _, e := range lsTree(t, repo, tag, dir) {
			if !entryOK(e.name, e.dir) {
				r.Errorf("release %s: %s/%s: a compared package may hold only Go files, docs and testdata", rel, p.rel, e.name)
			}
			if !e.dir && compared(e.name) {
				atTag = append(atTag, e.name)
			}
		}
		sort.Strings(atTag)
		for _, name := range atTag {
			pinned := p.rel + "/" + name
			raw := git(t, repo, "show", tag+":"+dir+"/"+name)
			imps, err := goImports(name, raw)
			if err != nil {
				r.Errorf("release %s: %s doesn't parse: %v", rel, pinned, err)
			}
			for _, imp := range imps {
				rest, vv := strings.CutPrefix(normPath(imp), vvPrefix)
				if nc, ok := notCompared[rest]; vv && !known[rest] && (!ok || nc.from != pinned) {
					r.Errorf("release %s: %s imports %s, which the pinned verifier doesn't: it isn't compared", rel, pinned, imp)
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

// goImports lists a Go file's import paths, from its syntax.
func goImports(name string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// treeEntry is a directory entry.
type treeEntry struct {
	name string
	dir  bool
}

// lsTree lists a directory's entries at a tag (git ls-tree -z).
func lsTree(t *testing.T, repo, tag, dir string) []treeEntry {
	t.Helper()
	var out []treeEntry
	for _, e := range bytes.Split(git(t, repo, "ls-tree", "-z", tag, dir+"/"), []byte{0}) {
		meta, name, ok := bytes.Cut(e, []byte{'\t'})
		if !ok {
			continue
		}
		f := strings.Fields(string(meta)) // mode type object
		out = append(out, treeEntry{name: path.Base(string(name)), dir: len(f) == 3 && f[1] == "tree"})
	}
	return out
}

func treeHas(t *testing.T, repo, tag, dir string) bool {
	t.Helper()
	return len(bytes.TrimSpace(git(t, repo, "ls-tree", tag, dir))) > 0
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

// gitGrep is git grep, whose exit status 1 (nothing found) isn't an error.
func gitGrep(t *testing.T, repo string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", repo, "grep"}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 && stderr.Len() == 0 {
		return nil
	}
	if err != nil {
		t.Fatalf("git grep %s: %v: %s", strings.Join(args, " "), err, stderr.String())
	}
	return out
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

// pinnedChecks are the checks on the pinned module itself: its compared
// packages hold only Go files, docs and testdata (entries, by package),
// and its go.mod's go version (which sets the language version the
// service builds its code with) is the service's, which every release's
// is compared with.
func pinnedChecks(r reporter, entries map[string][]treeEntry, pinnedGo, serviceGo string) {
	r.Helper()
	rels := make([]string, 0, len(entries))
	for rel := range entries {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		for _, e := range entries[rel] {
			if !entryOK(e.name, e.dir) {
				r.Errorf("the pinned vettid-vault: %s/%s: a compared package may hold only Go files, docs and testdata", rel, e.name)
			}
		}
	}
	if pinnedGo != serviceGo {
		r.Errorf("the pinned vettid-vault's go.mod says go %s, the service's go %s: its code is built at another language version than the releases'", pinnedGo, serviceGo)
	}
}

// goLine is go.mod's go version, as go mod edit reads it.
func goLine(t *testing.T, gomod []byte) string {
	t.Helper()
	first, _, _ := strings.Cut(buildSettings(t, gomod, nil), "\n")
	return strings.TrimPrefix(first, "go ")
}

// pinnedVerifier reads the compared files from the vettid-vault version
// go.mod pins: every non-test Go file of votewire and of the vettid-vault
// packages it imports (go list -deps), and runs pinnedChecks on it,
// reporting through r.
func pinnedVerifier(t *testing.T, r reporter) []verifierPkg {
	t.Helper()
	modDir := strings.TrimSpace(string(goCmd(t, "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/vettid-vault")))
	if modDir == "" {
		t.Fatal("go list -m: no directory for github.com/vettid/vettid-vault (a vendor directory, or not downloaded)")
	}
	var out []verifierPkg
	entries := map[string][]treeEntry{}
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
			entries[rel] = append(entries[rel], treeEntry{name: e.Name(), dir: e.IsDir()})
			if e.IsDir() || !compared(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
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
	pinnedMod, err := os.ReadFile(filepath.Join(modDir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	serviceMod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	pinnedChecks(r, entries, goLine(t, pinnedMod), goLine(t, serviceMod))
	return out
}

// serviceBuild is the service's buildSettings: its go.mod, and the
// //go:debug directives of its tree.
func serviceBuild(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	build := buildSettings(t, b, goDebugLines(gitGrep(t, "../..", "-a", "-h", "-e", "//go:debug", "--", "*.go")))
	if !strings.Contains(build, "\ntoolchain ") {
		t.Fatal("../../go.mod has no toolchain line")
	}
	return build
}

// TestPinnedVerifier runs the pinned module's side of the comparison
// (pinnedChecks) in every test run, from the module cache: it is the code
// the service runs.
func TestPinnedVerifier(t *testing.T) {
	pkgs := pinnedVerifier(t, t)
	if !slices.ContainsFunc(pkgs, func(p verifierPkg) bool { return p.rel == "vms/votewire" && len(p.files) >= 8 }) {
		t.Fatal("the pinned votewire is compared with fewer files than it has")
	}
	if b := serviceBuild(t); !strings.HasPrefix(b, "go ") {
		t.Fatalf("serviceBuild = %q", b)
	}
}
