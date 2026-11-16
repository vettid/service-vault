package vaultroots

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The verifier comparison against a fixture vettid-vault repo, offline.

const fixtureToolchain = "toolchain go1.26.10" // the base tree's

// baseTree is a release's tree as the pinned module has it.
func baseTree() map[string]string {
	return map[string]string{
		"go.mod":                    "module github.com/vettid/vettid-vault\n\ngo 1.26.0\n\n" + fixtureToolchain + "\n",
		"vms/votewire/bundle.go":    "package votewire\n\nimport \"github.com/vettid/vettid-vault/vms/strictjson\"\n\nfunc VerifyBundle(b []byte) error { return strictjson.Check(b) }\n",
		"vms/votewire/votewire.go":  "package votewire\n\nimport \"errors\"\n\nconst MaxBundle = 1 << 20\n\nvar ErrBody = errors.New(\"votewire: body\")\n\nvar oidSHA256 = []int{2, 16, 840}\n\nvar table = makeTable()\n\nfunc makeTable() []int { return nil }\n\ntype Info struct{ Body []byte }\n",
		"vms/votewire/body.go":      "package votewire\n\ntype Body struct{ X int }\n\nfunc parseBody(b []byte) (*Body, error) {\n\tif len(b) == 0 {\n\t\treturn nil, ErrBody\n\t}\n\treturn &Body{}, nil\n}\n",
		"vms/votewire/documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n",
		"vms/votewire/jcs.go":       "package votewire\n\nconst jcsMax = 8\n",
		"vms/strictjson/strict.go":  "package strictjson\n\nimport \"errors\"\n\nvar ErrSyntax = errors.New(\"strictjson: syntax\")\n\nfunc Check(b []byte) error { return nil }\n",
		"vms/suite/suite.go":        "package suite\n\nimport \"errors\"\n\nconst Label = \"x\"\n\nvar ErrSignature = errors.New(\"suite: signature\")\n",
		"vms/suite/rand_vectors.go": "//go:build vmsvectors\n\npackage suite\n\nimport _ \"github.com/vettid/vettid-vault/internal/hpkederand\"\n",
	}
}

// pinnedOf is the verifier the service pins, from a tree.
func pinnedOf(tree map[string]string) []verifierPkg {
	var out []verifierPkg
	for _, rel := range []string{"vms/votewire", "vms/strictjson", "vms/suite"} {
		p := verifierPkg{rel: rel, files: map[string][]byte{}}
		for f, src := range tree {
			if filepath.Dir(f) == rel && compared(filepath.Base(f)) {
				p.files[filepath.Base(f)] = []byte(src)
			}
		}
		out = append(out, p)
	}
	return out
}

// fixtureRepo makes a git repo with one commit, tagged release/staging/<n>,
// per tree.
func fixtureRepo(t *testing.T, trees map[uint64]map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
			"-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	for n := uint64(1); n <= uint64(len(trees)); n++ {
		tree, ok := trees[n]
		if !ok {
			t.Fatalf("fixture: no tree %d", n)
		}
		if n > 1 {
			run("rm", "-q", "-r", ".")
		}
		for f, src := range tree {
			p := filepath.Join(dir, filepath.FromSlash(f))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		run("add", "-A")
		run("commit", "-q", "--allow-empty", "-m", fmt.Sprint("release ", n))
		run("tag", fmt.Sprintf("release/staging/%d", n))
	}
	return dir
}

// recorder collects what the comparison reports.
type recorder struct{ errs, logs []string }

func (r *recorder) Helper() {}
func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *recorder) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}

// with returns a copy of tree with changes (an empty source removes the
// file).
func with(tree map[string]string, changes map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range tree {
		out[k] = v
	}
	for k, v := range changes {
		if v == "" {
			delete(out, k)
		} else {
			out[k] = v
		}
	}
	return out
}

// runCheck compares release 1 of a fixture holding tag (against the
// pinned base, or pinned if given) and returns what was reported, stale
// entries included.
func runCheck(t *testing.T, tag, pinned map[string]string, known []knownDifference) *recorder {
	t.Helper()
	if pinned == nil {
		pinned = baseTree()
	}
	repo := fixtureRepo(t, map[uint64]map[string]string{1: tag})
	v := &verifierCheck{pkgs: pinnedOf(pinned), build: buildSettings(t, []byte(pinned["go.mod"]), nil), known: known, used: map[knownDifference]bool{}}
	r := &recorder{}
	v.check(t, r, repo, "staging", 1)
	v.stale(r)
	return r
}

func wantErr(t *testing.T, r *recorder, parts ...string) {
	t.Helper()
	for _, e := range r.errs {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(e, p)
		}
		if ok {
			return
		}
	}
	t.Fatalf("no error with %q among %q", parts, r.errs)
}

func wantClean(t *testing.T, r *recorder) {
	t.Helper()
	if len(r.errs) != 0 {
		t.Fatalf("errors: %q", r.errs)
	}
}

const changedBundle = "package votewire\n\nimport \"github.com/vettid/vettid-vault/vms/strictjson\"\n\nfunc VerifyBundle(b []byte) error { _ = 1; return strictjson.Check(b) }\n"

// Every non-test Go file of votewire is compared, its message bodies,
// documents and JCS included.
func TestVerifierAllOfVotewire(t *testing.T) {
	for _, f := range []string{"body.go", "documents.go", "jcs.go"} {
		r := runCheck(t, with(baseTree(), map[string]string{"vms/votewire/" + f: baseTree()["vms/votewire/"+f] + "\nvar extra = 1\n"}), nil, nil)
		wantErr(t, r, "release staging/1", "vms/votewire/"+f+" differs")
	}
}

func TestVerifierSame(t *testing.T) {
	wantClean(t, runCheck(t, baseTree(), nil, nil))
}

func TestVerifierNewDifference(t *testing.T) {
	r := runCheck(t, with(baseTree(), map[string]string{"vms/votewire/bundle.go": changedBundle}), nil, nil)
	wantErr(t, r, "release staging/1", "vms/votewire/bundle.go differs")
	// A file only one side has.
	r = runCheck(t, with(baseTree(), map[string]string{"vms/votewire/extra.go": "package votewire\n"}), nil, nil)
	wantErr(t, r, "release staging/1", "vms/votewire/extra.go is at the tag but not in the pinned vettid-vault")
	r = runCheck(t, with(baseTree(), map[string]string{"vms/suite/suite.go": ""}), nil, nil)
	wantErr(t, r, "release staging/1", "vms/suite/suite.go is in the pinned vettid-vault but not at the tag")
}

// Test files aren't compared.
func TestVerifierTestFilesNotCompared(t *testing.T) {
	wantClean(t, runCheck(t, with(baseTree(), map[string]string{"vms/votewire/bundle_test.go": "package votewire\n\nvar changed = 1\n"}), nil, nil))
}

func known(path, atTag, pinned string) knownDifference {
	return knownDifference{Release: "staging/1", Path: path, SHA256: shaOf([]byte(atTag)), PinnedSHA256: shaOf([]byte(pinned)), Reason: "reviewed"}
}

func TestVerifierKnownDifference(t *testing.T) {
	base := baseTree()
	k := known("vms/votewire/bundle.go", changedBundle, base["vms/votewire/bundle.go"])
	wantClean(t, runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": changedBundle}), nil, []knownDifference{k}))
}

// An entry matches only its release and path, whatever the hashes.
func TestVerifierKnownDifferenceOtherReleaseOrPath(t *testing.T) {
	base := baseTree()
	tag := with(base, map[string]string{"vms/votewire/bundle.go": changedBundle})
	k := known("vms/votewire/bundle.go", changedBundle, base["vms/votewire/bundle.go"])
	other := k
	other.Release = "staging/2"
	r := runCheck(t, tag, nil, []knownDifference{other})
	wantErr(t, r, "vms/votewire/bundle.go differs")
	wantErr(t, r, "release staging/2, vms/votewire/bundle.go", "matches no difference any more")
	other = k
	other.Path = "vms/votewire/votewire.go"
	r = runCheck(t, tag, nil, []knownDifference{other})
	wantErr(t, r, "vms/votewire/bundle.go differs")
	wantErr(t, r, "release staging/1, vms/votewire/votewire.go", "matches no difference any more")
}

func TestVerifierKnownDifferenceShaChanged(t *testing.T) {
	base := baseTree()
	k := known("vms/votewire/bundle.go", changedBundle, base["vms/votewire/bundle.go"])
	// The tag's side changed again since the review.
	again := strings.Replace(changedBundle, "_ = 1", "_ = 2", 1)
	r := runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": again}), nil, []knownDifference{k})
	wantErr(t, r, "vms/votewire/bundle.go differs")
	wantErr(t, r, "matches no difference any more")
	// The pinned side changed since the review.
	pinned := with(base, map[string]string{"vms/votewire/bundle.go": strings.Replace(base["vms/votewire/bundle.go"], "b []byte", "in []byte", 1)})
	pinned["vms/votewire/bundle.go"] = strings.Replace(pinned["vms/votewire/bundle.go"], "Check(b)", "Check(in)", 1)
	r = runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": changedBundle}), pinned, []knownDifference{k})
	wantErr(t, r, "vms/votewire/bundle.go differs")
}

func TestVerifierStaleEntry(t *testing.T) {
	base := baseTree()
	k := known("vms/votewire/bundle.go", changedBundle, base["vms/votewire/bundle.go"])
	wantErr(t, runCheck(t, base, nil, []knownDifference{k}), "release staging/1, vms/votewire/bundle.go", "matches no difference any more")
}

func TestVerifierStrictjsonPlaces(t *testing.T) {
	base := baseTree()
	both := with(base, map[string]string{"internal/strictjson/strict.go": base["vms/strictjson/strict.go"]})
	wantErr(t, runCheck(t, both, nil, nil), "release staging/1: both internal/strictjson and vms/strictjson are there")
	// The old place alone: compared as the new one, its import undone.
	old := with(base, map[string]string{
		"vms/strictjson/strict.go":      "",
		"internal/strictjson/strict.go": base["vms/strictjson/strict.go"],
		"vms/votewire/bundle.go":        strings.Replace(base["vms/votewire/bundle.go"], "vms/strictjson", "internal/strictjson", 1),
	})
	wantClean(t, runCheck(t, old, nil, nil))
	// Only the import is undone: the same quoted path elsewhere in the file
	// (here a string constant) is compared as it is.
	const lit = "\nconst src = \"github.com/vettid/vettid-vault/vms/strictjson\"\n"
	pinned := with(base, map[string]string{"vms/votewire/bundle.go": base["vms/votewire/bundle.go"] + lit})
	oldLit := with(old, map[string]string{"vms/votewire/bundle.go": old["vms/votewire/bundle.go"] + strings.Replace(lit, "vms/strictjson", "internal/strictjson", 1)})
	wantErr(t, runCheck(t, oldLit, pinned, nil), "vms/votewire/bundle.go differs")
	wantClean(t, runCheck(t, with(old, map[string]string{"vms/votewire/bundle.go": old["vms/votewire/bundle.go"] + lit}), pinned, nil))
	// A grouped, named import is undone too.
	const grouped = "package votewire\n\nimport (\n\t\"errors\"\n\tsj \"github.com/vettid/vettid-vault/vms/strictjson\"\n)\n\nvar errX = errors.New(\"x\")\n\nfunc VerifyBundle(b []byte) error { return sj.Check(b) }\n"
	pinnedGrouped := with(base, map[string]string{"vms/votewire/bundle.go": grouped})
	wantClean(t, runCheck(t, with(old, map[string]string{"vms/votewire/bundle.go": strings.Replace(grouped, "vms/strictjson", "internal/strictjson", 1)}), pinnedGrouped, nil))
}

// Each pinned bundle.go below is compared with the same file whose every
// "vms/strictjson" reads "internal/strictjson", at a tag with strictjson
// in its old place: it compares equal only if each one is an import path.
func TestVerifierMoveImportOnlyImports(t *testing.T) {
	base := baseTree()
	const body = `
func VerifyBundle(b []byte) error { return strictjson.Check(b) }
`
	for name, c := range map[string]struct {
		pinned string
		want   []string // nil: compares equal
	}{
		"a comment above the import": {`package votewire

// "github.com/vettid/vettid-vault/vms/strictjson"
import "github.com/vettid/vettid-vault/vms/strictjson"
` + body, []string{"bundle.go differs"}},
		"a comment inside the import block": {`package votewire

import (
	// "github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/strictjson"
)
` + body, []string{"bundle.go differs"}},
		"a comment after the imports": {`package votewire

import "github.com/vettid/vettid-vault/vms/strictjson"

// "github.com/vettid/vettid-vault/vms/strictjson"
` + body, []string{"bundle.go differs"}},
		"two import declarations": {`package votewire

import "errors"
import "github.com/vettid/vettid-vault/vms/strictjson"

var errX = errors.New("x")
` + body, nil},
		"the same path twice": {`package votewire

import (
	"github.com/vettid/vettid-vault/vms/strictjson"
	sj "github.com/vettid/vettid-vault/vms/strictjson"
)

var _ = sj.Check
` + body, nil},
		"a file that doesn't parse": {`package votewire

import "github.com/vettid/vettid-vault/vms/strictjson"
import (
`, []string{"vms/votewire/bundle.go doesn't parse", "bundle.go differs"}},
	} {
		t.Run(name, func(t *testing.T) {
			tag := with(base, map[string]string{
				"vms/strictjson/strict.go":      "",
				"internal/strictjson/strict.go": base["vms/strictjson/strict.go"],
				"vms/votewire/bundle.go":        strings.ReplaceAll(c.pinned, "vms/strictjson", "internal/strictjson"),
			})
			r := runCheck(t, tag, with(base, map[string]string{"vms/votewire/bundle.go": c.pinned}), nil)
			if c.want == nil {
				wantClean(t, r)
				return
			}
			for _, w := range c.want {
				wantErr(t, r, w)
			}
		})
	}
}

func TestVerifierBuildSettings(t *testing.T) {
	base := baseTree()
	if got := buildSettings(t, []byte(base["go.mod"]), nil); got != "go 1.26.0\n"+fixtureToolchain {
		t.Fatalf("buildSettings = %q", got)
	}
	for name, c := range map[string]struct {
		tree map[string]string
		want string
	}{
		"another toolchain":             {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go1.26.10", "go1.26.9", 1)}), "toolchain go1.26.9"},
		"no toolchain":                  {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain+"\n", "", 1)}), `are "go 1.26.0"`},
		"another go":                    {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go 1.26.0", "go 1.25.0", 1)}), "go 1.25.0"},
		"a godebug line":                {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug x509negativeserial=1\n"}), "godebug x509negativeserial=1"},
		"a godebug block":               {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug (\n\tasn1allowinvalid=1 // a comment\n)\n"}), "godebug asn1allowinvalid=1"},
		"godebug( unspaced":             {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug(\n\tx509sha1=1\n)\n"}), "godebug x509sha1=1"},
		"a //go:debug in a binary file": {with(base, map[string]string{".gitattributes": "cmd/*.go binary\n", "cmd/main.go": "//go:debug x509negativeserial=1\n\npackage main\n\nfunc main() {}\n"}), "//go:debug x509negativeserial=1"},
		"a //go:debug":                  {with(base, map[string]string{"cmd/main.go": "//go:debug x509negativeserial=1\n\npackage main\n\nfunc main() {}\n"}), "//go:debug x509negativeserial=1"},
	} {
		r := runCheck(t, c.tree, nil, nil)
		if !slices.ContainsFunc(r.errs, func(e string) bool {
			return strings.Contains(e, "build settings") && strings.Contains(e, c.want)
		}) {
			t.Errorf("%s: no build settings error with %q among %q", name, c.want, r.errs)
		}
	}
	// Comments and spacing alone change nothing.
	spaced := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain, "toolchain   go1.26.10 // pinned", 1)})
	wantClean(t, runCheck(t, spaced, nil, nil))
	other := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go1.26.10", "go1.26.9", 1)})
	k := knownDifference{Release: "staging/1", Path: buildPath, SHA256: shaOf([]byte("go 1.26.0\ntoolchain go1.26.9")), PinnedSHA256: shaOf([]byte("go 1.26.0\n" + fixtureToolchain)), Reason: "reviewed"}
	wantClean(t, runCheck(t, other, nil, []knownDifference{k}))
}

func TestVerifierHpkederandOnlyFromRandVectors(t *testing.T) {
	base := baseTree()
	wantClean(t, runCheck(t, base, nil, nil))
	r := runCheck(t, with(base, map[string]string{"vms/suite/suite.go": "package suite\n\nimport (\n\t\"errors\"\n\n\t_ \"github.com/vettid/vettid-vault/internal/hpkederand\"\n)\n\nconst Label = \"x\"\n\nvar ErrSignature = errors.New(\"suite: signature\")\n"}), nil, nil)
	wantErr(t, r, "vms/suite/suite.go imports github.com/vettid/vettid-vault/internal/hpkederand")
	r = runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": "package votewire\n\nimport _ \"github.com/vettid/vettid-vault/internal/other\"\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}), nil, nil)
	wantErr(t, r, "vms/votewire/bundle.go imports github.com/vettid/vettid-vault/internal/other")
	// A raw string import path is an import too.
	r = runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": "package votewire\n\nimport _ `github.com/vettid/vettid-vault/internal/other`\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}), nil, nil)
	wantErr(t, r, "vms/votewire/bundle.go imports github.com/vettid/vettid-vault/internal/other")
}

// File names git would quote are read whole (ls-tree -z): a space, a
// non-ASCII letter, a quote.
func TestVerifierFileNameWithSpace(t *testing.T) {
	for _, name := range []string{"odd name.go", "été.go", "a\"b.go"} {
		r := runCheck(t, with(baseTree(), map[string]string{"vms/votewire/" + name: "package votewire\n"}), nil, nil)
		wantErr(t, r, "vms/votewire/"+name+" is at the tag but not in the pinned vettid-vault")
	}
}

// A compared package holds only Go files, docs and testdata.
func TestVerifierNonGoFiles(t *testing.T) {
	for _, f := range []string{"vms/suite/asm_amd64.s", "vms/votewire/blob.syso", "vms/strictjson/table.bin"} {
		wantErr(t, runCheck(t, with(baseTree(), map[string]string{f: "x\n"}), nil, nil), "release staging/1: "+f+": a compared package may hold only Go files, docs and testdata")
	}
	wantClean(t, runCheck(t, with(baseTree(), map[string]string{"vms/suite/README.md": "doc\n", "vms/suite/testdata/v.json": "{}\n"}), nil, nil))
	wantErr(t, runCheck(t, with(baseTree(), map[string]string{"vms/suite/vectors/v.json": "{}\n"}), nil, nil), "vms/suite/vectors: a compared package may hold only")
}

// The reviewed differences file parses, every entry complete, and a
// malformed one is refused.
func TestKnownDifferencesFile(t *testing.T) {
	b, err := os.ReadFile("testdata/verifier_differences.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKnownDifferences(b); err != nil {
		t.Fatalf("testdata/verifier_differences.json: %v", err)
	}
	ok := `[{"release":"staging/1","path":"p","sha256":"` + shaOf(nil) + `","pinned_sha256":"` + shaOf(nil) + `","reason":"r"}]`
	if _, err := parseKnownDifferences([]byte(ok)); err != nil {
		t.Fatalf("a complete entry: %v", err)
	}
	for name, bad := range map[string]string{
		"an unknown field":  strings.Replace(ok, `"reason"`, `"extra":1,"reason"`, 1),
		"no reason":         strings.Replace(ok, `"reason":"r"`, `"reason":" "`, 1),
		"a short sha":       strings.Replace(ok, `"sha256":"`+shaOf(nil), `"sha256":"abc`, 1),
		"an upper-case sha": strings.Replace(ok, `"sha256":"`+shaOf(nil), `"sha256":"`+strings.ToUpper(shaOf(nil)), 1),
		"data after":        ok + "[]",
	} {
		if _, err := parseKnownDifferences([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// strictjson's old place imported however it is written (a raw string, an
// escape) is the compared package, not an outside import.
func TestVerifierOldStrictjsonImportForms(t *testing.T) {
	base := baseTree()
	for _, form := range []string{"`github.com/vettid/vettid-vault/internal/strictjson`", "\"github.com/vettid/vettid-vault/internal/strict\\x6Ason\""} {
		old := with(base, map[string]string{
			"vms/strictjson/strict.go":      "",
			"internal/strictjson/strict.go": base["vms/strictjson/strict.go"],
			"vms/votewire/bundle.go":        strings.Replace(base["vms/votewire/bundle.go"], "\"github.com/vettid/vettid-vault/vms/strictjson\"", form, 1),
		})
		r := runCheck(t, old, nil, nil)
		wantErr(t, r, "vms/votewire/bundle.go differs") // the bytes differ: a reviewed difference at most
		if slices.ContainsFunc(r.errs, func(e string) bool { return strings.Contains(e, "which the pinned verifier doesn't") }) {
			t.Fatalf("%s: the old place's import counted as an outside one: %q", form, r.errs)
		}
	}
}

// The pinned module's own checks: only Go files, docs and testdata in its
// compared packages, and its go version the service's.
func TestPinnedChecks(t *testing.T) {
	ok := map[string][]treeEntry{"vms/votewire": {{name: "bundle.go"}, {name: "README.md"}, {name: "testdata", dir: true}}}
	r := &recorder{}
	pinnedChecks(r, ok, "1.26.0", "1.26.0")
	wantClean(t, r)
	r = &recorder{}
	pinnedChecks(r, map[string][]treeEntry{"vms/suite": {{name: "asm.s"}}, "vms/votewire": {{name: "vectors", dir: true}}}, "1.26.0", "1.26.0")
	wantErr(t, r, "the pinned vettid-vault: vms/suite/asm.s: a compared package may hold only")
	wantErr(t, r, "the pinned vettid-vault: vms/votewire/vectors: a compared package may hold only")
	r = &recorder{}
	pinnedChecks(r, ok, "1.25.0", "1.26.0")
	wantErr(t, r, "the pinned vettid-vault's go.mod says go 1.25.0, the service's go 1.26.0")
}
