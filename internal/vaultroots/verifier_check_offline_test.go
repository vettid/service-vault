package vaultroots

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The verifier comparison against a fixture vettid-vault repo, offline.

const fixtureToolchain = "toolchain go1.26.10"

// baseTree is a release's tree as the pinned module has it.
func baseTree() map[string]string {
	return map[string]string{
		"go.mod":                    "module github.com/vettid/vettid-vault\n\ngo 1.26.0\n\n" + fixtureToolchain + "\n",
		"vms/votewire/bundle.go":    "package votewire\n\nimport \"github.com/vettid/vettid-vault/vms/strictjson\"\n\nfunc VerifyBundle(b []byte) error { return strictjson.Check(b) }\n",
		"vms/votewire/votewire.go":  "package votewire\n\nconst MaxBundle = 1 << 20\n\ntype Info struct{ Body []byte }\n",
		"vms/votewire/body.go":      "package votewire\n\ntype Body struct{ X int }\n",
		"vms/votewire/documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n",
		"vms/votewire/jcs.go":       "package votewire\n\nconst jcsMax = 8\n",
		"vms/strictjson/strict.go":  "package strictjson\n\nfunc Check(b []byte) error { return nil }\n",
		"vms/suite/suite.go":        "package suite\n\nconst Label = \"x\"\n",
		"vms/suite/rand_vectors.go": "//go:build vmsvectors\n\npackage suite\n\nimport _ \"github.com/vettid/vettid-vault/internal/hpkederand\"\n",
	}
}

// pinnedOf is the verifier the service pins, from a tree.
func pinnedOf(tree map[string]string) []verifierPkg {
	var out []verifierPkg
	for _, rel := range []string{"vms/votewire", "vms/strictjson", "vms/suite"} {
		p := verifierPkg{rel: rel, files: map[string][]byte{}}
		for f, src := range tree {
			if filepath.Dir(f) == rel && compared(rel, filepath.Base(f)) {
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

// run compares release 1 of a fixture holding tag (against the pinned
// base, or pinned if given) and returns what was reported, stale entries
// included.
func runCheck(t *testing.T, tag, pinned map[string]string, known []knownDifference) *recorder {
	t.Helper()
	if pinned == nil {
		pinned = baseTree()
	}
	repo := fixtureRepo(t, map[uint64]map[string]string{1: tag})
	v := &verifierCheck{pkgs: pinnedOf(pinned), toolchain: fixtureToolchain, known: known, used: map[knownDifference]bool{}}
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

func known(path, atTag, pinned string) knownDifference {
	return knownDifference{Release: "staging/1", Path: path, SHA256: shaOf([]byte(atTag)), PinnedSHA256: shaOf([]byte(pinned)), Reason: "reviewed"}
}

func TestVerifierKnownDifference(t *testing.T) {
	base := baseTree()
	k := known("vms/votewire/bundle.go", changedBundle, base["vms/votewire/bundle.go"])
	wantClean(t, runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": changedBundle}), nil, []knownDifference{k}))
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
}

func TestVerifierToolchain(t *testing.T) {
	base := baseTree()
	other := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go1.26.10", "go1.26.9", 1)})
	wantErr(t, runCheck(t, other, nil, nil), "release staging/1", "go.mod toolchain is \"toolchain go1.26.9\"")
	none := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain+"\n", "", 1)})
	wantErr(t, runCheck(t, none, nil, nil), "go.mod toolchain is \"\"")
	k := knownDifference{Release: "staging/1", Path: toolchainPath, SHA256: shaOf([]byte("toolchain go1.26.9")), PinnedSHA256: shaOf([]byte(fixtureToolchain)), Reason: "reviewed"}
	wantClean(t, runCheck(t, other, nil, []knownDifference{k}))
}

func TestVerifierHpkederandOnlyFromRandVectors(t *testing.T) {
	base := baseTree()
	wantClean(t, runCheck(t, base, nil, nil))
	r := runCheck(t, with(base, map[string]string{"vms/suite/suite.go": "package suite\n\nimport _ \"github.com/vettid/vettid-vault/internal/hpkederand\"\n\nconst Label = \"x\"\n"}), nil, nil)
	wantErr(t, r, "vms/suite/suite.go imports github.com/vettid/vettid-vault/internal/hpkederand")
	r = runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": "package votewire\n\nimport _ \"github.com/vettid/vettid-vault/internal/other\"\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}), nil, nil)
	wantErr(t, r, "vms/votewire/bundle.go imports github.com/vettid/vettid-vault/internal/other")
}

// A file name with a space is read whole (ls-tree -z).
func TestVerifierFileNameWithSpace(t *testing.T) {
	r := runCheck(t, with(baseTree(), map[string]string{"vms/votewire/odd name.go": "package votewire\n"}), nil, nil)
	wantErr(t, r, "vms/votewire/odd name.go is at the tag but not in the pinned vettid-vault")
}

func TestVerifierExcludedReachAtTag(t *testing.T) {
	base := baseTree()
	r := runCheck(t, with(base, map[string]string{"vms/votewire/votewire.go": "package votewire\n\nconst MaxBundle = 1 << 20\n\ntype Info struct{ Body []byte }\n\nvar n = docHelper()\n"}), nil, nil)
	wantErr(t, r, "release staging/1: vms/votewire: votewire.go uses docHelper, declared in documents.go")
}

// excludedReach on its own: each way in, and the look-alikes that aren't.
func TestExcludedReach(t *testing.T) {
	base := map[string][]byte{}
	for f, src := range baseTree() {
		if filepath.Dir(f) == "vms/votewire" {
			base[filepath.Base(f)] = []byte(src)
		}
	}
	set := func(changes map[string]string) map[string][]byte {
		out := map[string][]byte{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range changes {
			out[k] = []byte(v)
		}
		return out
	}
	if p := excludedReach(base); len(p) != 0 {
		t.Fatalf("the base: %q", p)
	}
	for name, c := range map[string]struct {
		changes map[string]string
		want    string
	}{
		"a function":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = docHelper(); return nil }\n"}, "bundle.go uses docHelper, declared in documents.go"},
		"a variable":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = docSchema; return nil }\n"}, "bundle.go uses docSchema, declared in documents.go"},
		"a type":                      {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { var x Body; _ = x; return nil }\n"}, "bundle.go uses Body, declared in body.go"},
		"a constant":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = jcsMax; return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go"},
		"an init":                     {map[string]string{"body.go": "package votewire\n\ntype Body struct{ X int }\n\nfunc init() {}\n"}, "body.go has an init"},
		"a call in a variable":        {map[string]string{"jcs.go": "package votewire\n\nconst jcsMax = 8\n\nvar _ = setUp()\n\nfunc setUp() int { return 0 }\n"}, "jcs.go: the package-level variable _'s initializer calls something"},
		"a method on a compared type": {map[string]string{"documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n\nfunc (i *Info) Check() error { return nil }\n"}, "documents.go declares the method Info.Check on a compared file's type"},
		"a parse error":               {map[string]string{"body.go": "package votewire\n\nfunc {\n"}, "body.go doesn't parse"},
	} {
		if p := excludedReach(set(c.changes)); !strings.Contains(strings.Join(p, "\n"), c.want) {
			t.Errorf("%s: %q, want %q", name, p, c.want)
		}
	}
	// Look-alikes: a struct field, a composite literal key, a local, a
	// selector, all named like an excluded file's declarations.
	alike := set(map[string]string{"bundle.go": `package votewire

type Out struct{ Body []byte; docHelper int }

func VerifyBundle(b []byte) error {
	docSchema := 1
	_ = docSchema
	o := Out{Body: b, docHelper: 2}
	_ = o.Body
	return nil
}
`})
	if p := excludedReach(alike); len(p) != 0 {
		t.Fatalf("look-alikes reported: %q", p)
	}
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
