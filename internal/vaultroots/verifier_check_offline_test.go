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

const fixtureToolchain = "toolchain go1.26.10" // the base tree's

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
	v := &verifierCheck{pkgs: pinnedOf(pinned), build: buildLines([]byte(pinned["go.mod"])), known: known, used: map[knownDifference]bool{}}
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

func TestVerifierBuildSettings(t *testing.T) {
	base := baseTree()
	pinnedBuild := "go 1.26.0\n" + fixtureToolchain
	if got := buildLines([]byte(base["go.mod"])); got != pinnedBuild {
		t.Fatalf("buildLines = %q", got)
	}
	other := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go1.26.10", "go1.26.9", 1)})
	wantErr(t, runCheck(t, other, nil, nil), "release staging/1", "go.mod go/toolchain/godebug are \"go 1.26.0\\ntoolchain go1.26.9\"")
	none := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain+"\n", "", 1)})
	wantErr(t, runCheck(t, none, nil, nil), "go.mod go/toolchain/godebug are \"go 1.26.0\"")
	goLine := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go 1.26.0", "go 1.25.0", 1)})
	wantErr(t, runCheck(t, goLine, nil, nil), "go.mod go/toolchain/godebug")
	godebug := with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug x509negativeserial=1\n"})
	wantErr(t, runCheck(t, godebug, nil, nil), "godebug x509negativeserial=1")
	block := with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug (\n\tasn1allowinvalid=1 // a comment\n)\n"})
	wantErr(t, runCheck(t, block, nil, nil), "godebug asn1allowinvalid=1")
	// Comments and spacing alone change nothing.
	spaced := with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain, "toolchain   go1.26.10 // pinned", 1)})
	wantClean(t, runCheck(t, spaced, nil, nil))
	k := knownDifference{Release: "staging/1", Path: buildPath, SHA256: shaOf([]byte("go 1.26.0\ntoolchain go1.26.9")), PinnedSHA256: shaOf([]byte(pinnedBuild)), Reason: "reviewed"}
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

// File names git would quote are read whole (ls-tree -z): a space, a
// non-ASCII letter, a quote.
func TestVerifierFileNameWithSpace(t *testing.T) {
	for _, name := range []string{"odd name.go", "\u00e9t\u00e9.go", "a\"b.go"} {
		r := runCheck(t, with(baseTree(), map[string]string{"vms/votewire/" + name: "package votewire\n"}), nil, nil)
		wantErr(t, r, "vms/votewire/"+name+" is at the tag but not in the pinned vettid-vault")
	}
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
	vvOK := func(imp string) bool {
		rest, vv := strings.CutPrefix(imp, vvPrefix)
		return !vv || rest == "vms/strictjson" || rest == "vms/suite"
	}
	if p := excludedReach(base, vvOK); len(p) != 0 {
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
		"a method on a compared type": {map[string]string{"documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n\nfunc (i *Info) Check() error { return nil }\n"}, "documents.go declares the method Info.Check on a type the files not compared don't define"},
		"a method on an alias of a compared type": {map[string]string{"body.go": "package votewire\n\ntype Body struct{ X int }\n\ntype info = Info\n\nfunc (i *info) UnmarshalJSON(b []byte) error { return nil }\n"}, "body.go declares the method info.UnmarshalJSON on a type the files not compared don't define"},
		"cgo":                                {map[string]string{"jcs.go": "package votewire\n\nimport \"C\"\n\nconst jcsMax = 8\n"}, "jcs.go imports C"},
		"unsafe":                             {map[string]string{"jcs.go": "package votewire\n\nimport \"unsafe\"\n\nconst jcsMax = 8\n\nvar _ = unsafe.Sizeof(0)\n"}, "jcs.go imports unsafe"},
		"a blank import":                     {map[string]string{"jcs.go": "package votewire\n\nimport _ \"embed\"\n\nconst jcsMax = 8\n"}, "jcs.go has a _ import of embed"},
		"a dot import":                       {map[string]string{"jcs.go": "package votewire\n\nimport . \"strings\"\n\nconst jcsMax = 8\n\nvar _ = ToUpper\n"}, "jcs.go has a . import of strings"},
		"an uncompared vettid-vault package": {map[string]string{"body.go": "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/evil\"\n\ntype Body struct{ X int }\n\nvar _ = evil.X\n"}, "body.go imports github.com/vettid/vettid-vault/internal/evil, which isn't compared"},
		"a key":                              {map[string]string{"bundle.go": "package votewire\n\nvar limits = map[int]bool{jcsMax: true}\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go, as a key"},
		"a parse error":                      {map[string]string{"body.go": "package votewire\n\nfunc {\n"}, "body.go doesn't parse"},
	} {
		if p := excludedReach(set(c.changes), vvOK); !strings.Contains(strings.Join(p, "\n"), c.want) {
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
	if p := excludedReach(alike, vvOK); len(p) != 0 {
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

// What the files not compared may do: import the standard library, a
// compared vettid-vault package or another module, and declare methods on
// their own types.
func TestExcludedReachAllowed(t *testing.T) {
	src := map[string][]byte{
		"bundle.go":    []byte("package votewire\n\nfunc VerifyBundle(b []byte) error { return nil }\n"),
		"body.go":      []byte("package votewire\n\nimport (\n\t\"encoding/json\"\n\n\t\"github.com/vettid/vettid-vault/vms/strictjson\"\n)\n\ntype Body struct{ X int }\n\nfunc (b *Body) UnmarshalJSON(p []byte) error { _ = strictjson.Check; return json.Unmarshal(p, new(int)) }\n"),
		"documents.go": []byte("package votewire\n\nimport \"golang.org/x/text/unicode/norm\"\n\nvar _ = norm.NFC\n"),
	}
	ok := func(imp string) bool {
		rest, vv := strings.CutPrefix(imp, vvPrefix)
		return !vv || rest == "vms/strictjson"
	}
	if p := excludedReach(src, ok); len(p) != 0 {
		t.Fatalf("reported: %q", p)
	}
}

// A release's files not compared import a vettid-vault package by its old
// strictjson place: compared, after the move is undone.
func TestVerifierExcludedImportOldStrictjson(t *testing.T) {
	base := baseTree()
	old := with(base, map[string]string{
		"vms/strictjson/strict.go":      "",
		"internal/strictjson/strict.go": base["vms/strictjson/strict.go"],
		"vms/votewire/bundle.go":        strings.Replace(base["vms/votewire/bundle.go"], "vms/strictjson", "internal/strictjson", 1),
		"vms/votewire/body.go":          "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/strictjson\"\n\ntype Body struct{ X int }\n\nvar _ = strictjson.Check\n",
	})
	wantClean(t, runCheck(t, old, nil, nil))
	evil := with(base, map[string]string{"vms/votewire/body.go": "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/evil\"\n\ntype Body struct{ X int }\n\nvar _ = evil.X\n"})
	wantErr(t, runCheck(t, evil, nil, nil), "release staging/1: vms/votewire: body.go imports github.com/vettid/vettid-vault/internal/evil, which isn't compared")
}
