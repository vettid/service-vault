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

// The list of files not compared is a reviewed decision: a change to it
// shows here.
func TestVotewireNotVerifierList(t *testing.T) {
	if want := []string{"body.go", "documents.go", "jcs.go"}; !slices.Equal(votewireNotVerifier, want) {
		t.Fatalf("votewireNotVerifier = %q, want %q", votewireNotVerifier, want)
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
		"another toolchain": {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go1.26.10", "go1.26.9", 1)}), "toolchain go1.26.9"},
		"no toolchain":      {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], fixtureToolchain+"\n", "", 1)}), `are "go 1.26.0"`},
		"another go":        {with(base, map[string]string{"go.mod": strings.Replace(base["go.mod"], "go 1.26.0", "go 1.25.0", 1)}), "go 1.25.0"},
		"a godebug line":    {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug x509negativeserial=1\n"}), "godebug x509negativeserial=1"},
		"a godebug block":   {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug (\n\tasn1allowinvalid=1 // a comment\n)\n"}), "godebug asn1allowinvalid=1"},
		"godebug( unspaced": {with(base, map[string]string{"go.mod": base["go.mod"] + "\ngodebug(\n\tx509sha1=1\n)\n"}), "godebug x509sha1=1"},
		"a //go:debug":      {with(base, map[string]string{"cmd/main.go": "//go:debug x509negativeserial=1\n\npackage main\n\nfunc main() {}\n"}), "//go:debug x509negativeserial=1"},
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

func TestVerifierExcludedReachAtTag(t *testing.T) {
	base := baseTree()
	r := runCheck(t, with(base, map[string]string{"vms/votewire/bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = docHelper(); return nil }\n"}), nil, nil)
	wantErr(t, r, "release staging/1: vms/votewire: bundle.go uses docHelper, declared in documents.go")
	r = runCheck(t, with(base, map[string]string{"vms/votewire/jcs.go": "package votewire\n\nimport \"github.com/vettid/vettid-vault/vms/suite\"\n\nconst jcsMax = 8\n\nfunc reset() { suite.ErrSignature = nil }\n"}), nil, nil)
	wantErr(t, r, "release staging/1: vms/votewire: jcs.go mentions suite.ErrSignature other than as a plain read")
}

// reach runs excludedReach on the base votewire files with changes, with
// the base strictjson and suite as the other compared packages.
func reach(changes map[string]string) []string {
	sources := map[string]map[string][]byte{}
	for f, src := range baseTree() {
		dir := filepath.Dir(f)
		if !strings.HasPrefix(dir, "vms/") {
			continue
		}
		if sources[dir] == nil {
			sources[dir] = map[string][]byte{}
		}
		sources[dir][filepath.Base(f)] = []byte(src)
	}
	for k, v := range changes {
		sources["vms/votewire"][k] = []byte(v)
	}
	ok := func(imp string) bool {
		rest, vv := strings.CutPrefix(imp, vvPrefix)
		return !vv || rest == "vms/strictjson" || rest == "vms/suite"
	}
	return excludedReach(sources["vms/votewire"], ok, comparedVars(sources))
}

// excludedReach on its own: each way in, and the look-alikes that aren't.
func TestExcludedReach(t *testing.T) {
	if p := reach(nil); len(p) != 0 {
		t.Fatalf("the base: %q", p)
	}
	const body = "package votewire\n\nimport (\n\t\"github.com/vettid/vettid-vault/vms/strictjson\"\n\t\"github.com/vettid/vettid-vault/vms/suite\"\n)\n\ntype Body struct{ X int }\n\nvar _, _ = strictjson.Check, suite.Label\n\n"
	for name, c := range map[string]struct {
		changes map[string]string
		want    string
	}{
		"a function":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = docHelper(); return nil }\n"}, "bundle.go uses docHelper, declared in documents.go"},
		"a variable":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = docSchema; return nil }\n"}, "bundle.go uses docSchema, declared in documents.go"},
		"a type":                      {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { var x Body; _ = x; return nil }\n"}, "bundle.go uses Body, declared in body.go"},
		"an embedded type":            {map[string]string{"bundle.go": "package votewire\n\ntype Out struct{ Body }\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}, "bundle.go uses Body, declared in body.go"},
		"a constant":                  {map[string]string{"bundle.go": "package votewire\n\nfunc VerifyBundle(b []byte) error { _ = jcsMax; return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go"},
		"an init":                     {map[string]string{"body.go": "package votewire\n\ntype Body struct{ X int }\n\nfunc init() {}\n"}, "body.go has an init"},
		"a call in a variable":        {map[string]string{"jcs.go": "package votewire\n\nconst jcsMax = 8\n\nvar _ = setUp()\n\nfunc setUp() int { return 0 }\n"}, "jcs.go: the package-level variable _'s initializer calls something"},
		"a nested call in a variable": {map[string]string{"jcs.go": "package votewire\n\nconst jcsMax = 8\n\nvar xs = []int{setUp()}\n\nfunc setUp() int { return 0 }\n"}, "jcs.go: the package-level variable xs's initializer calls something"},
		"a method on a compared type": {map[string]string{"documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n\nfunc (i *Info) Check() error { return nil }\n"}, "documents.go declares the method Info.Check on a type the files not compared don't define"},
		"a method on an alias of a compared type": {map[string]string{"body.go": "package votewire\n\ntype Body struct{ X int }\n\ntype info = Info\n\nfunc (i *info) UnmarshalJSON(b []byte) error { return nil }\n"}, "body.go declares the method info.UnmarshalJSON on a type the files not compared don't define"},
		"a method on a compared generic type":     {map[string]string{"bundle.go": "package votewire\n\ntype Box[T any] struct{ v T }\n\nfunc VerifyBundle(b []byte) error { return nil }\n", "body.go": "package votewire\n\ntype Body struct{ X int }\n\nfunc (b *Box[T]) Set(v T) { b.v = v }\n"}, "body.go declares the method Box.Set on a type the files not compared don't define"},
		"cgo":                                     {map[string]string{"jcs.go": "package votewire\n\nimport \"C\"\n\nconst jcsMax = 8\n"}, "jcs.go imports C"},
		"unsafe":                                  {map[string]string{"jcs.go": "package votewire\n\nimport \"unsafe\"\n\nconst jcsMax = 8\n\nvar _ = unsafe.Sizeof(0)\n"}, "jcs.go imports unsafe"},
		"a blank import":                          {map[string]string{"jcs.go": "package votewire\n\nimport _ \"embed\"\n\nconst jcsMax = 8\n"}, "jcs.go has a _ import of embed"},
		"a dot import":                            {map[string]string{"jcs.go": "package votewire\n\nimport . \"strings\"\n\nconst jcsMax = 8\n\nvar _ = ToUpper\n"}, "jcs.go has a . import of strings"},
		"an uncompared vettid-vault package":      {map[string]string{"body.go": "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/evil\"\n\ntype Body struct{ X int }\n\nvar _ = evil.X\n"}, "body.go imports github.com/vettid/vettid-vault/internal/evil, which isn't compared"},
		"a map key":                               {map[string]string{"bundle.go": "package votewire\n\nvar limits = map[int]bool{jcsMax: true}\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go, as a key"},
		"an array key":                            {map[string]string{"bundle.go": "package votewire\n\nvar limits = [...]bool{jcsMax: true}\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go, as a key"},
		"a map key an excluded field hides":       {map[string]string{"bundle.go": "package votewire\n\nvar limits = map[int]bool{jcsMax: true}\n\nfunc VerifyBundle(b []byte) error { return nil }\n", "jcs.go": "package votewire\n\nconst jcsMax = 8\n\ntype t struct{ jcsMax int }\n"}, "bundle.go uses jcsMax, declared in jcs.go, as a key"},
		"a map key a compared field hides":        {map[string]string{"bundle.go": "package votewire\n\ntype o struct{ jcsMax int }\n\nvar limits = map[int]bool{jcsMax: true}\n\nfunc VerifyBundle(b []byte) error { return nil }\n"}, "bundle.go uses jcsMax, declared in jcs.go, as a key"},
		"a predeclared name":                      {map[string]string{"jcs.go": "package votewire\n\nconst jcsMax = 8\n\nconst true = false\n"}, "jcs.go declares true, a predeclared name"},
		"a predeclared func":                      {map[string]string{"jcs.go": "package votewire\n\nconst jcsMax = 8\n\nfunc len(s string) int { return 0 }\n"}, "jcs.go declares len, a predeclared name"},
		"a parse error":                           {map[string]string{"body.go": "package votewire\n\nfunc {\n"}, "body.go doesn't parse"},
		// Compared state written or handed out by an excluded file.
		"a sentinel assigned":                  {map[string]string{"body.go": body + "func reset() { ErrBody = nil }\n"}, "body.go mentions ErrBody other than as a plain read"},
		"a slice element set":                  {map[string]string{"body.go": body + "func reset() { oidSHA256[0] = 9 }\n"}, "body.go mentions oidSHA256 other than as a plain read"},
		"a slice read":                         {map[string]string{"body.go": body + "func get() int { return oidSHA256[0] }\n"}, "body.go mentions oidSHA256 other than as a plain read"},
		"a slice returned":                     {map[string]string{"body.go": body + "func get() []int { return oidSHA256 }\n"}, "body.go mentions oidSHA256 other than as a plain read"},
		"a sentinel in another operation":      {map[string]string{"body.go": body + "func f() bool { return ErrBody < ErrBody }\n"}, "body.go mentions ErrBody other than as a plain read"},
		"a computed variable returned":         {map[string]string{"body.go": body + "func get() []int { return table }\n"}, "body.go mentions table other than as a plain read"},
		"a slice sliced":                       {map[string]string{"body.go": body + "func get() []int { return oidSHA256[:] }\n"}, "body.go mentions oidSHA256 other than as a plain read"},
		"a slice passed on":                    {map[string]string{"body.go": body + "func use(x []int) {}\n\nfunc get() { use(oidSHA256) }\n"}, "body.go mentions oidSHA256 other than as a plain read"},
		"a sentinel's address":                 {map[string]string{"body.go": body + "func get() *error { return &ErrBody }\n"}, "body.go mentions ErrBody other than as a plain read"},
		"a sentinel passed on":                 {map[string]string{"body.go": body + "func use(e error) {}\n\nfunc get() { use(ErrBody) }\n"}, "body.go mentions ErrBody other than as a plain read"},
		"another package's sentinel assigned":  {map[string]string{"body.go": body + "func reset() { suite.ErrSignature = nil }\n"}, "body.go mentions suite.ErrSignature other than as a plain read"},
		"strictjson's sentinel assigned":       {map[string]string{"body.go": body + "func reset() { strictjson.ErrSyntax = nil }\n"}, "body.go mentions strictjson.ErrSyntax other than as a plain read"},
		"a renamed import's sentinel assigned": {map[string]string{"body.go": "package votewire\n\nimport s \"github.com/vettid/vettid-vault/vms/suite\"\n\ntype Body struct{ X int }\n\nfunc reset() { s.ErrSignature = nil }\n"}, "body.go mentions s.ErrSignature other than as a plain read"},
	} {
		if p := reach(c.changes); !strings.Contains(strings.Join(p, "\n"), c.want) {
			t.Errorf("%s: %q, want %q", name, p, c.want)
		}
	}
	// Look-alikes: struct fields and keys of a compared struct, a local,
	// a selector, all named like an excluded file's declarations; an
	// excluded type embedding a compared one.
	alike := map[string]string{"bundle.go": `package votewire

type Out struct{ Body []byte; docHelper int }

func VerifyBundle(b []byte) error {
	docSchema := 1
	_ = docSchema
	o := Out{Body: b, docHelper: 2}
	_ = o.Body
	return nil
}
`, "documents.go": "package votewire\n\nvar docSchema = map[string]any{\"doc\": nil}\n\nfunc docHelper() int { return len(docSchema) }\n\ntype wrapped struct{ Info }\n"}
	if p := reach(alike); len(p) != 0 {
		t.Fatalf("look-alikes reported: %q", p)
	}
}

// What the files not compared may do: import the standard library, a
// compared vettid-vault package or another module; declare methods on
// their own types (generic ones too); read an error sentinel plainly.
func TestExcludedReachAllowed(t *testing.T) {
	p := reach(map[string]string{
		"body.go": `package votewire

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

type Body struct{ X int }

type pair[T any] struct{ a, b T }

func (p *pair[T]) First() T { return p.a }

func (b *Body) UnmarshalJSON(p []byte) error {
	if err := json.Unmarshal(p, new(int)); err != nil {
		return ErrBody
	}
	err := strictjson.Check(p)
	if err == strictjson.ErrSyntax || err != ErrBody {
		return suite.ErrSignature
	}
	switch err {
	case ErrBody, suite.ErrSignature:
		return err
	}
	var e error = ErrBody
	return e
}
`,
		"documents.go": "package votewire\n\nimport \"golang.org/x/text/unicode/norm\"\n\nvar _ = norm.NFC\n",
	})
	if len(p) != 0 {
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
		"vms/votewire/body.go":          "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/strictjson\"\n\ntype Body struct{ X int }\n\nvar _ = strictjson.Check\n\nfunc reset() { strictjson.ErrSyntax = nil }\n",
	})
	r := runCheck(t, old, nil, nil)
	wantErr(t, r, "body.go mentions strictjson.ErrSyntax other than as a plain read")
	if slices.ContainsFunc(r.errs, func(e string) bool { return strings.Contains(e, "isn't compared") }) {
		t.Fatalf("the old place's import refused: %q", r.errs)
	}
	evil := with(base, map[string]string{"vms/votewire/body.go": "package votewire\n\nimport \"github.com/vettid/vettid-vault/internal/evil\"\n\ntype Body struct{ X int }\n\nvar _ = evil.X\n"})
	wantErr(t, runCheck(t, evil, nil, nil), "release staging/1: vms/votewire: body.go imports github.com/vettid/vettid-vault/internal/evil, which isn't compared")
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
