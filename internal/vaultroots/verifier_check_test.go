package vaultroots

// The bundle verifier comparison of the rootscheck test (rootscheck_test.go,
// build tag rootscheck): for a release tag of a vettid-vault clone, its
// verifier code against the pinned one. It needs only git, so it is tested
// offline here (verifier_check_offline_test.go) against a fixture repo.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// votewireNotVerifier are the files of votewire (the vault's bundle
// verifier package) no bundle or root check reaches (message bodies,
// documents, JCS): every other file is compared, a new one included.
// The excluded files aren't compared, so nothing in them may reach the
// verifier: excludedReach fails on a compared file using one of their
// top-level names, a method of theirs on any type they don't define
// themselves (an alias of a compared type included), an init, a
// package-level variable whose initializer calls something, or an import
// that could run code of its own (cgo, unsafe, a blank or dot import, a
// vettid-vault package that isn't compared).
var votewireNotVerifier = []string{"body.go", "documents.go", "jcs.go"}

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

// buildPath is the knownDifference path of go.mod's build settings (its
// go, toolchain and godebug lines).
const buildPath = "go.mod go/toolchain/godebug"

type verifierCheck struct {
	pkgs  []verifierPkg
	build string // the service's go.mod build settings (buildLines)
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

func goSource(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// compared reports whether a file of the package at rel is compared.
func compared(rel, name string) bool {
	return goSource(name) && (rel != "vms/votewire" || !slices.Contains(votewireNotVerifier, name))
}

// vvImport finds a file's imports of vettid-vault packages.
var vvImport = regexp.MustCompile(`"` + regexp.QuoteMeta(vvPrefix) + `([^"]+)"`)

// buildLines is what of go.mod decides how the module is built: its go
// and toolchain lines and its godebug settings (which set GODEBUG
// defaults, crypto/x509's and encoding/asn1's among them), one per line
// in order, comments and spacing dropped.
func buildLines(gomod []byte) string {
	var out []string
	inGodebug := false
	for _, l := range strings.Split(string(gomod), "\n") {
		if i := strings.Index(l, "//"); i >= 0 {
			l = l[:i]
		}
		l = strings.Join(strings.Fields(l), " ")
		switch {
		case inGodebug && l == ")":
			inGodebug = false
		case inGodebug && l != "":
			out = append(out, "godebug "+l)
		case l == "godebug (":
			inGodebug = true
		case strings.HasPrefix(l, "go "), strings.HasPrefix(l, "toolchain "), strings.HasPrefix(l, "godebug "):
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
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
	// How the release is built (go, toolchain, godebug), against the
	// service.
	if b := buildLines(git(t, repo, "show", tag+":go.mod")); b != v.build {
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
		sources := map[string][]byte{} // votewire's, for excludedReach
		for _, name := range lsTree(t, repo, tag, dir) {
			if !goSource(name) {
				continue
			}
			if p.rel == "vms/votewire" {
				sources[name] = git(t, repo, "show", tag+":"+dir+"/"+name)
			}
			if compared(p.rel, name) {
				atTag = append(atTag, name)
			}
		}
		if p.rel == "vms/votewire" {
			importOK := func(imp string) bool {
				if moved && imp == vvPrefix+strictjsonMove[0] {
					imp = vvPrefix + strictjsonMove[1]
				}
				rest, vv := strings.CutPrefix(imp, vvPrefix)
				return !vv || known[rest]
			}
			for _, problem := range excludedReach(sources, importOK) {
				r.Errorf("release %s: vms/votewire: %s: the files not compared reach the verifier", rel, problem)
			}
		}
		for _, name := range atTag {
			pinned := p.rel + "/" + name
			raw := git(t, repo, "show", tag+":"+dir+"/"+name)
			for _, m := range vvImport.FindAllSubmatch(norm(raw), -1) {
				imp := string(m[1])
				if nc, ok := notCompared[imp]; !known[imp] && (!ok || nc.from != pinned) {
					r.Errorf("release %s: %s imports %s%s, which the pinned verifier doesn't: it isn't compared", rel, pinned, vvPrefix, imp)
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

// excludedReach lists how votewire's files that aren't compared
// (votewireNotVerifier) could reach the verifier, given every non-test Go
// file of the package (name to source):
//   - a compared file using one of their top-level names: an identifier
//     its own scopes don't declare, or a composite literal key that names
//     one and no struct field of the package;
//   - a method of theirs on a type they don't define themselves: a
//     compared file's type, or an alias (an alias of a compared type would
//     give it the method, an UnmarshalJSON say);
//   - an init, or a package-level variable whose initializer calls
//     something;
//   - an import that could run code of its own: cgo, unsafe, a blank or
//     dot import, or one importOK refuses (a vettid-vault package that
//     isn't compared).
//
// A file that doesn't parse is a problem too.
func excludedReach(sources map[string][]byte, importOK func(string) bool) []string {
	fset := token.NewFileSet()
	var problems []string
	files := map[string]*ast.File{}
	names := make([]string, 0, len(sources))
	for n := range sources {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := parser.ParseFile(fset, n, sources[n], 0)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s doesn't parse: %v", n, err))
			continue
		}
		files[n] = f
	}
	excluded := func(n string) bool { return slices.Contains(votewireNotVerifier, n) }
	declared := map[string]string{} // an excluded file's top-level name -> the file
	defined := map[string]bool{}    // the types the excluded files define (not aliases)
	fields := map[string]bool{}     // every struct field name of the package
	for _, n := range names {
		f := files[n]
		if f == nil {
			continue
		}
		ast.Inspect(f, func(x ast.Node) bool {
			if st, ok := x.(*ast.StructType); ok {
				for _, fl := range st.Fields.List {
					for _, id := range fl.Names {
						fields[id.Name] = true
					}
					if len(fl.Names) == 0 { // embedded: named by its type
						fields[receiverType(fl.Type)] = true
					}
				}
			}
			return true
		})
		if !excluded(n) {
			continue
		}
		for _, imp := range f.Imports {
			ip, _ := strconv.Unquote(imp.Path.Value)
			switch {
			case ip == "C" || ip == "unsafe":
				problems = append(problems, fmt.Sprintf("%s imports %s", n, ip))
			case imp.Name != nil && (imp.Name.Name == "_" || imp.Name.Name == "."):
				problems = append(problems, fmt.Sprintf("%s has a %s import of %s", n, imp.Name.Name, ip))
			case !importOK(ip):
				problems = append(problems, fmt.Sprintf("%s imports %s, which isn't compared", n, ip))
			}
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					if d.Name.Name == "init" {
						problems = append(problems, n+" has an init")
					} else {
						declared[d.Name.Name] = n
					}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, id := range s.Names {
							declared[id.Name] = n
						}
						if d.Tok != token.VAR {
							continue
						}
						for _, val := range s.Values {
							ast.Inspect(val, func(x ast.Node) bool {
								if _, ok := x.(*ast.CallExpr); ok {
									problems = append(problems, fmt.Sprintf("%s: the package-level variable %s's initializer calls something", n, s.Names[0].Name))
									return false
								}
								return true
							})
						}
					case *ast.TypeSpec:
						declared[s.Name.Name] = n
						if !s.Assign.IsValid() {
							defined[s.Name.Name] = true
						}
					}
				}
			}
		}
	}
	for _, n := range names {
		f := files[n]
		if f == nil {
			continue
		}
		if excluded(n) {
			for _, d := range f.Decls {
				if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && len(fd.Recv.List) > 0 {
					if rt := receiverType(fd.Recv.List[0].Type); !defined[rt] {
						problems = append(problems, fmt.Sprintf("%s declares the method %s.%s on a type the files not compared don't define", n, rt, fd.Name.Name))
					}
				}
			}
			continue
		}
		for _, id := range f.Unresolved {
			if src, ok := declared[id.Name]; ok {
				problems = append(problems, fmt.Sprintf("%s uses %s, declared in %s", n, id.Name, src))
			}
		}
		// The parser leaves composite literal keys unresolved (a key may
		// be a field): one that names no field is a value used.
		ast.Inspect(f, func(x ast.Node) bool {
			if kv, ok := x.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && !fields[id.Name] {
					if src, ok := declared[id.Name]; ok {
						problems = append(problems, fmt.Sprintf("%s uses %s, declared in %s, as a key", n, id.Name, src))
					}
				}
			}
			return true
		})
	}
	slices.Sort(problems)
	return slices.Compact(problems)
}

// receiverType is a method receiver's type name.
func receiverType(e ast.Expr) string {
	for {
		switch x := e.(type) {
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// lsTree lists the names (base names) of a directory's entries at a tag.
func lsTree(t *testing.T, repo, tag, dir string) []string {
	t.Helper()
	var out []string
	for _, e := range bytes.Split(git(t, repo, "ls-tree", "-z", "--name-only", tag, dir+"/"), []byte{0}) {
		if len(e) > 0 {
			out = append(out, path.Base(string(e)))
		}
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
