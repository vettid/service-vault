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
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
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

// votewirePkg is the vault's bundle verifier package.
const votewirePkg = "github.com/vettid/vettid-vault/vms/votewire"

// votewireNotVerifier are the files of votewire no bundle or root check
// reaches (message bodies, documents, JCS): every other file is compared,
// a new one included. As they aren't compared, nothing in them may reach
// the verifier (excludedReach).
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

func goSource(name string) bool {
	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
}

// compared reports whether a file of the package at rel is compared.
func compared(rel, name string) bool {
	return goSource(name) && (rel != "vms/votewire" || !slices.Contains(votewireNotVerifier, name))
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
// godebug settings (as the go command reads them: go mod edit -json), and
// the tree's //go:debug directives (both set GODEBUG defaults, some of
// crypto/x509's and encoding/asn1's parsing among them). One per line.
func buildSettings(t *testing.T, gomod []byte, goDebug []string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o644); err != nil {
		t.Fatal(err)
	}
	var m struct {
		Go, Toolchain string
		Godebug       []struct{ Key, Value string }
	}
	if err := json.Unmarshal(goCmd(t, "mod", "edit", "-json", filepath.Join(dir, "go.mod")), &m); err != nil {
		t.Fatalf("go mod edit -json: %v", err)
	}
	out := []string{"go " + m.Go}
	if m.Toolchain != "" {
		out = append(out, "toolchain "+m.Toolchain)
	}
	for _, g := range m.Godebug {
		out = append(out, "godebug "+g.Key+"="+g.Value)
	}
	d := slices.Clone(goDebug)
	slices.Sort(d)
	out = append(out, slices.Compact(d)...)
	return strings.Join(out, "\n")
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
	if b := buildSettings(t, git(t, repo, "show", tag+":go.mod"), goDebugLines(gitGrep(t, repo, "-h", "-e", "//go:debug", tag, "--", "*.go"))); b != v.build {
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
	// Each compared package's sources at the tag (every non-test Go file).
	tagSources := map[string]map[string][]byte{}
	for _, p := range v.pkgs {
		dir := p.rel
		if moved && dir == strictjsonMove[1] {
			dir = strictjsonMove[0]
		}
		src := map[string][]byte{}
		for _, e := range lsTree(t, repo, tag, dir) {
			if !entryOK(e.name, e.dir) {
				r.Errorf("release %s: %s/%s: a compared package may hold only Go files, docs and testdata", rel, p.rel, e.name)
			}
			if !e.dir && goSource(e.name) {
				src[e.name] = norm(git(t, repo, "show", tag+":"+dir+"/"+e.name))
			}
		}
		tagSources[p.rel] = src
	}
	importOK := func(imp string) bool {
		rest, vv := strings.CutPrefix(normPath(imp), vvPrefix)
		return !vv || known[rest]
	}
	for _, problem := range excludedReach(tagSources["vms/votewire"], importOK, comparedVars(tagSources)) {
		r.Errorf("release %s: vms/votewire: %s: the files not compared reach the verifier", rel, problem)
	}
	for _, p := range v.pkgs {
		dir := p.rel
		if moved && dir == strictjsonMove[1] {
			dir = strictjsonMove[0]
		}
		var atTag []string
		for name := range tagSources[p.rel] {
			if compared(p.rel, name) {
				atTag = append(atTag, name)
			}
		}
		sort.Strings(atTag)
		for _, name := range atTag {
			pinned := p.rel + "/" + name
			normed := tagSources[p.rel][name]
			imps, err := goImports(name, normed)
			if err != nil {
				r.Errorf("release %s: %s doesn't parse: %v", rel, pinned, err)
			}
			for _, imp := range imps {
				rest, vv := strings.CutPrefix(imp, vvPrefix)
				if nc, ok := notCompared[rest]; vv && !known[rest] && (!ok || nc.from != pinned) {
					r.Errorf("release %s: %s imports %s, which the pinned verifier doesn't: it isn't compared", rel, pinned, imp)
				}
			}
			raw := git(t, repo, "show", tag+":"+dir+"/"+name)
			want, ok := p.files[name]
			switch {
			case !ok:
				differ(pinned, "is at the tag but not in the pinned vettid-vault", raw, nil)
			case !bytes.Equal(normed, want):
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

// comparedVars are the package-level variables of the compared files, by
// package import path: name to whether it is an error sentinel (its
// initializer is errors.New or fmt.Errorf). Excluded votewire files' own
// variables aren't among them. Files that don't parse are left out
// (excludedReach and the comparison report them).
func comparedVars(sources map[string]map[string][]byte) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for rel, src := range sources {
		vars := map[string]bool{}
		for name, b := range src {
			if !compared(rel, name) {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), name, b, parser.SkipObjectResolution)
			if err != nil {
				continue
			}
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, id := range vs.Names {
						vars[id.Name] = i < len(vs.Values) && isSentinelInit(vs.Values[i])
					}
				}
			}
		}
		out[vvPrefix+rel] = vars
	}
	return out
}

// isSentinelInit: errors.New(...) or fmt.Errorf(...).
func isSentinelInit(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	s, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := s.X.(*ast.Ident)
	return ok && (pkg.Name == "errors" && s.Sel.Name == "New" || pkg.Name == "fmt" && s.Sel.Name == "Errorf")
}

// excludedReach lists how votewire's files that aren't compared
// (votewireNotVerifier) could reach the verifier, given every non-test Go
// file of the package (name to source) and the compared packages'
// package-level variables (comparedVars):
//   - a compared file using one of their top-level names: an identifier
//     its own scopes don't declare, or a composite literal key that names
//     one (always in a map or array literal; in a struct literal, unless a
//     struct a compared file declares has a field of that name);
//   - a method of theirs on a type they don't define themselves: a
//     compared file's type, or an alias (an alias of a compared type would
//     give it the method, an UnmarshalJSON say);
//   - their mention of a compared package-level variable (votewire's, or
//     strictjson's or suite's through their import) other than a plain read
//     of an error sentinel: returned, compared with == or !=, a case, or
//     the value of an assignment. Anything else could change what the
//     verifier relies on (ErrBundleRoot = nil, oidSHA256[0] = 9,
//     suite.ErrSignature = nil; a slice passed on can be written);
//   - an init, or a package-level variable whose initializer calls
//     something;
//   - a top-level name of theirs shadowing a predeclared one (true, len);
//   - an import that could run code of its own: cgo, unsafe, a blank or
//     dot import, or one importOK refuses (a vettid-vault package that
//     isn't compared).
//
// A file that doesn't parse is a problem too.
func excludedReach(sources map[string][]byte, importOK func(string) bool, vars map[string]map[string]bool) []string {
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
	universe := types.Universe.Names()
	declared := map[string]string{} // an excluded file's top-level name -> the file
	defined := map[string]bool{}    // the types the excluded files define (not aliases)
	fields := map[string]bool{}     // the struct field names the compared files declare
	for _, n := range names {
		f := files[n]
		if f == nil {
			continue
		}
		if !excluded(n) {
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
		declare := func(id *ast.Ident) {
			declared[id.Name] = n
			if slices.Contains(universe, id.Name) {
				problems = append(problems, fmt.Sprintf("%s declares %s, a predeclared name", n, id.Name))
			}
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					if d.Name.Name == "init" {
						problems = append(problems, n+" has an init")
					} else {
						declare(d.Name)
					}
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, id := range s.Names {
							declare(id)
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
						declare(s.Name)
						if !s.Assign.IsValid() {
							defined[s.Name.Name] = true
						}
					}
				}
			}
		}
	}
	local := vars[votewirePkg]
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
			problems = append(problems, varMisuse(n, f, local, vars)...)
			continue
		}
		for _, id := range f.Unresolved {
			if src, ok := declared[id.Name]; ok {
				problems = append(problems, fmt.Sprintf("%s uses %s, declared in %s", n, id.Name, src))
			}
		}
		// The parser leaves composite literal keys unresolved (a key may
		// be a field): in a map or array literal it is a value; in another
		// package's struct literal a field; else a field only if a
		// compared file's struct has one of that name.
		ast.Inspect(f, func(x ast.Node) bool {
			cl, ok := x.(*ast.CompositeLit)
			if !ok {
				return true
			}
			valueKeys := false
			switch cl.Type.(type) {
			case *ast.MapType, *ast.ArrayType:
				valueKeys = true
			case *ast.SelectorExpr:
				return true
			}
			for _, e := range cl.Elts {
				kv, ok := e.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if id, ok := kv.Key.(*ast.Ident); ok && (valueKeys || !fields[id.Name]) {
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

// varMisuse lists an excluded file's mentions of compared package-level
// variables other than a plain read of an error sentinel (excludedReach).
// local are votewire's compared variables; vars every compared package's,
// by import path, reached as <name>.X through the file's imports.
func varMisuse(n string, f *ast.File, local map[string]bool, vars map[string]map[string]bool) []string {
	unresolved := map[*ast.Ident]bool{}
	for _, id := range f.Unresolved {
		unresolved[id] = true
	}
	imported := map[string]string{} // the name a file gives an import -> its path
	for _, imp := range f.Imports {
		ip, _ := strconv.Unquote(imp.Path.Value)
		name := path.Base(ip)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imported[name] = ip
	}
	var problems []string
	mention := func(node ast.Node, what string, sentinel bool, stack []ast.Node) {
		if !sentinel || len(stack) == 0 || !plainRead(stack[len(stack)-1], node) {
			problems = append(problems, fmt.Sprintf("%s mentions %s other than as a plain read of an error sentinel", n, what))
		}
	}
	ast.Walk(&stackVisitor{fn: func(x ast.Node, stack []ast.Node) bool {
		switch x := x.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && unresolved[id] {
				if pv, ok := vars[imported[id.Name]]; ok {
					if s, ok := pv[x.Sel.Name]; ok {
						mention(x, id.Name+"."+x.Sel.Name, s, stack)
					}
					return false
				}
			}
		case *ast.Ident:
			if unresolved[x] {
				if s, ok := local[x.Name]; ok {
					mention(x, x.Name, s, stack)
				}
			}
		}
		return true
	}}, f)
	return problems
}

// plainRead reports whether node, a sentinel's mention, is read plainly by
// its parent: returned, compared with == or !=, a switch case, or the
// value of an assignment or declaration.
func plainRead(parent, node ast.Node) bool {
	in := func(list []ast.Expr) bool {
		for _, e := range list {
			if ast.Node(e) == node {
				return true
			}
		}
		return false
	}
	switch p := parent.(type) {
	case *ast.ReturnStmt:
		return in(p.Results)
	case *ast.BinaryExpr:
		return p.Op == token.EQL || p.Op == token.NEQ
	case *ast.CaseClause:
		return in(p.List)
	case *ast.AssignStmt:
		return in(p.Rhs)
	case *ast.ValueSpec:
		return in(p.Values)
	}
	return false
}

// stackVisitor walks a tree with its ancestors at hand; fn returning false
// skips a node's children.
type stackVisitor struct {
	stack []ast.Node
	fn    func(n ast.Node, stack []ast.Node) bool
}

func (v *stackVisitor) Visit(n ast.Node) ast.Visitor {
	if n == nil {
		v.stack = v.stack[:len(v.stack)-1]
		return nil
	}
	if !v.fn(n, v.stack) {
		return nil
	}
	v.stack = append(v.stack, n)
	return v
}

// receiverType is a method receiver's (or embedded field's) type name.
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
		case *ast.SelectorExpr:
			return x.Sel.Name
		case *ast.Ident:
			return x.Name
		default:
			return ""
		}
	}
}

// treeEntry is a directory entry at a tag.
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

// pinnedVerifier reads the compared files from the vettid-vault version
// go.mod pins: votewire's but votewireNotVerifier, and every non-test Go
// file of the vettid-vault packages votewire imports (go list -deps). It
// runs the same checks on it as on a release (entryOK, excludedReach),
// reporting through r.
func pinnedVerifier(t *testing.T, r reporter) []verifierPkg {
	t.Helper()
	modDir := strings.TrimSpace(string(goCmd(t, "list", "-m", "-f", "{{.Dir}}", "github.com/vettid/vettid-vault")))
	if modDir == "" {
		t.Fatal("go list -m: no directory for github.com/vettid/vettid-vault (a vendor directory, or not downloaded)")
	}
	var out []verifierPkg
	deps := map[string]bool{}
	sources := map[string]map[string][]byte{}
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
		deps[rel] = true
		p := verifierPkg{rel: rel, files: map[string][]byte{}}
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		src := map[string][]byte{}
		for _, e := range ents {
			if !entryOK(e.Name(), e.IsDir()) {
				r.Errorf("the pinned vettid-vault: %s/%s: a compared package may hold only Go files, docs and testdata", rel, e.Name())
			}
			if e.IsDir() || !goSource(e.Name()) {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			src[e.Name()] = b
			if compared(rel, e.Name()) {
				p.files[e.Name()] = b
			}
		}
		sources[rel] = src
		out = append(out, p)
	}
	if !slices.ContainsFunc(out, func(p verifierPkg) bool { return p.rel == "vms/votewire" && p.files["bundle.go"] != nil }) {
		t.Fatal("vms/votewire/bundle.go is not in the pinned vettid-vault")
	}
	importOK := func(imp string) bool {
		rest, vv := strings.CutPrefix(imp, vvPrefix)
		return !vv || deps[rest]
	}
	for _, problem := range excludedReach(sources["vms/votewire"], importOK, comparedVars(sources)) {
		r.Errorf("the pinned vettid-vault: vms/votewire: %s: the files not compared reach the verifier", problem)
	}
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
	build := buildSettings(t, b, goDebugLines(gitGrep(t, "../..", "-h", "-e", "//go:debug", "--", "*.go")))
	if !strings.Contains(build, "\ntoolchain ") {
		t.Fatal("../../go.mod has no toolchain line")
	}
	return build
}

// TestPinnedVerifier runs the pinned module's side of the comparison
// (entryOK, excludedReach) in every test run, from the module cache: it
// is the code the service runs.
func TestPinnedVerifier(t *testing.T) {
	if pkgs := pinnedVerifier(t, t); len(pkgs) < 3 {
		t.Fatalf("the pinned verifier has %d packages, want votewire, strictjson and suite at least", len(pkgs))
	}
	if b := serviceBuild(t); !strings.HasPrefix(b, "go ") {
		t.Fatalf("serviceBuild = %q", b)
	}
}
