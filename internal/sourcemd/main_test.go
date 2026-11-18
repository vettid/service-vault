package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/SOURCE.md is what go.mod and the notes generate (VAULT-SERVICE-
// INDEPENDENCE S2).
func TestSourceMDUpToDate(t *testing.T) {
	want, err := render("../..")
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../docs/SOURCE.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("docs/SOURCE.md is out of date: run `go run ./internal/sourcemd -w` from the repository root")
	}
}

func writeMod(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A direct requirement without a note, a note without a requirement, and
// a directive the parser doesn't know all fail; indirect ones are skipped.
func TestRenderRefuses(t *testing.T) {
	const tools = "module x/tools\n\ngo 1.26.0\n\nrequire github.com/sigstore/sigstore-go v1.3.0\n"
	full := func(extra string) string {
		var b strings.Builder
		b.WriteString("module github.com/vettid/service-vault\n\ngo 1.26.0\n\nrequire (\n")
		for p := range notes {
			b.WriteString("\t" + p + " v1.0.0\n")
		}
		b.WriteString("\tgolang.org/x/sys v0.1.0 // indirect\n)\n" + extra)
		return b.String()
	}
	for name, c := range map[string]struct {
		mod, want string
	}{
		"ok":         {full(""), ""},
		"indirect;":  {full("require example.com/dep v1.0.0 // indirect; pulled in by x\n"), ""},
		"no note":    {full("require example.com/new v1.0.0\n"), "no note for it"},
		"replace":    {full("replace example.com/a => ../a\n"), "not handled"},
		"stray note": {"module github.com/vettid/service-vault\n\ngo 1.26.0\n\nrequire rsc.io/qr v0.2.0\n", "does not require directly"},
	} {
		dir := t.TempDir()
		writeMod(t, dir, c.mod)
		writeMod(t, filepath.Join(dir, "tools", "rootwatch"), tools)
		_, err := render(dir)
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

func TestPseudo(t *testing.T) {
	for v, want := range map[string]pseudoVersion{
		"v0.0.0-20261112163356-425a5aeaef1b":              {"425a5aeaef1b", "2026-11-12 16:33:56"},
		"v1.2.4-0.20231217203849-220c5c2851b7":            {"220c5c2851b7", "2023-12-17 20:38:49"},
		"v1.2.3-pre.0.20231217203849-220c5c2851b7":        {"220c5c2851b7", "2023-12-17 20:38:49"},
		"v2.0.0-20231217203849-220c5c2851b7+incompatible": {"220c5c2851b7", "2023-12-17 20:38:49"},
	} {
		if got, ok := pseudo(v); !ok || got != want {
			t.Errorf("%s: %v %v", v, got, ok)
		}
	}
	for _, v := range []string{"v1.3.0", "v2.1.3", "v0.0.0-2026111216335-425a5aeaef1b", "v0.0.0-20261112163356-425A5AEAEF1B"} {
		if _, ok := pseudo(v); ok {
			t.Errorf("%s: read as a pseudo-version", v)
		}
	}
}
