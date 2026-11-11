package servicevault_test

// Every alarm the daemon logs (`"alarm", "<name>"`) is in the stack's
// ALARMS, so it reaches someone: an ERROR line marked for an alarm is left
// out of the generic errors alarm.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAlarmsAreInTheStack(t *testing.T) {
	stack, err := os.ReadFile("cdk/lib/service-vault-stack.ts")
	if err != nil {
		t.Fatal(err)
	}
	block := string(stack)
	i := strings.Index(block, "export const ALARMS = {")
	if i < 0 {
		t.Fatal("no ALARMS in the stack")
	}
	block = block[i : i+strings.Index(block[i:], "} as const;")]
	logged := regexp.MustCompile(`"alarm", "([a-z_]+)"`)
	found := 0
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "cdk.out" || strings.HasPrefix(d.Name(), ".")) && path != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range logged.FindAllStringSubmatch(string(src), -1) {
			found++
			if !regexp.MustCompile(`\n\s*` + m[1] + `:`).MatchString(block) {
				t.Errorf("%s logs alarm %q, which isn't in ALARMS (cdk/lib/service-vault-stack.ts)", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no alarm found in the source")
	}
}
