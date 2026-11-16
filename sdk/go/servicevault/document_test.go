package servicevault_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/service-vault/sdk/go/servicevault"
)

func docErr(t *testing.T, err error) *servicevault.DocumentError {
	t.Helper()
	var de *servicevault.DocumentError
	if !errors.As(err, &de) {
		return nil
	}
	return de
}

// Every number a member's vault would refuse, judged in the canonical
// bytes, names the field it is in.
func TestApprovalDocumentNumbers(t *testing.T) {
	for _, c := range []struct{ payload, field string }{
		{`{"n":-1}`, "/payload/n"},
		{`{"n":0.5}`, "/payload/n"},
		{`{"n":-0.5}`, "/payload/n"},
		{`{"n":1.5e3}`, ""},          // 1500: passes
		{`{"n":1e21}`, "/payload/n"}, // canonical 1e+21
		{`{"n":1e-7}`, "/payload/n"}, // canonical 1e-7
		{`{"n":0.000001}`, "/payload/n"},
		{`{"n":9007199254740992}`, "/payload/n"}, // 2^53
		{`{"n":9007199254740993}`, "/payload/n"}, // the double 2^53
		{`{"n":123456789012345678901}`, "/payload/n"},
		{`{"change":{"amount":-3}}`, "/payload/change/amount"},
		{`{"push":[1,2,{"x":[0,-2]}]}`, "/payload/push/2/x/1"},
		{`{"a/b":{"c~d":-1}}`, "/payload/a~1b/c~0d"},
		{`{"":0.25}`, "/payload/"},
	} {
		_, err := servicevault.ApprovalDocument("contract_template.change", "x", json.RawMessage(c.payload))
		de := docErr(t, err)
		switch {
		case c.field == "" && err != nil:
			t.Errorf("%s: %v", c.payload, err)
		case c.field != "" && (de == nil || de.Reason != servicevault.DocumentNumber || de.Field != c.field):
			t.Errorf("%s: %v, want number at %s", c.payload, err, c.field)
		}
	}
}

// Numbers whose canonical form is an integer from 0 to 2^53 - 1 pass,
// whatever form the input had.
func TestApprovalDocumentNumbersPass(t *testing.T) {
	for _, p := range []string{
		`{"n":0}`, `{"n":-0}`, `{"n":-0.0}`, `{"n":0.0e5}`, `{"n":1.0}`, `{"n":1e3}`, `{"n":1E+3}`, `{"n":10e-1}`,
		`{"n":9007199254740991}`, `{"n":9007199254740991.0}`, `{"a":[1,2,3],"b":{"c":42},"s":"-1.5e3"}`,
	} {
		doc, err := servicevault.ApprovalDocument("contract_template.change", "x", json.RawMessage(p))
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if c, _ := servicevault.CanonicalAction("contract_template.change", "x", json.RawMessage(p)); string(c) != string(doc) {
			t.Errorf("%s: %s, not CanonicalAction's %s", p, doc, c)
		}
	}
}

// nested returns a payload whose own nesting is n levels (the payload
// object itself is one): {"a":{"a":...}} with a [] innermost.
func nested(n int) string {
	return strings.Repeat(`{"a":`, n-1) + `[]` + strings.Repeat(`}`, n-1)
}

func TestApprovalDocumentDepth(t *testing.T) {
	// The document is level 1, so the payload has 15.
	if _, err := servicevault.ApprovalDocument("contract_template.change", "x", json.RawMessage(nested(15))); err != nil {
		t.Fatalf("15 levels: %v", err)
	}
	_, err := servicevault.ApprovalDocument("contract_template.change", "x", json.RawMessage(nested(16)))
	want := "/payload" + strings.Repeat("/a", 15)
	if de := docErr(t, err); de == nil || de.Reason != servicevault.DocumentDepth || de.Field != want {
		t.Fatalf("16 levels: %v, want depth at %s", err, want)
	}
	// Scalars add no level.
	if _, err := servicevault.ApprovalDocument("contract_template.change", "x",
		json.RawMessage(strings.Repeat(`{"a":`, 14)+`{"a":1,"b":"s","c":null}`+strings.Repeat(`}`, 14))); err != nil {
		t.Fatalf("scalars at the deepest level: %v", err)
	}
	// Past CanonicalJSON's own bound (64), still a depth error, not ErrCanonical.
	if de := docErr(t, servicevault.CheckDocument([]byte(`{"action":"x","payload":`+nested(80)+`,"summary":"x"}`))); de == nil || de.Reason != servicevault.DocumentDepth {
		t.Fatalf("80 levels: %v", de)
	}
}

func TestApprovalDocumentSize(t *testing.T) {
	doc := func(n int) []byte {
		b, err := servicevault.CanonicalAction("contract_template.change", "x", json.RawMessage(`{"a":"`+strings.Repeat("y", n)+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	n := servicevault.MaxDocumentBytes - len(doc(0))
	if b := doc(n); len(b) != servicevault.MaxDocumentBytes || servicevault.CheckDocument(b) != nil {
		t.Fatalf("%d bytes: %v", len(b), servicevault.CheckDocument(b))
	}
	if de := docErr(t, servicevault.CheckDocument(doc(n+1))); de == nil || de.Reason != servicevault.DocumentSize || de.Field != "" {
		t.Fatalf("one byte over: %v", de)
	}
}

// CheckDocument judges the bytes as sent: they must be canonical.
func TestCheckDocumentCanonical(t *testing.T) {
	for _, b := range []string{
		`{"action":"x","payload":{},"summary":"x"} `,
		`{"payload":{},"action":"x","summary":"x"}`,
		`{"action":"x","payload":{"a":1,"a":1},"summary":"x"}`,
		`{"action":"x","payload":{},"summary":"x"}{}`,
		`{"action":"x","payload":{`,
		``,
	} {
		if err := servicevault.CheckDocument([]byte(b)); !errors.Is(err, servicevault.ErrCanonical) {
			t.Errorf("%q: %v", b, err)
		}
	}
	// A number refused in its non-canonical form is still named as one.
	if de := docErr(t, servicevault.CheckDocument([]byte(`{"action":"x","payload":{"n":1.0},"summary":"x"}`))); de == nil || de.Reason != servicevault.DocumentNumber {
		t.Fatalf("1.0 as sent: %v", de)
	}
	if err := servicevault.CheckDocument([]byte(`{"action":"x","payload":{"n":1},"summary":"x"}`)); err != nil {
		t.Fatal(err)
	}
}

// Two faults: the nesting is judged over the whole document first, as a
// member's vault does.
func TestApprovalDocumentDepthFirst(t *testing.T) {
	p := `{"a":-1,"b":` + nested(16) + `}`
	_, err := servicevault.ApprovalDocument("contract_template.change", "x", json.RawMessage(p))
	if de := docErr(t, err); de == nil || de.Reason != servicevault.DocumentDepth || !strings.HasPrefix(de.Field, "/payload/b/") {
		t.Fatalf("%v", err)
	}
}

// The action and the summary are within the receiver's bounds.
func TestApprovalDocumentShape(t *testing.T) {
	for _, c := range []struct {
		action, summary, field string
	}{
		{"", "x", "/action"},
		{"Contract.change", "x", "/action"},
		{"a-b", "x", "/action"},
		{strings.Repeat("a", 65), "x", "/action"},
		{"x", strings.Repeat("s", servicevault.MaxDocumentSummary+1), "/summary"},
	} {
		_, err := servicevault.ApprovalDocument(c.action, c.summary, json.RawMessage(`{}`))
		if de := docErr(t, err); de == nil || de.Reason != servicevault.DocumentShape || de.Field != c.field {
			t.Errorf("%.20q %d: %v", c.action, len(c.summary), err)
		}
	}
	if _, err := servicevault.ApprovalDocument(strings.Repeat("a", 60)+"_.09", strings.Repeat("s", servicevault.MaxDocumentSummary), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Out of the double range: no canonical form.
	if _, err := servicevault.ApprovalDocument("x", "x", json.RawMessage(`{"n":1E400}`)); !errors.Is(err, servicevault.ErrCanonical) {
		t.Fatalf("1E400: %v", err)
	}
}
