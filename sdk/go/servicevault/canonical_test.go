package servicevault_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vettid/service-vault/sdk/go/servicevault"
)

// actionHashVector is one fixed input of testdata/action_hash.json with
// its canonical bytes and hash. The vectors are fixed: a change to the
// encoding that alters one is a breaking change for applications.
type actionHashVector struct {
	Name      string `json:"name"`
	Action    string `json:"action"`
	Summary   string `json:"summary"`
	Payload   string `json:"payload"` // the JSON text as submitted
	Canonical string `json:"canonical"`
	Hash      string `json:"action_hash"`
}

func TestActionHashVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/action_hash.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []actionHashVector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 8 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		c, err := servicevault.CanonicalAction(v.Action, v.Summary, json.RawMessage(v.Payload))
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(c) != v.Canonical {
			t.Errorf("%s: canonical\n got %s\nwant %s", v.Name, c, v.Canonical)
		}
		h, err := servicevault.ActionHash(v.Action, v.Summary, json.RawMessage(v.Payload))
		if err != nil || h != v.Hash {
			t.Errorf("%s: hash %s, want %s (%v)", v.Name, h, v.Hash, err)
		}
	}
}

// Numbers as RFC 8785 Appendix B prints them, and other single values.
func TestCanonicalJSONValues(t *testing.T) {
	for in, want := range map[string]string{
		`0`: `0`, `-0`: `0`, `-0.0`: `0`, `1`: `1`, `-1`: `-1`, `4.50`: `4.5`, `2e-3`: `0.002`,
		`0.000001`: `0.000001`, `1e-7`: `1e-7`, `1E30`: `1e+30`, `1e21`: `1e+21`, `1e20`: `100000000000000000000`,
		`9007199254740993`: `9007199254740992`, `12345678901234567890`: `12345678901234567000`,
		`333333333.33333329`: `333333333.3333333`, `5e-324`: `5e-324`, `1.7976931348623157e308`: `1.7976931348623157e+308`,
		`-1.5e-7`: `-1.5e-7`, `100.0`: `100`, `0.1`: `0.1`,
		`"\u20ac\/\u0041"`: `"€/A"`, `"\ud83d\ude00"`: `"😀"`, `"a\u001fb\u007f"`: "\"a\\u001fb\x7f\"",
		`"\b\f\n\r\t\"\\"`:                          `"\b\f\n\r\t\"\\"`,
		` [ 1 , true , false , null , { } , [ ] ] `: `[1,true,false,null,{},[]]`,
		// RFC 8785 §3.2.3's sorting example.
		`{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`: "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}",
		// Sorted by UTF-16 code units: U+FB33 sorts after U+1F600 (a surrogate pair, 0xD83D...).
		`{"\ufb33":1,"😀":2,"a":3,"B":4,"":5}`: "{\"\":5,\"B\":4,\"a\":3,\"\U0001F600\":2,\"\ufb33\":1}",
	} {
		got, err := servicevault.CanonicalJSON([]byte(in))
		if err != nil || string(got) != want {
			t.Errorf("%s: got %s, %v; want %s", in, got, err, want)
		}
	}
}

func TestCanonicalJSONRejects(t *testing.T) {
	for _, in := range []string{
		``, `{`, `{"a":1,"a":2}`, `"\ud800"`, `"\udc00x"`, `"\ud800\u0041"`, "\"\xff\"", "\"a\nb\"", `01`, `1.`, `.5`, `1e`,
		`+1`, `1e400`, `NaN`, `[1,]`, `{"a":1,}`, `{"a" 1}`, `tru`, `[1] 2`, `"\x"`, `"\u12"`,
	} {
		if got, err := servicevault.CanonicalJSON([]byte(in)); err == nil {
			t.Errorf("%q accepted as %s", in, got)
		}
	}
	deep := ""
	for i := 0; i <= servicevault.MaxCanonicalDepth+1; i++ {
		deep += "["
	}
	if _, err := servicevault.CanonicalJSON([]byte(deep)); err == nil {
		t.Error("too deep accepted")
	}
	if _, err := servicevault.ActionHash("vote.open", "s", json.RawMessage(`[1]`)); err == nil {
		t.Error("array payload accepted")
	}
}
