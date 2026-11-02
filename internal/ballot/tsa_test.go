package ballot

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/vettid/service-vault/internal/ballot/ballottest"
)

func TestTSATime(t *testing.T) {
	if got, err := TSATime(ballottest.Bundle(1793500123, 1793500999)); err != nil || got != 1793500123 {
		t.Fatalf("made: %d %v", got, err)
	}
	for name, b := range map[string]string{"none": `{}`, "empty": `{"verificationMaterial":{"timestampVerificationData":{"rfc3161Timestamps":[{"signedTimestamp":"AAAA"}]}}}`} {
		if _, err := TSATime(json.RawMessage(b)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The staging bundle of the anchor vector: the timestamp's genTime read
// from a real token is within the window the site and the vaults allow of
// the Rekor time.
func TestTSATimeVector(t *testing.T) {
	raw, err := os.ReadFile("../../vote/testdata/anchor-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var b struct {
		VM struct {
			Tlog []struct {
				T string `json:"integratedTime"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	_ = json.Unmarshal(v.Bundle, &b)
	tsa, err := TSATime(v.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	var integrated int64
	for _, c := range b.VM.Tlog[0].T {
		integrated = integrated*10 + int64(c-'0')
	}
	if d := integrated - tsa; d < -60 || d > 600 {
		t.Fatalf("tsa %d, integrated %d", tsa, integrated)
	}
}
