package anchor

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type vector struct {
	Proposal string          `json:"proposal"`
	Bundle   json.RawMessage `json:"bundle"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	raw, err := os.ReadFile("../../vote/testdata/anchor-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A real staging token verifies against the pinned chain; the document,
// the instance and the signature it timestamps are all checked.
func TestTimestampTime(t *testing.T) {
	v := loadVector(t)
	doc := []byte(v.Proposal)
	at, err := TimestampTime(Staging, v.Bundle, doc)
	if err != nil || at < 1.7e9 {
		t.Fatalf("the staging vector: %d, %v", at, err)
	}
	if _, err := TimestampTime(Production, v.Bundle, doc); err == nil {
		t.Error("a staging token verified against production's chain")
	}
	if _, err := TimestampTime(Staging, v.Bundle, append([]byte(" "), doc...)); err == nil {
		t.Error("another document verified")
	}
	// Another message signature: the imprint no longer matches.
	var m map[string]any
	_ = json.Unmarshal(v.Bundle, &m)
	ms := m["messageSignature"].(map[string]any)
	sig := ms["signature"].(string)
	ms["signature"] = strings.Replace(sig, sig[:4], "AAAA", 1)
	forged, _ := json.Marshal(m)
	if _, err := TimestampTime(Staging, forged, doc); err == nil {
		t.Error("a changed signature verified")
	}
	if _, err := TimestampTime(Staging, json.RawMessage(`{}`), doc); err == nil {
		t.Error("an empty bundle verified")
	}
}

// A token outside the issuing authority's validFor is refused, even though
// its signature and chain are good.
func TestTimestampOutsideValidity(t *testing.T) {
	v := loadVector(t)
	pins, err := pinnedTSAs(Staging)
	if err != nil {
		t.Fatal(err)
	}
	at, err := timestampTime(pins, v.Bundle, []byte(v.Proposal))
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*tsaPin){
		"ended before":   func(p *tsaPin) { p.end = time.Unix(at-1, 0) },
		"starts after":   func(p *tsaPin) { p.start = time.Unix(at+1, 0) },
		"inside exactly": nil,
	} {
		cp := append([]tsaPin(nil), pins...)
		if mod != nil {
			for i := range cp {
				mod(&cp[i])
			}
		}
		_, err := timestampTime(cp, v.Bundle, []byte(v.Proposal))
		if (mod == nil) != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type pinnedTSAFile struct {
	TSAs []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"validFor"`
	} `json:"timestampAuthorities"`
}

func tsaSet(t *testing.T, data []byte) map[string]bool {
	t.Helper()
	var f pinnedTSAFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, a := range f.TSAs {
		k := a.ValidFor.Start + "|" + a.ValidFor.End
		for _, c := range a.CertChain.Certificates {
			k += "|" + string(c.RawBytes)
		}
		out[k] = true
	}
	return out
}

// The embedded staging root's timestamp authorities are those the votes
// site's tests and the vault's release configuration pin.
func TestStagingRootAgreesWithSiteAndVault(t *testing.T) {
	mine, err := trustedRoots.ReadFile("trust/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	want := tsaSet(t, mine)
	if len(want) == 0 {
		t.Fatal("no timestamp authorities")
	}
	for _, f := range []string{"testdata/site_staging_trusted_root.json", "testdata/vault_staging_timestamp_authorities.json"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got := tsaSet(t, data)
		if len(got) != len(want) {
			t.Fatalf("%s: %d authorities, want %d", f, len(got), len(want))
		}
		for k := range want {
			if !got[k] {
				t.Errorf("%s lacks an authority of the embedded root", f)
			}
		}
	}
}
