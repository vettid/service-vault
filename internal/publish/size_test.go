package publish

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/vettid/service-vault/internal/ballot"
	"github.com/vettid/service-vault/vote"
)

// siteMaxUpload is the votes site's MaxUpload (6 MiB less 64 KiB), the
// most a request to it may carry (another repository: GC #7325).
const siteMaxUpload = 6<<20 - 64<<10

// The largest upload the results can make fits the site: the largest
// results document the site takes (512 KiB) and bundle (64 KiB), a
// signature, and as many rows as ballot.SiteRowsUpload allows. A new
// field in the body, or another encoding, fails here.
func TestUploadBodyFitsSite(t *testing.T) {
	doc := bytes.Repeat([]byte{0xff}, 512<<10)
	bundle := json.RawMessage(`"` + string(bytes.Repeat([]byte{'a'}, 64<<10-2)) + `"`)
	rows := bytes.Repeat([]byte{0xff}, ballot.SiteRowsUpload/4*3)
	body, err := uploadBody(doc, make([]byte, vote.SigLen), bundle, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > siteMaxUpload {
		t.Fatalf("the largest upload is %d bytes, over the site's %d", len(body), siteMaxUpload)
	}
}
