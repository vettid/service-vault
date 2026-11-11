# Pinned Sigstore trusted roots

`production.json` and `staging.json` are each instance's Sigstore trusted
root (`dev.sigstore.trustedroot.v1.TrustedRoot`, protojson), fetched
through the instance's TUF repository with sigstore-go v1.3.0's embedded
TUF root and no local cache (the TUF metadata is verified by the client):
production from `tuf-repo-cdn.sigstore.dev`, staging from
`tuf-repo-cdn.sigstage.dev`. Only `timestampAuthorities` is read by this
service (anchor/tsa.go). To refresh a file, run the program below
in a scratch module that requires `github.com/sigstore/sigstore-go v1.3.0`
(`go run . production > production.json`, `go run . staging > staging.json`)
and review the diff of `timestampAuthorities` before committing.

```go
package main

import (
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	opts := tuf.DefaultOptions().WithDisableLocalCache()
	if os.Args[1] == "staging" {
		opts.Root, opts.RepositoryBaseURL = tuf.StagingRoot(), tuf.StagingMirror
	}
	tr, err := root.FetchTrustedRootWithOptions(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b, err := tr.MarshalJSON()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}
```

`../testdata` holds the staging timestamp authorities as the votes site's
tests and the vault's release configuration pin them; a test checks that
this staging root agrees with both.
