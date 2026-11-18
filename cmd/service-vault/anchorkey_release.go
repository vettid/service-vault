//go:build !devsigner

package main

import (
	"errors"

	"github.com/vettid/service-vault/internal/keystore"
)

// devSigner reports a devsigner build.
const devSigner = false

// createAnchorKey refuses: a release build never makes an anchor key (key
// protection, GC #7406 §7 step 1). It opens one that exists, until the
// marker says the key moved; a new deployment uses the signer.
func createAnchorKey() (*keystore.AnchorKey, error) {
	return nil, errors.New("no anchor key, and a release build doesn't create one: set SV_ANCHOR_SIGNER")
}
