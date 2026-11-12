//go:build devsigner

package main

import "github.com/vettid/service-vault/internal/keystore"

// devSigner reports a devsigner build: local development and tests only.
const devSigner = true

// createAnchorKey makes a fresh anchor key held in memory, sealed in the
// table: devsigner builds only, never a release (GC #7406 §7 step 1).
func createAnchorKey() (*keystore.AnchorKey, error) { return keystore.NewAnchorKey() }
