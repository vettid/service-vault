//go:build devsigner

package main

import (
	"context"
	"testing"
)

// A devsigner build makes an anchor key when none is stored (local
// development and tests).
func TestSetupAnchorNoKeyDevsigner(t *testing.T) {
	blobs := newCountingBlobs()
	as, err := setupAnchor(context.Background(), anchorCfg(""), nil, &fakeSSM{}, plainKMS{}, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if blobs.anchorCreates != 1 || len(as.spki) == 0 {
		t.Fatalf("creates %d", blobs.anchorCreates)
	}
}
