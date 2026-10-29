package ballot

import (
	"crypto/sha256"
	"sort"
)

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// sortTags sorts tags bytewise (BALLOT-PROTOCOL §2).
func sortTags(tags [][]byte) {
	sort.Slice(tags, func(i, j int) bool { return string(tags[i]) < string(tags[j]) })
}
