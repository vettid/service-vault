package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// While held (GC #9109), /health answers 200 and every other request,
// /v1 routes and a POST to /health included, 503 identity_key_mismatch.
func TestHeldHandler(t *testing.T) {
	h := heldHandler()
	for _, tc := range []struct {
		method, path string
		code         int
		body         string
	}{
		{"GET", "/health", 200, `"status":"held"`},
		{"POST", "/health", 503, `"error":"identity_key_mismatch"`},
		{"POST", "/v1/invites", 503, `"error":"identity_key_mismatch"`},
		{"GET", "/v1/approvals/x", 503, `"error":"identity_key_mismatch"`},
		{"GET", "/v1/anchor-key", 503, `"error":"identity_key_mismatch"`},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.code || !strings.Contains(rec.Body.String(), tc.body) || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, rec.Code, rec.Body)
		}
	}
}
