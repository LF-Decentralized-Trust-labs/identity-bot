package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A request this middleware cannot resolve is refused, not served.
//
// chi dispatches on RawPath when a URL carries escaped characters and on Path
// otherwise. The gate matched only on Path, so a caller who could make the two
// disagree — an escaped separator was enough — reached the handler with NO
// authorisation check at all. The comment said the router would answer 404. It
// did not; it served the route.
//
// Proven before the fix, unauthenticated and remote:
//
//	DELETE /api/backup/destinations/a%2Fb  -> 204
//	DELETE /api/contacts/a%2Fb             -> 500 (the handler ran)
//	POST   /api/credentials/a%2Fb/revoke   -> 500 (the handler ran)
//
// This was already true before controllers existed. It matters more now,
// because the same matched pattern is what decides whether an action is raised
// — so every gate keyed on a pattern with a {param} had the same way past it.
func TestAnEscapedPathCannotSkipTheGate(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	for _, c := range []struct{ method, path string }{
		{"DELETE", "/api/backup/destinations/a%2Fb"},
		{"DELETE", "/api/contacts/a%2Fb"},
		{"POST", "/api/credentials/a%2Fb/revoke"},
		{"POST", "/api/rotation/a%2Fb"},
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, remote(c.method, c.path, ""))
		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Errorf("%s %s: got %d — an unauthenticated caller reached a handler by "+
				"escaping a separator", c.method, c.path, w.Code)
		}
	}
}

// The ordinary paths still resolve, or the fix above would be a denial of
// service wearing a security fix's clothes.
func TestOrdinaryPathsStillResolveToTheirRoute(t *testing.T) {
	s := newAuthTestServer(t)
	r := s.buildRouter("")

	// Public, so a 403 here would mean the gate stopped classifying it.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, remote("GET", "/api/attestation", ""))
	if w.Code == http.StatusForbidden {
		t.Errorf("a public route was refused: %s", w.Body.String())
	}

	// Owner-only with a parameter, which must still be REFUSED rather than
	// unresolvable — the distinction the fix turns on.
	w = httptest.NewRecorder()
	r.ServeHTTP(w, remote("DELETE", "/api/contacts/BSomebody", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("an owner route with a parameter: got %d, want 403", w.Code)
	}
}
