package server

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A request signed under a key state of the owner's that is not the one in
// force here is told so, distinctly from a forgery: 401 stale_key_state, so
// the app reads the key state again. One that names the key state in force and
// does not verify is refused as it always was.
func TestAStaleOwnerSignatureIsSaidToBeStale(t *testing.T) {
	s := newAuthTestServer(t)
	_, aid := sealTestOwner(t, s)
	old := make([]byte, ed25519.SeedSize)
	for i := range old {
		old[i] = byte(90 + i)
	}
	r := s.buildRouter("")

	stale := signed(t, "GET", "/api/profile", "", old, time.Now())
	stale.Header.Set(headerOwnerKeyState, "2.EAnEarlierRotationOfTheOwner")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, stale)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "stale_key_state") {
		t.Fatalf("a request signed under an earlier key state was answered %d %s", w.Code, w.Body.String())
	}

	resetSeenSignatures(t)
	current := signed(t, "GET", "/api/profile", "", old, time.Now())
	current.Header.Set(headerOwnerKeyState, "0."+aid)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, current)
	if w.Code != http.StatusForbidden {
		t.Fatalf("a bad signature naming the key state in force was answered %d", w.Code)
	}
}
