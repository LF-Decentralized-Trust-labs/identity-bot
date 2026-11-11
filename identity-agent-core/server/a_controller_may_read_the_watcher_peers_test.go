package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The owner reads the list of contacts the watcher asks from any of their own
// apps, so a paired controller may read it; choosing the list stays owner-only.
func TestAControllerReadsTheWatcherPeersButCannotChangeThem(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	r := s.buildRouter()

	w := httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "GET", "/api/watcher/peers", "", seed, "", time.Now()))
	if w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("a paired controller was refused the read: %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, asThatMachine(t, aid, "PUT", "/api/watcher/peers", `{"aids":[]}`, seed, "", time.Now().Add(-time.Second)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("a paired controller changed the list: %d %s", w.Code, w.Body.String())
	}
}
