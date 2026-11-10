package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// A sign-in begun before collector secrets existed has nobody to show the
// refusal to: whoever holds the token (it is in the QR code) would read it. It
// is shown on neither status route.
func TestARefusalOfASessionWithNoCollectorSecretIsShownToNobody(t *testing.T) {
	const token = "session-unbound"
	s := &CoreServer{
		localOwnerSecret: testOwnerSecret,
		challengeStatus:  map[string]map[string]interface{}{token: {"status": "pending"}},
	}
	s.recordRefusal(token, refusalCredentialNotAllowed)

	for _, path := range []string{"/api/login/session/the-website/" + token, "/api/login/challenge/" + token + "/status"} {
		r := chi.NewRouter()
		s.mountLoginWidgetRoutes(r)
		r.Get("/api/login/challenge/{token}/status", s.handleChallengeStatus)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, w.Code)
		}
		var got map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		if _, there := got["last_refusal"]; there {
			t.Errorf("%s: an unbound session showed the refusal: %v", path, got)
		}
	}
}
