package server

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// aBrowserSession is a session the owner granted, as a browser carries it.
func aBrowserSession(t *testing.T, s *CoreServer) string {
	t.Helper()
	if s.BrowserSessions == nil {
		s.BrowserSessions = newBrowserSessions()
	}
	const secret = "a-secret-only-the-browser-has"
	id, code, _, err := s.BrowserSessions.newChallenge(hashSecret(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BrowserSessions.grant(code); err != nil {
		t.Fatal(err)
	}
	token, _, err := s.BrowserSessions.claim(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

var aRouteParameter = regexp.MustCompile(`\{[^}]+\}`)

// A browser session may do nothing a controller may not (ADR-050): every route
// closed to a controller, and every route closed to a session alone, is
// refused to a session through the real router, for the stated reason, before
// its handler runs. Fails for any route that a session reaches, which is how
// this list once fell 33 routes behind the controller's and a session could set
// which identity this agent is.
func TestABrowserSessionIsRefusedEverythingAControllerIs(t *testing.T) {
	s := newAuthTestServer(t)
	token := aBrowserSession(t, s)
	r := s.buildRouter()

	registered := map[string]bool{}
	if err := chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered[method+" "+route] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	tried := 0
	for route := range everySessionForbidden() {
		if !registered[route] {
			// Not mounted on this server: it must be one named as mounted only
			// elsewhere, whose refusal is the same gate (requiresTheKeyItself,
			// tested for every route below).
			if _, known := conditionallyMounted[route]; !known {
				t.Errorf("%s is refused to a session but mounted nowhere this test can try it", route)
			}
			continue
		}
		method, pattern, _ := strings.Cut(route, " ")
		path := aRouteParameter.ReplaceAllString(pattern, "x")
		req := remote(method, path, `{}`)
		req.Header.Set(headerSessionToken, "Bearer "+token)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		tried++
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "a browser session cannot do this") {
			t.Errorf("%s: a browser session got %d %s", route, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
	if want := len(everySessionForbidden()) - len(conditionallyMounted); tried != want {
		t.Fatalf("%d refused routes were tried through the router, want %d", tried, want)
	}

	// And it is a working session: an ordinary read goes through the gate.
	req := remote(http.MethodGet, "/api/contacts", "")
	req.Header.Set(headerSessionToken, "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "a browser session cannot do this") || rec.Code == http.StatusForbidden {
		t.Fatalf("the session itself is refused, so the test proves nothing: %d %s", rec.Code, rec.Body.String())
	}
}

// The structural rule, for every route at once: nothing a controller is
// refused is open to a session.
func TestNothingClosedToAControllerIsOpenToASession(t *testing.T) {
	for route := range controllerOwnerOnly {
		method, pattern, _ := strings.Cut(route, " ")
		if _, forbidden := requiresTheKeyItself(method, pattern); !forbidden {
			t.Errorf("%s is closed to a controller and open to a browser session", route)
		}
	}
}
