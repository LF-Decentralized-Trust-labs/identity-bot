package server

import (
	"net/http/httptest"
	"strings"
	"testing"

	"net/http"

	"github.com/go-chi/chi/v5"
)

// The core's routes at the root that take an identifier (/{aid}/...) answer
// a first segment that is not one with a refusal and nothing else, even to
// the owner. That is the premise on which an add-on may own a path such as
// /apps (identifierRoutes).
func TestTheIdentityRoutesAnswerOnlyIdentifiers(t *testing.T) {
	s, _ := grantWorld(t)
	if err := s.initLoginHandler(); err != nil {
		t.Fatal(err)
	}
	if err := s.initOIDCHandler(); err != nil {
		t.Fatal(err)
	}
	router := s.buildRouter("")
	var routes []string
	chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, identifierRoutes) {
			routes = append(routes, method+" "+route)
		}
		return nil
	})
	if len(routes) < 7 {
		t.Fatalf("found only %v under %s; the OIDC routes are not mounted", routes, identifierRoutes)
	}
	for _, rt := range routes {
		method, pattern, _ := strings.Cut(rt, " ")
		for _, word := range []string{"apps", "login", "EABC"} {
			path := strings.Replace(pattern, "{aid}", word, 1)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, local(method, path, ""))
			if w.Code < 400 {
				t.Errorf("%s %s answered %d for a segment that is not an identifier", method, path, w.Code)
			}
		}
	}
}

// An OIDC issuer named by an identifier is served even before this Identity
// Agent holds a relationship under it: an OIDC client is configured with its
// issuer before its first sign-in. A path that is not an identifier is not
// an issuer.
func TestAnOIDCIssuerIsAnIdentifier(t *testing.T) {
	s, _ := grantWorld(t)
	if err := s.initLoginHandler(); err != nil {
		t.Fatal(err)
	}
	if err := s.initOIDCHandler(); err != nil {
		t.Fatal(err)
	}
	router := s.buildRouter("")
	discover := func(issuer string) int {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, local("GET", "/"+issuer+"/.well-known/openid-configuration", ""))
		return w.Code
	}
	if code := discover("login"); code != http.StatusNotFound {
		t.Errorf("discovery for a word answered %d", code)
	}
	if code := discover("EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"); code != http.StatusOK {
		t.Errorf("discovery for an identifier answered %d", code)
	}
	held := s.thisIdentityAgentsIdentifier()
	if code := discover(held); code != http.StatusOK {
		t.Errorf("discovery for this Identity Agent's own identifier %s answered %d", held, code)
	}
}
