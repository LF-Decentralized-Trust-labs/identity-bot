package server

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// The owner's management routes address an invite or an enrolment by the ID
// the list shows, never by the secret: a path is written to access logs, proxy
// logs and browser history. (A route the holder of a secret calls — redeeming
// an invite, reading what it is for — carries the code in its path by nature;
// those are public routes, and logRequests keeps the value out of the log.)
func TestNoOwnerRouteTakesASecretInItsPath(t *testing.T) {
	s := newAuthTestServer(t)
	s.DataDir = t.TempDir()
	if err := s.initAssetHandler(); err != nil {
		t.Fatal(err)
	}
	checked := map[string]bool{}
	err := chi.Walk(s.buildRouter(),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if classify(method, route) != accessOwner {
				return nil
			}
			checked[method+" "+route] = true
			for _, p := range []string{"{token}", "{secret}", "{code}"} {
				if strings.Contains(route, p) {
					t.Errorf("%s %s takes a secret in the path; address it by its listed ID", method, route)
				}
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	// The routes that withdraw an invite or an enrolment must be among those
	// walked, or this proves nothing about them.
	for _, want := range []string{
		"DELETE /api/employees/invites/{invite}",
		"DELETE /api/assets/{id}/invites/{invite}",
		"DELETE /api/enrolments/{enrolment}",
	} {
		if !checked[want] {
			t.Errorf("%s is not an owner route this agent serves", want)
		}
	}
}

func TestTheRequestLogNamesTheRouteNotTheSecretInThePath(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	r := chi.NewRouter()
	r.Use(logRequests)
	r.Get("/api/invites/{token}", func(w http.ResponseWriter, _ *http.Request) {})
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/invites/SECRET-CODE-123", nil))

	if strings.Contains(buf.String(), "SECRET-CODE-123") {
		t.Fatalf("the request log holds the secret: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "/api/invites/{token}") {
		t.Errorf("the request log should name the route: %s", buf.String())
	}
}

// The router itself must log by route: the logger test above proves the
// middleware, this proves it is the one in use.
func TestTheServersRouterLogsNoSecretFromAPath(t *testing.T) {
	s := newAuthTestServer(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	s.buildRouter().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/i/SECRET-CODE-456", nil))
	if buf.Len() == 0 {
		t.Fatal("the router logged nothing")
	}
	if strings.Contains(buf.String(), "SECRET-CODE-456") {
		t.Fatalf("the router's request log holds a secret from the path: %s", buf.String())
	}
}
