package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/sandbox"
)

// The gate decides what a controller may reach, and a handler does not decide
// it again.
//
// The gate opens every owner-class route to an authorised controller except
// the owner-only list (ADR-050). A handler that then asks "is this the owner?"
// closes the route again, silently: the org app on a controller was refused GET
// /api/vault/credentials with "credential management is for the owner of this
// agent" although storing and removing a service key is open to a controller by
// decision. Nothing reported the disagreement, because each half was right by
// its own reading.
//
// So this walks the real router and sends every owner-class route a request
// signed by an authorised controller at the default score. The bodies are
// empty and the services absent, so most handlers stop at their first
// validation step — which is after an ownership check, so a handler that still
// has one is caught.
//
//   - A route on the owner-only list is refused, at the gate, as owner-only.
//   - Every other route is not refused at all. A 403 there is a handler
//     re-closing what the gate opened.
func TestHandlersDoNotRecloseWhatTheGateOpenedToAController(t *testing.T) {
	s := newAuthTestServer(t)
	aid, seed := anAuthorisedMachine(t, s, GradeEnrolled)
	router := s.buildRouter("")

	param := regexp.MustCompile(`\{[^}]*\}`)
	checked := 0
	err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if classify(method, route) != accessOwner {
			return nil
		}
		// A wildcard route is the web UI's fallthrough, not an action.
		if strings.Contains(route, "*") {
			return nil
		}
		path := param.ReplaceAllString(route, "x")
		checked++

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req := asThatMachine(t, aid, method, path, "", seed, "", time.Time{}).WithContext(ctx)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var body struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)

		if _, ownerOnly := isOwnerOnly(method, route); ownerOnly {
			if w.Code != http.StatusForbidden || body.Reason != reasonOwnerOnly {
				t.Errorf("%s %s is owner-only, but a controller got %d %s",
					method, route, w.Code, strings.TrimSpace(w.Body.String()))
			}
			return nil
		}
		if w.Code == http.StatusForbidden {
			t.Errorf("%s %s is open to a controller by ADR-050, but was refused: %s — "+
				"a handler re-checked ownership after the gate admitted the controller",
				method, route, strings.TrimSpace(w.Body.String()))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the router: %v", err)
	}
	if checked == 0 {
		t.Fatal("no owner-class routes found, so this test proves nothing")
	}
}

// The helper every such handler now uses answers yes for the two callers the
// gate admits as acting for the owner, and no for the two it admits as
// somebody else: a browser session and a caller holding a scoped token.
func TestOwnerOrItsControllerAdmitsNobodyElse(t *testing.T) {
	s := newAuthTestServer(t)

	if !s.isOwnerOrItsController(local("GET", "/api/vault/credentials", "")) {
		t.Error("the owner at this computer was not recognised")
	}
	admitted := remote("GET", "/api/vault/credentials", "")
	admitted = admitted.WithContext(context.WithValue(admitted.Context(), theGateAdmittedTheOwnerKey{}, ownerSigned))
	if !s.isOwnerOrItsController(admitted) {
		t.Error("an owner the gate admitted by signature was not recognised")
	}
	ctrl := remote("GET", "/api/vault/credentials", "")
	ctrl = ctrl.WithContext(context.WithValue(ctrl.Context(), controllerContextKey{}, ControllerGrant{ControllerAID: "Bcontroller"}))
	if !s.isOwnerOrItsController(ctrl) {
		t.Error("a controller the gate admitted was not recognised")
	}

	session := remote("GET", "/api/vault/credentials", "")
	session.Header.Set("Authorization", "Bearer some-browser-session")
	if s.isOwnerOrItsController(session) {
		t.Error("a browser session was treated as the owner or its controller")
	}
	scoped := withResolvedCaller(remote("GET", "/api/vault/credentials", ""), sandbox.CallerContext{CallerAID: "an-ai-agent", Scopes: []string{"vault.read"}, Remote: true})
	if s.isOwnerOrItsController(scoped) {
		t.Error("a caller holding a scoped token was treated as the owner or its controller")
	}
	if s.isOwnerOrItsController(remote("GET", "/api/vault/credentials", "")) {
		t.Error("a stranger was treated as the owner or its controller")
	}
}
