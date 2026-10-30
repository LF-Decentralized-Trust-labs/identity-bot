package aiagents

import (
	"identity-agent-core/asset"
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Every owner-only entry and every per-action minimum names a route an
// Identity Agent with every add-on in this module serves: this package
// includes the sandboxed-apps add-on as well as its own, and the core's rules
// name routes of both. The maps are keyed by hand-typed strings, and
// a key that matches no route guards nothing while looking exactly like
// protection.
func TestEveryControllerRuleNamesARouteThisAgentServes(t *testing.T) {
	s := fixtures.NewAuthTestServer(t)
	// The employee and signer routes are mounted only with an asset handler.
	ah, err := asset.NewHandler(s.DataDir, nil)
	if err != nil {
		t.Fatalf("asset handler: %v", err)
	}
	fixtures.UseAssetHandler(s, ah)

	served := map[string]bool{}
	if werr := chi.Walk(hostOf(s).BuildRouter(""),
		func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			served[method+" "+route] = true
			return nil
		}); werr != nil {
		t.Fatalf("walking the router: %v", werr)
	}
	for route := range helpers.ControllerOwnerOnly() {
		if !served[route] {
			t.Errorf("%s is owner-only but this Identity Agent serves no such route", route)
		}
	}
	for route := range helpers.ControllerMinimumScore() {
		if !served[route] {
			t.Errorf("%s has a minimum score but this Identity Agent serves no such route", route)
		}
	}
}
