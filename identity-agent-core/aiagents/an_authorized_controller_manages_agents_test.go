package aiagents

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An authorized controller does the application's work (ADR-044). The AI-agent
// application operations therefore no longer re-check the owner inside the handler
// — the router-wide authorize gate decides who may reach them, and it admits the
// owner's authorized controller the same way it admits the owner. These tests pin
// that the application handlers no longer owner-gate: a request that is not the
// owner gets past the owner question to the real work. (The capability registry's
// handlers are tested with the sandboxed-apps add-on, and that the gate itself
// admits a controller to these non-closed routes is covered by the
// controller-reachability tests next door.)

func TestProvisionAgentNoLongerOwnerGatedInHandler(t *testing.T) {
	s := helpers.NewAuthTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/mcp/agents",
		strings.NewReader(`{"name":"x","capabilities":["infra.zone.list"]}`))
	rec := httptest.NewRecorder()

	of(s).handleProvisionAgent(rec, req)

	// With the owner-only re-check gone, a non-owner request is no longer refused
	// in the handler; it reaches the real work (here a 503, since this bare server
	// has no asset handler) — anything but the owner-only 403 that used to lock out
	// the controller the router admits.
	if rec.Code == http.StatusForbidden {
		t.Fatalf("provisioning still returns 403 from the handler, so it is re-gating "+
			"owner-only and would refuse the controller the router admits; body: %s",
			rec.Body.String())
	}
}

// Re-issuing a grant is where an agent's ceiling can be widened after it exists,
// so a browser session is held to the same bar as for provisioning and minting:
// whatever it changed would outlive the session that changed it.
func TestABrowserSessionCannotReissueAnAgentsGrant(t *testing.T) {
	for _, route := range []string{
		"POST /api/mcp/agents",
		"POST /api/mcp/tokens",
		"PUT /api/mcp/agents/{id}/capabilities",
	} {
		method, pattern, _ := strings.Cut(route, " ")
		if _, forbidden := helpers.RequiresTheKeyItself(method, pattern); !forbidden {
			t.Fatalf("a browser session can reach %s, and what it changes there outlives it", route)
		}
	}
}
