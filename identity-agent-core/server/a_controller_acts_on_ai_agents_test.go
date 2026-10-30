package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/buildmode"
)

// What a controller does to AI agents passes the one check, and is recorded against it.

// A controller with nothing vouched for it creates an AI agent in a production
// build. Before the one check this was refused: creating an AI agent was raised
// to a named level nothing could produce, and only a development build stood in
// for the missing measurement.
func TestAControllerCreatesAnAIAgentWithNothingVouchedInAProductionBuild(t *testing.T) {
	if buildmode.IsDev() {
		t.Skip("this proves the production build; run without the development flag")
	}
	w := newTalkWorld(t)
	body := `{"name":"Clerk","capabilities":["` + capabilityMessageAgent + `"]}`
	req := asThatMachineTo(t, w.s.thisIdentityAgentsIdentifier(), w.ctlAID, "POST", "/api/mcp/agents",
		body, w.ctlSeed, "", time.Time{})
	rec := httptest.NewRecorder()
	w.s.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("a controller with the placeholder score could not create an AI agent: %d %s",
			rec.Code, rec.Body.String())
	}
}

// What a controller makes is recorded against it, because it keeps working
// after the controller's grant is revoked or expires: an AI agent and its
// token, a token minted on its own, and a member's approval.
func TestWhatAControllerMakesIsRecordedAgainstIt(t *testing.T) {
	w := newTalkWorld(t)
	me := w.s.thisIdentityAgentsIdentifier()
	send := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := asThatMachineTo(t, me, w.ctlAID, method, path, body, w.ctlSeed, "", time.Time{})
		rec := httptest.NewRecorder()
		w.s.router.ServeHTTP(rec, req)
		return rec
	}

	rec := send("POST", "/api/mcp/agents", `{"name":"Made by a machine","capabilities":["`+capabilityMessageAgent+`"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("provisioning: %d %s", rec.Code, rec.Body.String())
	}
	var made struct {
		AssetID string `json:"asset_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &made)
	if a, ok := w.s.assetHandler.Store.GetAsset(made.AssetID); !ok || a.MadeByController != w.ctlAID {
		t.Fatalf("the AI agent does not record the machine that made it: %+v", a)
	}

	rec = send("POST", "/api/mcp/tokens", `{"name":"machine-token","scopes":["`+capabilityMessageAgent+`"]}`)
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("minting: %d %s", rec.Code, rec.Body.String())
	}
	byName := map[string]string{}
	for _, tok := range w.s.loadMCPTokens() {
		byName[tok.Name] = tok.MadeByController
	}
	if byName["machine-token"] != w.ctlAID || byName["Made by a machine"] != w.ctlAID {
		t.Fatalf("a token does not record the machine that minted it: %v", byName)
	}

	if err := w.s.assetHandler.Store.UpsertEmployee(asset.Employee{
		PairwiseAID: "EMember", Name: "Sam", Role: "Staff", Status: "pending",
	}); err != nil {
		t.Fatal(err)
	}
	rec = send("POST", "/api/employees/EMember/approve", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("approving: %d %s", rec.Code, rec.Body.String())
	}
	if e, _ := w.s.assetHandler.Store.GetEmployee("EMember"); e.ApprovedByController != w.ctlAID {
		t.Fatalf("a member's approval does not record the machine that gave it: %+v", e)
	}
}

// Every action closed to a browser session has had a decision made about it
// for a controller too: owner-only, or named here as deliberately open with the
// reason. Adding a route to sessionForbidden and to neither fails here, which
// is the only thing that would catch it.
func TestEveryActionClosedToASessionWasDecidedForAControllerToo(t *testing.T) {
	// Closed to a session because what they make outlives the session; a
	// controller is hardware the owner authorised, and what it makes is
	// recorded against it (ADR-050).
	deliberatelyOpen := map[string]string{
		"POST /api/mcp/agents":                           "creating an AI agent is the application's work, recorded against the controller",
		"PATCH /api/mcp/agents/{id}":                     "configuring an AI agent is the application's work",
		"PUT /api/mcp/agents/{id}/brain-sign-in":         "signing an AI agent's brain in is the application's work (ADR-051)",
		"DELETE /api/mcp/agents/{id}/brain-sign-in":      "removing an AI agent's sign-in is the application's work (ADR-051)",
		"POST /api/mcp/brain-sign-in/test":               "checking a sign-in before it is kept is the application's work (ADR-052)",
		"POST /api/mcp/agents/{id}/brain-sign-in/test":   "checking a kept sign-in is the application's work (ADR-052)",
		"POST /api/mcp/brain-sign-in/models":             "listing a key's models to choose one is the application's work (ADR-052)",
		"POST /api/mcp/agents/{id}/brain-sign-in/models": "listing a kept key's models is the application's work (ADR-052)",
		"PUT /api/mcp/agents/{id}/brain":                 "choosing an AI agent's model is the application's work, recorded (ADR-052)",
		"PUT /api/github":                                "connecting the organisation's GitHub App is the application's work (ADR-054)",
		"DELETE /api/github":                             "disconnecting the organisation's GitHub App is the application's work (ADR-054)",
		"GET /api/github/repositories":                   "listing the App's repositories is the application's work (ADR-054)",
		"PUT /api/mcp/agents/{id}/github":                "granting an AI agent repositories is the application's work (ADR-054)",
		"PUT /api/mcp/agents/{id}/capabilities":          "setting an AI agent's capabilities is the application's work",
		"POST /api/mcp/agents/{id}/revoke":               "revoking an AI agent is the organisation's work, recorded against the machine that did it",
		"POST /api/mcp/agents/{id}/body-enrolment":       "an enrolment string is the first step of a body the person still approves",
		"POST /api/mcp/agents/{id}/bodies/{bid}/approve": "approving a body is recorded against the machine that decided",
		"POST /api/mcp/agents/{id}/bodies/{bid}/reject":  "rejecting a body grants nothing",
		"POST /api/mcp/tokens":                           "minting a token is the application's work, recorded against the controller",
		"POST /api/employees/{aid}/approve":              "approving a member is the organisation's work, recorded against the controller",
		"POST /api/employees/{aid}/revoke":               "revoking a member is the organisation's work",
		// A controller is where a person takes control of an AI agent's screen
		// from, judged by the one check as an action apart from watching.
		routeScreenControl: "taking control of an AI agent's screen is its own action in the one check, at the default unless raised (ADR-053)",
		routeScreenInput:   "clicks and keys on an AI agent's screen are their own action in the one check, at the default unless raised (ADR-053)",
		// The owner's own front end must be able to show them a recovery of
		// their identity is running; that is who the warning is for.
		"GET /api/recovery/sessions":      "the owner is told a recovery of their identity is running",
		"GET /api/recovery/sessions/{id}": "the owner is told about a recovery of their identity",
	}
	for route := range everySessionForbidden() {
		_, closed := controllerOwnerOnly[route]
		_, open := deliberatelyOpen[route]
		switch {
		case closed && open:
			t.Errorf("%s is both owner-only and named as open to a controller", route)
		case !closed && !open:
			t.Errorf("%s is closed to a browser session and has no decision for a controller: "+
				"make it owner-only, or name it here as deliberately open and say why", route)
		}
	}
	for route := range deliberatelyOpen {
		if _, ok := everySessionForbidden()[route]; !ok {
			t.Errorf("%s is named as deliberately open but is no longer closed to a session, "+
				"so this entry decides nothing", route)
		}
	}
}
