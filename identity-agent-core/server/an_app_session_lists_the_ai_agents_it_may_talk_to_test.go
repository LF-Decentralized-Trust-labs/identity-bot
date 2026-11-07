package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/asset"
	"identity-agent-core/authprovider"
	"identity-agent-core/internal/coretypes"
)

// A person signed in at an app can read which AI agents they may talk to, and
// only that: the same people the talk routes let talk, and a few identifiers.

const listPath = "/api/app-session/agents"

func withTwoAIAgents(t *testing.T, w *anAppWorld) {
	t.Helper()
	for _, a := range []asset.Asset{
		{ID: "agent-1", DisplayName: "Orchestrator", AssetType: "ai_agent", PairwiseAID: "Eagent1", DelegatorAID: "Eorg",
			Capabilities: []string{"system.info.read"}, SigningIndex: 7,
			AgentConfig: &asset.AgentConfig{Role: "secret role", SystemPrompt: "secret prompt", Brain: asset.BrainConfig{Provider: "anthropic", Model: "m"}}},
		{ID: "agent-2", DisplayName: "Reviewer", AssetType: "ai_agent", PairwiseAID: "Eagent2", DelegatorAID: "Eorg"},
	} {
		if err := w.s.assetHandler.Store.UpsertAsset(a); err != nil {
			t.Fatal(err)
		}
	}
}

func listedBy(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		Agents []map[string]any `json:"agents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	return got.Agents
}

func TestAnAppSessionSeesTheAIAgentsItsPersonMayTalkToAndNothingMoreOfThem(t *testing.T) {
	w := anAppSessionWorld(t)
	withTwoAIAgents(t, w)
	rec := w.serve(w.request(http.MethodGet, listPath, "", chatOrigin, w.key))
	agents := listedBy(t, rec)
	if len(agents) != 2 {
		t.Fatalf("a signer sees %d AI agents, want the 2 of the organisation (and no app or website): %s", len(agents), rec.Body)
	}
	allowed := map[string]bool{"id": true, "name": true, "agent_aid": true, "person_aid": true, "organisation_aid": true}
	for _, a := range agents {
		for k := range a {
			if !allowed[k] {
				t.Errorf("the answer says %q of an AI agent, which is more than its name and who is behind it: %s", k, rec.Body)
			}
		}
	}
	if agents[0]["name"] != "Orchestrator" || agents[0]["agent_aid"] != "Eagent1" || agents[0]["organisation_aid"] != "Eorg" || agents[0]["id"] != "agent-1" {
		t.Fatalf("first AI agent = %v", agents[0])
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != chatOrigin {
		t.Fatalf("the app's own origin is not answered: %v", rec.Header())
	}
}

func TestAnAppSessionSeesNoAIAgentItsPersonMayNotTalkTo(t *testing.T) {
	w := anAppSessionWorld(t)
	withTwoAIAgents(t, w)
	if err := w.s.assetHandler.Store.UpsertEmployee(asset.Employee{PairwiseAID: "Ebob", Name: "Bob", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	// An employee may talk to none (agentmessage.PersonRef.MayTalkToAnAIAgent),
	// so is shown an empty list, not an error and not a partial one.
	w.token = "tok-bob"
	w.open("chat", coretypes.Signer{AID: "Ebob", Standing: "employee", Name: "Bob"}, time.Now().Add(time.Hour))
	rec := w.serve(w.request(http.MethodGet, listPath, "", chatOrigin, w.key))
	if agents := listedBy(t, rec); len(agents) != 0 || rec.Body.String() == "" {
		t.Fatalf("an employee sees %v, want an empty list", agents)
	}
	if got := rec.Body.String(); !json.Valid([]byte(got)) || !strings.Contains(got, `"agents":[]`) {
		t.Fatalf("an empty list must be [] and not null: %s", got)
	}
	// And a session the roster no longer stands behind sees nothing at all.
	w.token = "tok-gone"
	w.open("chat", coretypes.Signer{AID: "Egone", Standing: "signer"}, time.Now().Add(time.Hour))
	if rec := w.serve(w.request(http.MethodGet, listPath, "", chatOrigin, w.key)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a person who no longer stands = %d, want 401: %s", rec.Code, rec.Body)
	}
}

func TestTheListIsForAnAppSessionAndAnAppSessionStillReachesNoOtherRoute(t *testing.T) {
	w := anAppSessionWorld(t)
	withTwoAIAgents(t, w)
	w.s.MountExtraRoutes(func(r chi.Router) {
		r.Get("/mcp/agents", func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte(`{"agents":["everything"]}`)) })
		r.Get("/mcp/agents/{id}/machine", func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte(`machine`)) })
	})
	w.h = w.s.buildRouter()
	for _, p := range []string{"/api/mcp/agents", "/api/mcp/agents/agent-1/machine", "/api/employees", "/api/mcp/conversations/c1/export"} {
		if rec := w.serve(w.request(http.MethodGet, p, "", chatOrigin, w.key)); rec.Code != http.StatusForbidden {
			t.Errorf("GET %s by an app session = %d, want refused: %s", p, rec.Code, rec.Body)
		}
	}
	// The list takes a GET only: no other method on it is admitted.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := w.serve(w.request(m, listPath, `{}`, chatOrigin, w.key)); rec.Code < 400 {
			t.Errorf("%s %s by an app session = %d, want refused", m, listPath, rec.Code)
		}
	}
	// From another app's page, or with the token alone, it is refused as the talk routes are.
	if rec := w.serve(w.request(http.MethodGet, listPath, "", otherOrigin, w.key)); rec.Code != http.StatusForbidden {
		t.Errorf("from another app's origin = %d, want 403", rec.Code)
	}
	if rec := w.serve(w.request(http.MethodGet, listPath, "", chatOrigin, nil)); rec.Code != http.StatusUnauthorized {
		t.Errorf("a copied token with no key = %d, want 401", rec.Code)
	}
	// A caller with no session at all is not answered.
	bare := httptest.NewRequest(http.MethodGet, listPath, nil)
	bare.RemoteAddr = "203.0.113.9:51000"
	if rec := w.serve(bare); rec.Code < 400 {
		t.Errorf("no credentials = %d, want refused", rec.Code)
	}
}

func TestAControllersListOfAIAgentsIsUnchanged(t *testing.T) {
	resetSeenSignatures(t)
	cw := newControllerWorld(t)
	s := cw.s
	s.MountExtraRoutes(func(r chi.Router) {
		r.Get("/mcp/agents", func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte(`{"agents":["the whole roster"]}`)) })
	})
	h := s.buildRouter()
	target, err := s.whoThisIdentityAgentIs()
	if err != nil {
		t.Fatal(err)
	}
	// Before and after this route existed, a controller read the roster here.
	r := asThatMachineTo(t, target, cw.ctlAID, http.MethodGet, "/api/mcp/agents", "", cw.ctlSeed, authprovider.Level(""), time.Now())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"agents":["the whole roster"]}` {
		t.Fatalf("a controller's GET /api/mcp/agents = %d %s", rec.Code, rec.Body)
	}
	// The app session's list is not a way for a controller to the roster.
	r = asThatMachineTo(t, target, cw.ctlAID, http.MethodGet, listPath, "", cw.ctlSeed, authprovider.Level(""), time.Now())
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "everything") {
		t.Fatalf("a controller on the app session's list = %d, want 404 and no roster: %s", rec.Code, rec.Body)
	}
}
