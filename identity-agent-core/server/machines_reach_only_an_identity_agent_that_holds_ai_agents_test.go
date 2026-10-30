package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// An Identity Agent that holds no AI agent answers none of the routes an AI
// agent's body calls; the moment it holds one, they answer again. The routes a
// person uses to make the first AI agent are not affected.
func TestMachinesReachOnlyAnIdentityAgentThatHoldsAIAgents(t *testing.T) {
	s, agentID := bodyWorld(t)
	rebuildRouter(s)

	answer := func(method, path string) (int, string) {
		rec := httptest.NewRecorder()
		s.router.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader("{}")))
		return rec.Code, rec.Body.String()
	}
	// A handler may itself refuse (an unknown machine), so "the route is not
	// there" is judged by answering exactly as a route that was never mounted.
	absentCode, absent := answer("GET", "/api/agent-host/no-such-route")
	missing := func(method, path string) bool {
		code, body := answer(method, path)
		return code == absentCode && body == absent
	}
	// Every route a body calls is declared public, so the declarations are the
	// list: a body route added later is covered without editing this test.
	var bodyRoutes [][2]string
	for key := range everyPublicRoute() {
		method, path, _ := strings.Cut(key, " ")
		if strings.HasPrefix(path, bodyRoutePrefix) {
			path = strings.NewReplacer("{rid}", "x", "{cid}", "x").Replace(path)
			bodyRoutes = append(bodyRoutes, [2]string{method, path})
		}
	}
	if len(bodyRoutes) < 16 {
		t.Fatalf("found %d body routes among the public routes, want all 16", len(bodyRoutes))
	}

	for _, rt := range bodyRoutes {
		if missing(rt[0], rt[1]) {
			t.Fatalf("%s %s: not there while this Identity Agent holds an AI agent", rt[0], rt[1])
		}
	}

	agent, _ := s.assetHandler.Store.GetAsset(agentID)
	if err := s.assetHandler.Store.DeleteAsset(agentID); err != nil {
		t.Fatal(err)
	}
	for _, rt := range bodyRoutes {
		if !missing(rt[0], rt[1]) {
			t.Fatalf("%s %s: answered with no AI agent held; want it to answer as if not there", rt[0], rt[1])
		}
	}
	// A person's routes for making the first AI agent still exist.
	for _, rt := range [][2]string{
		{"GET", "/api/mcp/brain-sign-in/choices"},
		{"GET", "/api/github"},
		{"POST", "/api/mcp/agents"},
	} {
		if missing(rt[0], rt[1]) {
			t.Fatalf("%s %s: not there with no AI agent held; a person needs it to make one", rt[0], rt[1])
		}
	}

	if err := s.assetHandler.Store.UpsertAsset(agent); err != nil {
		t.Fatal(err)
	}
	if missing("POST", "/api/agent-host/enrol") {
		t.Fatalf("enrol: not there after an AI agent is held again")
	}
}
