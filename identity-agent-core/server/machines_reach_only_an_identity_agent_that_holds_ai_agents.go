package server

import (
	"net/http"
	"strings"
)

// The routes an AI agent's body calls (/api/agent-host/...) are public: a
// machine reaches them before anybody trusts it, and each handler admits only
// a request signed by a live body. An Identity Agent that holds no AI agent
// has no body that could sign one, so on that Identity Agent every one of
// those routes can only ever refuse. Until the first AI agent is made they
// give the same refusal as an /api route that does not exist.
//
// That hides nothing a reader of this source cannot see, and a bare OPTIONS
// request is answered by the router before any middleware runs, so it still
// tells a mounted route from an unknown one. What it removes is every handler
// on these routes from an Identity Agent that has no use for them.
//
// This is decided per request, not when the router is built, because the
// first AI agent is made while the server runs. The routes a person uses to
// make and manage AI agents are owner-only and stay as they are: making the
// first AI agent, and choosing its brain sign-in or GitHub access, comes
// before it exists.

// bodyRoutePrefix is where every route an AI agent's body calls lives.
const bodyRoutePrefix = "/api/agent-host/"

// holdsAnAIAgent reports whether this Identity Agent has made at least one AI
// agent. A revoked AI agent still counts: its record is kept, and a body of it
// is refused by the handler with the reason, not by a missing route.
func (s *CoreServer) holdsAnAIAgent() bool {
	if s.assetHandler == nil {
		return false
	}
	return s.assetHandler.Store.HasAssetOfType("ai_agent")
}

// onlyWhileHoldingAIAgents answers a body route on an Identity Agent that holds
// no AI agent as an unknown route, and passes everything else through.
func (s *CoreServer) onlyWhileHoldingAIAgents(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, bodyRoutePrefix) && !s.holdsAnAIAgent() {
			denyAuthorization(w, unknownRouteRefusal)
			return
		}
		next.ServeHTTP(w, r)
	})
}
