package server

import (
	"net/http"
	"sort"

	"identity-agent-core/agentmessage"
)

// An app session (ADR-066) can read which AI agents its person may talk to, so
// an app can show them before anyone speaks. The answer is decided by the rule
// the talk routes ask (agentmessage.PersonRef.MayTalkToAnAIAgent), for the
// person the session names, and says of each AI agent only its name, its own
// identifier, and the identifiers of the person and the organisation behind
// it. It carries nothing about the AI agent's brain, machine, capabilities or
// grant, which GET /api/mcp/agents (a controller's) goes on answering as it
// did.

// anAIAgentToTalkTo is one AI agent in that answer, and all that is said of it.
type anAIAgentToTalkTo struct {
	// ID is the AI agent's asset id: what the talk routes name it by.
	ID string `json:"id"`
	// Name is what the AI agent is called.
	Name string `json:"name"`
	// AgentAID is the AI agent's own identifier, which a message to it is
	// addressed to.
	AgentAID string `json:"agent_aid"`
	// PersonAID is the person behind it: the signer of the machine that made
	// it, else the organisation's owner. Empty where neither can be named.
	PersonAID string `json:"person_aid,omitempty"`
	// OrganisationAID is the organisation that delegated it.
	OrganisationAID string `json:"organisation_aid,omitempty"`
}

// handleAppSessionListsAgents answers GET /api/app-session/agents. Only a
// request the gate admitted on an app session is answered: a controller, the
// owner and anyone else have their own route to the roster, and are told there
// is no such list here.
func (s *CoreServer) handleAppSessionListsAgents(w http.ResponseWriter, r *http.Request) {
	asking, ok := TheAppSessionThatAsked(r)
	if !ok {
		// Not 403: the gate opens this path to a controller like any other
		// (ADR-050) and nothing here re-closes it. There is simply no such
		// list for a caller that is not a person at an app.
		writeError(w, http.StatusNotFound, "No such list",
			"this list is of a person signed in at an app; the roster of AI agents is read at /api/mcp/agents")
		return
	}
	if s.assetHandler == nil {
		writeError(w, http.StatusServiceUnavailable, "Could not read the AI agents", "the asset store is not available")
		return
	}
	person := agentmessage.PersonRef{AID: asking.Person.AID, Standing: asking.Person.Standing}
	out := []anAIAgentToTalkTo{}
	if person.MayTalkToAnAIAgent() {
		assets, err := s.assetHandler.Store.ListAssets()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Could not read the AI agents", err.Error())
			return
		}
		owner, _ := s.theOwner()
		for _, a := range assets {
			if a.AssetType != "ai_agent" {
				continue
			}
			behind := owner
			if a.MadeByController != "" {
				if g, had, err := s.controllers().Get(a.MadeByController); err == nil && had && g.Signer != "" {
					behind = g.Signer
				}
			}
			name := a.DisplayName
			if name == "" {
				name = a.ID
			}
			out = append(out, anAIAgentToTalkTo{
				ID: a.ID, Name: name, AgentAID: a.PairwiseAID, PersonAID: behind, OrganisationAID: a.DelegatorAID,
			})
		}
	}
	// The store holds assets unordered; the same roster is always answered in the same order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	writeJSON(w, map[string]interface{}{"agents": out})
}
