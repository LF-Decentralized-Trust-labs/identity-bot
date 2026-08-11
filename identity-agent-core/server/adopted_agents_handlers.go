package server

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/store"
)

// Listing the machines this identity has adopted.
//
// The question behind this endpoint is "what do I own", and it is asked by the
// screen a person opens to answer it. Before this the answer could not be
// given: adoption issued a delegation, returned it to whoever asked, and wrote
// nothing down, so the list was empty however many machines had been adopted.
//
// Owner-only, by the router's default. What an identity owns is not something
// a counterparty is entitled to enumerate — it is a map of somebody's
// infrastructure, and publishing it would say where their agent lives, how many
// machines they run, and which of them are sealed.

// handleListAdoptedAgents answers with the machines this identity has adopted.
func (s *CoreServer) handleListAdoptedAgents(w http.ResponseWriter, r *http.Request) {
	agents, err := s.DataStore.ListAdoptedAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the agent list", err.Error())
		return
	}
	// An empty list is an answer, not an absence — somebody who has adopted
	// nothing should see "no machines yet" rather than an error, and the two
	// must not look the same to the caller.
	if agents == nil {
		agents = []store.AdoptedAgent{}
	}
	writeJSONResponse(w, map[string]interface{}{
		"agents": agents,
		"count":  len(agents),
	})
}

// handleForgetAdoptedAgent stops listing a machine.
//
// It does NOT revoke the delegation, and the response says so rather than
// leaving the caller to assume. The delegation is in a published key event log
// and the machine can still sign as what it was made; this only removes it from
// its owner's list. Letting somebody believe deleting a row had taken a
// machine's authority away would be the most dangerous kind of convenience.
func (s *CoreServer) handleForgetAdoptedAgent(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	if aid == "" {
		writeError(w, http.StatusBadRequest, "Missing agent", "name the agent to forget")
		return
	}
	if err := s.DataStore.ForgetAdoptedAgent(aid); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not forget the agent", err.Error())
		return
	}
	writeJSONResponse(w, map[string]interface{}{
		"ok": true,
		"note": "this agent is no longer listed here. Its delegation is unchanged — it was " +
			"issued in a key event log that has already been published, and it can still sign " +
			"as what it was made. Revoking that is a separate act.",
	})
}

// handleRenameAdoptedAgent gives a machine a name its owner chose.
func (s *CoreServer) handleRenameAdoptedAgent(w http.ResponseWriter, r *http.Request) {
	aid := chi.URLParam(r, "aid")
	var req struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || aid == "" {
		writeError(w, http.StatusBadRequest, "Missing label", `send {"label": "…"}`)
		return
	}
	agents, err := s.DataStore.ListAdoptedAgents()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read the agent list", err.Error())
		return
	}
	for _, a := range agents {
		if a.AID == aid {
			a.Label = req.Label
			if err := s.DataStore.SaveAdoptedAgent(a); err != nil {
				writeError(w, http.StatusInternalServerError, "Could not rename", err.Error())
				return
			}
			writeJSONResponse(w, map[string]interface{}{"ok": true, "aid": aid, "label": req.Label})
			return
		}
	}
	writeError(w, http.StatusNotFound, "No such agent",
		"this identity has not adopted an agent with that identifier")
}
