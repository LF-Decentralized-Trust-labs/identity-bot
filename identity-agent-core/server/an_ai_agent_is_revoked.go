package server

import (
	"errors"
	"log"
	"net/http"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/sandbox"

	"github.com/go-chi/chi/v5"
)

// An AI agent is revoked: from then on it can do nothing, and nothing makes
// it able to again.
//
// Revoking marks the AI agent revoked on its record first, so no change made
// meanwhile can grant it anything again, then withdraws every grant it holds,
// ends every machine that speaks for it, and refuses any machine still waiting
// to. A machine a provider made for it is destroyed (ADR-055). Its identity and
// its record stay, so what it did can still be checked; to use an AI agent
// again, a person creates a new one.

// errAgentRevoked is a change asked of an AI agent that was revoked.
var errAgentRevoked = errors.New("this AI agent was revoked, so it is never granted anything again; create a new AI agent instead")

func (s *CoreServer) handleRevokeAIAgent(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	unlock := lockAgentGrant(id)
	defer unlock()
	a, ok := s.aiAgentAsset(id)
	if !ok {
		jsonError(w, "AI agent not found", http.StatusNotFound)
		return
	}
	by := whoDecided(r)
	// Marked first: the grants below are withdrawn one by one, and a change to
	// what it may do arriving meanwhile must not issue it a new one.
	if a.RevokedAt == nil {
		now := time.Now().UTC()
		a.RevokedAt, a.RevokedBy, a.UpdatedAt = &now, by, now
		if err := s.assetHandler.Store.UpsertAsset(a); err != nil {
			jsonError(w, "the AI agent could not be marked revoked, so nothing was changed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if s.SandboxManager != nil {
			s.SandboxManager.RecordGovernanceEvent(sandbox.CallerContext{
				CallerAID: a.PairwiseAID, DelegationChain: []string{a.PairwiseAID, a.DelegatorAID},
				Reason: "revoked by " + by,
			}, "agent.revoked", "ok")
		}
		log.Printf("[mcp] AI agent %s (%s) revoked by %s", a.PairwiseAID, a.DisplayName, by)
	}
	// Every grant it holds, each written to the registry. One that cannot be
	// written yet is reported; asking again retries it. The AI agent is already
	// refused everything here.
	grants, failed := 0, 0
	for _, g := range s.grantsHeldBy(a.PairwiseAID, true) {
		rec, _ := s.DataStore.GetCredential(g.SAID)
		if rec == nil {
			continue
		}
		if _, _, err := s.withdrawCredential(rec); err != nil {
			log.Printf("[mcp] AI agent %s: grant %s could not be withdrawn yet: %v", a.PairwiseAID, g.SAID, err)
			failed++
			continue
		}
		grants++
	}
	// Every machine that speaks for it stops; one still waiting is refused.
	ended := 0
	for _, b := range s.bodies().ForAgent(a.ID) {
		switch b.State {
		case agentbody.StateActive:
			eb, err := s.endBinding(a, b, "its AI agent was revoked by "+by)
			if err != nil {
				log.Printf("[mcp] AI agent %s: machine %s could not be ended: %v", a.PairwiseAID, b.ID, err)
				failed++
				continue
			}
			s.withdrawBodyCredential(eb)
			ended++
		case agentbody.StatePending:
			if rejected, err := s.bodies().Decide(b.ID, a.ID, agentbody.StateRejected, by, "", time.Now()); err == nil {
				s.recordBodyEvent(a, rejected, "rejected", "denied", "its AI agent was revoked by "+by)
			}
		}
	}
	// Machines a provider is still making for it.
	s.sweepMachinesSoon("an AI agent was revoked")
	out := map[string]any{
		"asset_id": a.ID, "status": "revoked", "revoked_at": a.RevokedAt, "revoked_by": a.RevokedBy,
		"grants_withdrawn": grants, "machines_ended": ended,
	}
	if failed > 0 {
		out["incomplete"] = "some of it could not be written yet; revoke again to retry"
		writeJSONStatus(w, http.StatusAccepted, out)
		return
	}
	writeJSONStatus(w, http.StatusOK, out)
}
