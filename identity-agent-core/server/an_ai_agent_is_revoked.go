package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/permission"

	"github.com/go-chi/chi/v5"
)

// An AI agent is revoked: from then on it can do nothing, and nothing makes
// it able to again (ADR-056).
//
// Revoking marks the AI agent revoked first, so no change made meanwhile can
// grant it anything again, then withdraws every grant it holds, ends every
// machine that speaks for it, and refuses any machine still waiting to. A
// machine a provider made for it is destroyed (ADR-055). Its identity and its
// record stay, so what it did can still be checked; to use an AI agent again,
// a person creates a new one.
//
// The mark is kept in a file of its own, never on the AI agent's record: a
// change to the record read before the revocation and written after it would
// otherwise carry the AI agent back to life. Nothing removes a mark.

// errAgentRevoked is a change asked of an AI agent that was revoked.
var errAgentRevoked = errors.New("this AI agent was revoked, so it is never granted anything again; create a new AI agent instead")

// revokedMark is when an AI agent was revoked, and by whom.
type revokedMark struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
}

// revokedAgentStore keeps the marks, by asset id, in one file.
type revokedAgentStore struct {
	mu   sync.Mutex
	path string
}

var revokedStoreOnce sync.Map

func (s *CoreServer) revokedAIAgents() *revokedAgentStore {
	dir, err := filepath.Abs(s.DataDir)
	if err != nil {
		dir = s.DataDir
	}
	v, _ := revokedStoreOnce.LoadOrStore(dir, &revokedAgentStore{path: filepath.Join(dir, "revoked_ai_agents.json")})
	return v.(*revokedAgentStore)
}

func (r *revokedAgentStore) load() (map[string]revokedMark, error) {
	m := map[string]revokedMark{}
	b, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("the record of revoked AI agents is unreadable: %w", err)
	}
	return m, nil
}

// Get says whether an AI agent was revoked. A record that cannot be read
// counts every AI agent as revoked: refusing is the safe mistake.
func (r *revokedAgentStore) Get(assetID string) (revokedMark, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, err := r.load()
	if err != nil {
		log.Printf("[mcp] %v; treating AI agent %s as revoked", err, assetID)
		return revokedMark{By: "unknown"}, true
	}
	mark, ok := m[assetID]
	return mark, ok
}

// Mark records an AI agent revoked, once; a second mark keeps the first.
func (r *revokedAgentStore) Mark(assetID, by string, now time.Time) (revokedMark, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, err := r.load()
	if err != nil {
		return revokedMark{}, false, err
	}
	if mark, ok := m[assetID]; ok {
		return mark, false, nil
	}
	mark := revokedMark{At: now.UTC(), By: by}
	m[assetID] = mark
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return revokedMark{}, false, err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return revokedMark{}, false, err
	}
	return mark, true, os.Rename(tmp, r.path)
}

// refuseIfRevoked answers a request about a revoked AI agent, and says so.
func (s *CoreServer) refuseIfRevoked(w http.ResponseWriter, assetID string) bool {
	if _, revoked := s.revokedAIAgents().Get(assetID); revoked {
		jsonError(w, errAgentRevoked.Error(), http.StatusConflict)
		return true
	}
	return false
}

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
	mark, first, err := s.revokedAIAgents().Mark(a.ID, by, time.Now())
	if err != nil {
		jsonError(w, "the AI agent could not be marked revoked, so nothing was changed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if first {
		if s.ActivityLog != nil {
			s.ActivityLog.RecordGovernanceEvent(permission.CallerContext{
				CallerAID: a.PairwiseAID, DelegationChain: []string{a.PairwiseAID, a.DelegatorAID},
				Reason: "revoked by " + by,
			}, "agent.revoked", "ok")
		}
		log.Printf("[mcp] AI agent %s (%s) revoked by %s", a.PairwiseAID, a.DisplayName, by)
	}
	// Every grant it holds, each written to the registry. One that cannot be
	// written yet is reported; asking again retries it. The AI agent is
	// already refused everything, by the mark.
	var incomplete []string
	grants := 0
	for _, g := range s.grantsHeldBy(a.PairwiseAID, true) {
		rec, _ := s.DataStore.GetCredential(g.SAID)
		if rec == nil {
			continue
		}
		if _, _, err := s.withdrawCredential(rec); err != nil {
			incomplete = append(incomplete, "a grant could not be withdrawn yet: "+err.Error())
			continue
		}
		grants++
	}
	// Every machine that speaks for it stops, and its credential is withdrawn;
	// one ended before whose withdrawal did not go through is tried again. One
	// still waiting is refused.
	ended := 0
	for _, b := range s.bodies().ForAgent(a.ID) {
		switch b.State {
		case agentbody.StateActive:
			eb, err := s.endBinding(a, b, "its AI agent was revoked by "+by)
			if err != nil {
				incomplete = append(incomplete, "a machine could not be ended: "+err.Error())
				continue
			}
			ended++
			if err := s.withdrawBodyCredential(eb); err != nil {
				incomplete = append(incomplete, "a machine's credential could not be withdrawn yet: "+err.Error())
			}
		case agentbody.StateRevoked:
			if err := s.withdrawBodyCredential(b); err != nil {
				incomplete = append(incomplete, "a machine's credential could not be withdrawn yet: "+err.Error())
			}
		case agentbody.StatePending:
			rejected, err := s.bodies().Decide(b.ID, a.ID, agentbody.StateRejected, by, "", time.Now())
			if err != nil {
				incomplete = append(incomplete, "a machine waiting for approval could not be refused: "+err.Error())
				continue
			}
			s.recordBodyEvent(a, rejected, "rejected", "denied", "its AI agent was revoked by "+by)
		}
	}
	// Machines a provider is still making for it.
	s.sweepMachinesSoon("an AI agent was revoked")
	out := map[string]any{
		"asset_id": a.ID, "status": "revoked", "revoked_at": mark.At, "revoked_by": mark.By,
		"grants_withdrawn": grants, "machines_ended": ended,
	}
	if len(incomplete) > 0 {
		for _, why := range incomplete {
			log.Printf("[mcp] revoking AI agent %s: %s", a.PairwiseAID, why)
		}
		out["incomplete"] = incomplete
		writeJSONStatus(w, http.StatusAccepted, out)
		return
	}
	writeJSONStatus(w, http.StatusOK, out)
}
