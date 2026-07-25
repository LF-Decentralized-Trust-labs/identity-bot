package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

// Provisioning an AI-agent identity (the IA-mediated model). One
// local-owner call: mint a delegated agent AID chained to the owner root, bind
// an MCP token to it, and set the token's capability ceiling. The agent then
// authenticates with the bearer token (SDK-session-token mode — the agent never
// holds standalone signing authority), but every invocation now records the
// agent's REAL delegated AID and its lineage to the owner in the signed log —
// "owner -> agent -> action", third-party verifiable against the KELs.

// handleProvisionAgent creates an ai_agent asset (delegated AID) + a bound token.
func (s *CoreServer) handleProvisionAgent(w http.ResponseWriter, r *http.Request) {
	if !isLocalOwnerRequest(r) {
		jsonError(w, "agent provisioning is local-owner only", http.StatusForbidden)
		return
	}
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Capabilities) == 0 {
		jsonError(w, "capabilities is required (the capability ceiling this agent may invoke)", http.StatusBadRequest)
		return
	}

	// Mint the delegated agent AID (dip anchored to the owner root) + store the
	// agent asset with its capability ceiling.
	agent, err := s.assetHandler.ProvisionAgentAsset(req.Name, req.Capabilities)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Bind an MCP token to the agent identity. Token name = the agent's asset id
	// so it is unique and traceable back to the asset.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		jsonError(w, "token generation failed", http.StatusInternalServerError)
		return
	}
	plaintext := "iamcp_" + base64.RawURLEncoding.EncodeToString(raw)

	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	toks := s.loadMCPTokens()
	toks = append(toks, mcpToken{
		Name:         req.Name,
		Hash:         hashMCPToken(plaintext),
		Scopes:       req.Capabilities,
		CreatedAt:    time.Now().UTC(),
		AgentAID:     agent.PairwiseAID,
		DelegatorAID: agent.DelegatorAID,
		AssetID:      agent.ID,
	})
	if err := s.saveMCPTokens(toks); err != nil {
		jsonError(w, "failed to persist agent token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"agent_name":    req.Name,
		"asset_id":      agent.ID,
		"agent_aid":     agent.PairwiseAID,
		"delegator_aid": agent.DelegatorAID,
		"capabilities":  req.Capabilities,
		"token":         plaintext,
		"note":          "store this token now; only its hash is kept. Every call it makes is recorded as this agent AID, chained to the owner root.",
	})
}
