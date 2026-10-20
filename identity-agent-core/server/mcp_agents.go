package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/schemas"
	"identity-agent-core/store"

	"github.com/go-chi/chi/v5"
)

// capabilityGrantSchemaSAID identifies the AI agent grant schema (see the schema
// package's asset grants). The owner issues an ACDC of this schema to a
// provisioned agent; the endpoint verifies it to prove the agent's authority at
// invoke time.
var capabilityGrantSchemaSAID = schemas.AIAgentGrant.Schema.SAID

// Provisioning an AI-agent identity (the IA-mediated model). One
// local-owner call: mint a delegated agent AID chained to the owner root, bind
// an MCP token to it, and set the token's capability ceiling. The agent then
// authenticates with the bearer token (SDK-session-token mode — the agent never
// holds standalone signing authority), but every invocation now records the
// agent's REAL delegated AID and its lineage to the owner in the signed log —
// "owner -> agent -> action", third-party verifiable against the KELs.

// handleProvisionAgent creates an ai_agent asset (delegated AID) + a bound token.
func (s *CoreServer) handleProvisionAgent(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (the owner, or
	// the owner's authorized controller; a browser session is refused, see
	// sessionForbidden). Provisioning an AI agent
	// is not a root-of-trust operation, so it carries no extra owner-only re-check:
	// re-checking isOwner here would lock out the controller the gate just admitted.
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name                string                 `json:"name"`
		Capabilities        []string               `json:"capabilities"`
		ResourceConstraints map[string]interface{} `json:"resource_constraints,omitempty"`
		Role                string                 `json:"role,omitempty"`
		SystemPrompt        string                 `json:"system_prompt,omitempty"`
		Brain               asset.BrainConfig      `json:"brain,omitempty"`
		Exposure            *asset.Exposure        `json:"exposure,omitempty"`
		// ValidUntil is when the agent's grant lapses (RFC 3339); absent, it
		// holds until revoked.
		ValidUntil *time.Time `json:"valid_until,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Capabilities) == 0 {
		jsonError(w, "capabilities is required (the capability ceiling this agent may invoke)", http.StatusBadRequest)
		return
	}
	if req.ValidUntil != nil && !req.ValidUntil.After(time.Now()) {
		jsonError(w, "valid_until is in the past, so the grant would never be in force", http.StatusBadRequest)
		return
	}
	if err := checkResourceConstraints(req.ResourceConstraints, asset.NormaliseCapabilities(req.Capabilities)); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Its operational config — role, prompt, LLM brain, exposure. Exposure defaults
	// to the MCP server unless the caller says otherwise.
	cfg := &asset.AgentConfig{
		Role:         req.Role,
		SystemPrompt: req.SystemPrompt,
		Brain:        req.Brain,
		Exposure:     asset.Exposure{MCP: true},
	}
	if req.Exposure != nil {
		cfg.Exposure = *req.Exposure
	}

	// Mint the delegated agent AID (dip anchored to the owner root) + store the
	// agent asset with its capability ceiling and config.
	req.Name = strings.TrimSpace(req.Name)
	if s.anMCPTokenIsNamed(req.Name) {
		jsonError(w, asset.ErrAgentNameTaken.Error()+" (a token is filed under it)", http.StatusConflict)
		return
	}
	agent, err := s.assetHandler.ProvisionAgentAsset(req.Name, req.Capabilities, cfg, req.ValidUntil, req.ResourceConstraints)
	if errors.Is(err, asset.ErrAgentNameTaken) {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Endow the agent with a capability-grant credential: an ACDC the owner issues
	// to the agent's AID that formalizes the ceiling. The endpoint verifies it at
	// invoke time, so authority is credential-proven rather than a server-side list.
	// Non-fatal: on a driverless build the stored ceiling still governs.
	grantSAID, err := s.issueCapabilityGrant(agent)
	if err != nil {
		log.Printf("[mcp] agent %s provisioned without a capability grant (%v) — falling back to the stored ceiling", agent.PairwiseAID, err)
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
		GrantSAID:    grantSAID,
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
		"agent_config":  cfg,
		"grant_said":    grantSAID,
		"grant_issued":  grantSAID != "",
		"token":         plaintext,
		"note":          "store this token now; only its hash is kept. Every call it makes is recorded as this agent AID, chained to the owner root.",
	})
}

// anMCPTokenIsNamed reports whether a token is already filed under this name,
// compared as the asset store compares agent names. A token minted on its own
// carries no agent asset, so the store's check alone would miss it.
func (s *CoreServer) anMCPTokenIsNamed(name string) bool {
	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	for _, t := range s.loadMCPTokens() {
		if asset.SameAgentName(t.Name, name) {
			return true
		}
	}
	return false
}

// agentView is the owner-facing summary of an ai_agent asset — identity + config +
// status, never any secret (no token, no vault key).
type agentView struct {
	AssetID      string             `json:"asset_id"`
	Name         string             `json:"name"`
	AgentAID     string             `json:"agent_aid"`
	DelegatorAID string             `json:"delegator_aid"`
	Capabilities []string           `json:"capabilities"`
	Config       *asset.AgentConfig `json:"agent_config,omitempty"`
	Status       string             `json:"status"` // active | revoked
	CreatedAt    time.Time          `json:"created_at"`
}

// handleListAgents lists the org's ai_agent assets — the workforce roster.
func (s *CoreServer) handleListAgents(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller); the agent roster is not owner-only.
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	// Map asset id → grant status via the credential store (revoked grants show as revoked).
	agents := s.assetHandler.ListAgents()
	out := make([]agentView, 0, len(agents))
	for _, a := range agents {
		out = append(out, agentView{
			AssetID:      a.ID,
			Name:         a.DisplayName,
			AgentAID:     a.PairwiseAID,
			DelegatorAID: a.DelegatorAID,
			Capabilities: a.Capabilities,
			Config:       a.AgentConfig,
			Status:       s.agentStatus(a.PairwiseAID),
			CreatedAt:    a.CreatedAt,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"agents": out})
}

// agentStatus reports "active" or "revoked" for an agent by its most recent
// capability-grant credential status. Only the newest counts: a grant replaced
// when the ceiling changed is revoked, and that says nothing about the agent.
func (s *CoreServer) agentStatus(agentAID string) string {
	held := s.grantsHeldBy(agentAID, false)
	if len(held) > 0 && !isUsableStatus(held[0].Status) {
		return "revoked"
	}
	return "active"
}

// handleUpdateAgentConfig updates an agent's role/prompt/brain/exposure. Identity
// and grant are unchanged; use the provision/revoke paths for those.
func (s *CoreServer) handleUpdateAgentConfig(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller); agent configuration is not owner-only.
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var cfg asset.AgentConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, "invalid agent config", http.StatusBadRequest)
		return
	}
	updated, err := s.assetHandler.UpdateAgentConfig(id, &cfg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"asset_id":     updated.ID,
		"agent_config": updated.AgentConfig,
	})
}

// handleSetAgentCapabilities replaces an agent's capability ceiling.
//
// The ceiling is recorded in three places at provisioning — the asset record, the
// capability-grant ACDC the owner issues to the agent, and the scopes on the
// agent's token — and all three must move together. A ceiling widened in one place
// and not the others is worse than one that was never widened: the agent either
// holds authority nothing recorded, or is refused work it was told it could do,
// and which of those happens depends on which check runs first.
//
// The grant is re-issued rather than amended because an ACDC is a statement made at
// a point in time. Editing one in place would make the audit trail claim the owner
// granted something they had not yet decided to grant.
func (s *CoreServer) handleSetAgentCapabilities(w http.ResponseWriter, r *http.Request) {
	// App operation — authorized by the router-wide authorize gate (owner or the
	// owner's authorized controller), at the verified level since it re-issues the
	// agent's capability grant. The ceiling only ever limits: a capability the owner
	// has not imported and enabled is refused at invoke regardless (defining new
	// capabilities via pack import stays owner-only), so this grants no authority the
	// owner has not already approved.
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Capabilities []string `json:"capabilities"`
		// Absent keeps the constraints the grant already has; present, even
		// as {}, replaces them. Re-issuing without them would be a wider grant.
		ResourceConstraints *map[string]interface{} `json:"resource_constraints,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Capabilities == nil {
		// An absent list is almost certainly a mistake; an explicitly empty one is a
		// legitimate way to strip an agent of everything without revoking it.
		jsonError(w, "capabilities is required (send [] to remove every capability)", http.StatusBadRequest)
		return
	}

	// One change to an AI agent's grant at a time. Two at once would each find
	// the same grant to replace, both issue, and leave two usable grants.
	unlock := lockAgentGrant(id)
	defer unlock()

	before, ok := s.assetHandler.Store.GetAsset(id)
	if !ok {
		jsonError(w, "agent not found", http.StatusNotFound)
		return
	}
	candidate := before
	candidate.Capabilities = asset.NormaliseCapabilities(req.Capabilities)
	if req.ResourceConstraints != nil {
		candidate.GrantConstraints = *req.ResourceConstraints
	}
	if err := checkResourceConstraints(candidate.GrantConstraints, candidate.Capabilities); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The grant is re-issued FIRST, and nothing is changed unless it is. Updating
	// the record and then failing to issue left the token on the old grant, so
	// narrowing an AI agent's ceiling silently left it with the wider one. Only a
	// build with no engine, which has no grants at all, changes the record alone.
	grantSAID := ""
	if s.KeriDriver != nil {
		g, err := s.issueCapabilityGrant(&candidate)
		if err != nil {
			jsonError(w, "the grant could not be re-issued, so nothing was changed: "+err.Error(),
				http.StatusBadGateway)
			return
		}
		grantSAID = g
	}
	updated, err := s.assetHandler.SetAgentCapabilities(id, candidate.Capabilities)
	if err == nil {
		updated, err = s.assetHandler.SetAgentGrantConstraints(id, candidate.GrantConstraints)
	}
	if err != nil {
		jsonError(w, "the grant was re-issued, but the agent record was not updated: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	// The token carries its own copy of the scopes, consulted on every call.
	mcpTokensMu.Lock()
	toks := s.loadMCPTokens()
	touched := 0
	for i := range toks {
		if toks[i].AssetID == updated.ID {
			toks[i].Scopes = updated.Capabilities
			if grantSAID != "" {
				toks[i].GrantSAID = grantSAID
			}
			touched++
		}
	}
	saveErr := s.saveMCPTokens(toks)
	mcpTokensMu.Unlock()
	if saveErr != nil {
		// The record and grant already moved, so say plainly that the token did not.
		jsonError(w, "ceiling and grant updated, but the agent token still carries the old scopes: "+saveErr.Error(),
			http.StatusInternalServerError)
		return
	}

	log.Printf("[mcp] agent %s ceiling: %v -> %v (%d token(s) updated)",
		updated.PairwiseAID, before.Capabilities, updated.Capabilities, touched)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"asset_id":       updated.ID,
		"agent_aid":      updated.PairwiseAID,
		"previous":       before.Capabilities,
		"capabilities":   updated.Capabilities,
		"tokens_updated": touched,
		"grant_said":     grantSAID,
		"grant_issued":   grantSAID != "",
	})
}

// ensureRegistry returns the issuer's TEL registry SAID, incepting one (backerless,
// anchored in the issuer KEL) on first use and persisting it. One registry per issuer.
func (s *CoreServer) ensureRegistry(issuerRootAID string) (string, error) {
	if reg, err := s.DataStore.GetRegistryByIssuer(issuerRootAID); err == nil && reg != nil {
		return reg.RegistrySAID, nil
	}
	if s.KeriDriver == nil {
		return "", fmt.Errorf("keri driver unavailable")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	resp, err := s.KeriDriver.InceptRegistry(issuerRootAID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	vcpJSON, _ := json.Marshal(resp.VcpEvent)
	if err := s.DataStore.SaveRegistry(store.CredentialRegistry{
		RegistrySAID: resp.RegistrySaid,
		IssuerAID:    issuerRootAID,
		VcpJson:      string(vcpJSON),
		CreatedAt:    now,
	}); err != nil {
		log.Printf("[mcp] failed to persist registry %s: %v", resp.RegistrySaid, err)
	}
	// Persist the registry-inception anchoring event to the issuer KEL so it
	// survives reload, signed, so the registry's existence is provable.
	if err := s.saveOwnInteraction(issuerRootAID, resp.IxnEvent, resp.IxnRawBytesB64, resp.SequenceNumber, ""); err != nil {
		log.Printf("[mcp] failed to persist registry anchor for %s: %v", resp.RegistrySaid, err)
	}
	log.Printf("[mcp] incepted TEL registry %s for issuer %s", resp.RegistrySaid, issuerRootAID)
	return resp.RegistrySaid, nil
}

// issueCapabilityGrant issues a capability-grant ACDC from the owner root to the
// agent's AID, persists the credential and its anchoring KEL event (so a verifier
// can resolve the issuer KEL), and returns the grant SAID. Requires the KERI
// driver; on any failure the caller falls back to the stored ceiling.
func (s *CoreServer) issueCapabilityGrant(agent *asset.Asset) (string, error) {
	if s.KeriDriver == nil {
		return "", fmt.Errorf("keri driver unavailable")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	agentAID, issuerRootAID := agent.PairwiseAID, agent.DelegatorAID
	capabilities := agent.Capabilities
	if capabilities == nil {
		capabilities = []string{}
	}
	claims := map[string]interface{}{
		"i":            agentAID, // holder = the delegated agent
		"asset_type":   schemas.AIAgentGrant.AssetType,
		"name":         agent.DisplayName,
		"capabilities": capabilities,
	}
	if len(agent.GrantConstraints) > 0 {
		claims["resource_constraints"] = agent.GrantConstraints
	}
	expiry := ""
	if agent.GrantValidUntil != nil {
		expiry = agent.GrantValidUntil.UTC().Format(time.RFC3339)
		claims["valid_until"] = expiry
	}
	if err := schemas.AIAgentGrant.CheckAttributes(claims); err != nil {
		return "", err
	}
	// Issue into the owner's registry, so the grant is revoked by an event in that
	// registry's log, anchored in the owner's key log, which anybody can check.
	// There is no unrevocable fallback: a grant that cannot be withdrawn is not a
	// grant this software issues.
	registrySAID, err := s.ensureRegistry(issuerRootAID)
	if err != nil {
		return "", fmt.Errorf("no registry to issue the grant in: %w", err)
	}
	superseded := s.grantsHeldBy(agentAID, true)
	result, err := s.KeriDriver.IssueCredentialInRegistry(issuerRootAID, claims, capabilityGrantSchemaSAID, agentAID, nil, registrySAID)
	if err != nil {
		return "", err
	}
	// Fixed-width to the nanosecond, so two grants issued in one second still
	// order correctly as text, which is how the newest is picked.
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
	if err := s.DataStore.SaveCredential(store.CredentialRecord{
		SAID:           result.AcdcSaid,
		IssuerAID:      issuerRootAID,
		HolderAID:      agentAID,
		SchemaSAID:     capabilityGrantSchemaSAID,
		AcdcJson:       result.AcdcJsonB64,
		IxnSAID:        result.IxnSaid,
		IssuedAt:       now,
		Status:         "issued",
		Format:         "acdc",
		CredentialType: schemas.AIAgentGrant.Schema.Name,
		ExpiryDate:     expiry,
		RegistrySAID:   registrySAID,
		IssSAID:        result.IssSaid,
	}); err != nil {
		log.Printf("[mcp] failed to persist capability grant %s: %v", result.AcdcSaid, err)
	}
	// Persist the anchoring IXN event on the owner-root KEL, signed, so the
	// issuance is part of the published, verifiable history.
	if err := s.saveOwnInteraction(issuerRootAID, result.IxnEvent, result.IxnRawBytesB64, result.SequenceNumber, ""); err != nil {
		log.Printf("[mcp] failed to persist grant IXN event for %s: %v", result.AcdcSaid, err)
	}
	// The grant this one replaces is withdrawn, not left standing. A re-issue
	// that narrows a ceiling would otherwise leave the wider grant valid beside
	// it, and anything checking "does this agent hold a valid grant" would find
	// the old one as readily as the new.
	//
	// If the revocation cannot be written to the registry, the replaced grant is
	// still marked unusable here — this identity issued it, and its own record is
	// what its gateway reads — and the failure is reported, never skipped.
	for i := range superseded {
		old := superseded[i]
		status := "revoked"
		if _, err := s.revokeIssuedCredential(&old); err != nil {
			log.Printf("[mcp] grant %s superseded by %s: its revocation was not recorded in the registry (%v); "+
				"it is marked superseded and no longer admits anything here", old.SAID, result.AcdcSaid, err)
			status = "superseded"
		}
		if err := s.DataStore.UpdateCredentialStatus(old.SAID, status); err != nil {
			log.Printf("[mcp] grant %s superseded by %s but not marked %s: %v", old.SAID, result.AcdcSaid, status, err)
		}
	}
	log.Printf("[mcp] issued capability grant %s to agent %s (%d capabilities)", result.AcdcSaid, agentAID, len(capabilities))
	return result.AcdcSaid, nil
}

// checkResourceConstraints refuses constraints the gateway would not enforce as
// written: any shape but per capability id, per argument, a list of allowed
// values; an empty map or list, which the gateway reads as "no limit" though it
// looks like "nothing allowed"; and a limit on a capability the grant does not
// give, which could never apply. Accepting any of these would record a limit
// the AI agent is not actually held to.
func checkResourceConstraints(rc map[string]interface{}, capabilities []string) error {
	granted := map[string]bool{}
	for _, c := range capabilities {
		granted[c] = true
	}
	for capID, v := range rc {
		if !granted[capID] {
			return fmt.Errorf("resource_constraints names %q, which this grant does not give", capID)
		}
		args, ok := v.(map[string]interface{})
		if !ok || len(args) == 0 {
			return fmt.Errorf("resource_constraints[%q] must map at least one argument name to its allowed values", capID)
		}
		for arg, vals := range args {
			list, ok := vals.([]interface{})
			if !ok || len(list) == 0 {
				return fmt.Errorf("resource_constraints[%q][%q] must list at least one allowed value", capID, arg)
			}
			for _, x := range list {
				if _, ok := x.(string); !ok {
					return fmt.Errorf("resource_constraints[%q][%q] must list strings", capID, arg)
				}
			}
		}
	}
	return nil
}

var agentGrantLocks sync.Map

// lockAgentGrant serialises changes to one AI agent's grant.
func lockAgentGrant(assetID string) (unlock func()) {
	m, _ := agentGrantLocks.LoadOrStore(assetID, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}
