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
	"identity-agent-core/brainsignin"
	"identity-agent-core/schemas"

	"github.com/go-chi/chi/v5"
)

// capabilityGrantSchemaSAID identifies the AI agent grant schema (see the schema
// package's asset grants). The owner issues an ACDC of this schema to a
// provisioned agent; the endpoint verifies it to prove the agent's authority at
// invoke time.
var capabilityGrantSchemaSAID = schemas.AIAgentGrant.Schema.SAID

// capabilityGrantSchemaSAIDs are every version of the grant schema still
// honoured: the current one, and the first, which grants issued before edges
// carry.
var capabilityGrantSchemaSAIDs = []string{capabilityGrantSchemaSAID, schemas.AIAgentGrantV1.Schema.SAID}

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
	// Who asked, read before the body is: the request is kept as it was signed.
	by, release, err := s.authorityOf(r)
	if err != nil {
		jsonError(w, "who asked for this AI agent: "+err.Error(), http.StatusForbidden)
		return
	}
	defer release()
	var req struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
		// Always present, even empty, so a front end can tell an Identity Agent
		// that reports limits from one too old to.
		ResourceConstraints map[string]interface{} `json:"resource_constraints"`
		Role                string                 `json:"role,omitempty"`
		SystemPrompt        string                 `json:"system_prompt,omitempty"`
		Brain               asset.BrainConfig      `json:"brain,omitempty"`
		Exposure            *asset.Exposure        `json:"exposure,omitempty"`
		// ValidUntil is when the agent's grant lapses (RFC 3339); absent, it
		// holds until revoked.
		ValidUntil *time.Time `json:"valid_until,omitempty"`
		// BrainSignIn signs the brain in as the AI agent is made, so it is
		// never created half set up. Kept in the vault, never on the record.
		BrainSignIn *brainSignInRequest `json:"brain_sign_in,omitempty"`
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

	// The brain's sign-in. A key sent where the reference belongs is taken out
	// of the brain before anything is stored, and kept in the vault instead.
	brain, signIn := s.brainSecretFrom(req.Brain)
	// An AI agent not yet made has no sign-in of its own, so a reference to
	// one names somebody else's, and is not kept.
	if brainsignin.IsRef(brain.CredentialRef) {
		brain.CredentialRef = ""
	}
	if req.BrainSignIn != nil {
		rec, err := req.BrainSignIn.record(nil, time.Now().UTC())
		if err != nil {
			jsonError(w, "the brain's sign-in: "+err.Error(), http.StatusBadRequest)
			return
		}
		signIn = &rec
	}
	if signIn != nil && signIn.HasSecret() && by.Request != nil {
		// A signed request is kept as it was signed, with the grant it
		// authorises, and goes with that grant wherever the grant is shown or
		// exported. A key in it would be kept and exported with it, so it is
		// refused, and the key is sent on its own instead.
		jsonError(w, "the AI agent was not created: a key or sign-in token is never sent in the request that "+
			"creates an AI agent, because that request is kept as it was signed. Create the AI agent without it, "+
			"then send the sign-in to PUT /api/mcp/agents/{id}/brain-sign-in", http.StatusBadRequest)
		return
	}
	if signIn != nil {
		if _, err := s.brainVault(); err != nil {
			jsonError(w, "the AI agent was not created: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	// Its operational config — role, prompt, LLM brain, exposure. Exposure defaults
	// to the MCP server unless the caller says otherwise.
	cfg := &asset.AgentConfig{
		Role:         req.Role,
		SystemPrompt: req.SystemPrompt,
		Brain:        brain,
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
	if errors.Is(err, asset.ErrAgentNameTaken) || errors.Is(err, asset.ErrKeyElsewhere) {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, asset.ErrKeyUnavailable) {
		jsonError(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if by := madeByController(r); by != "" {
		agent.MadeByController = by
		if err := s.assetHandler.Store.UpsertAsset(*agent); err != nil {
			if derr := s.assetHandler.Store.DeleteAsset(agent.ID); derr != nil {
				log.Printf("[mcp] agent %s: which machine made it could not be recorded, and it could not be removed: %v", agent.PairwiseAID, derr)
			}
			jsonError(w, "the AI agent was not created: which machine made it could not be recorded: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	if signIn != nil {
		kept, err := s.keepBrainSignIn(*agent, *signIn, madeByController(r))
		if err != nil {
			if derr := s.assetHandler.Store.DeleteAsset(agent.ID); derr != nil {
				log.Printf("[mcp] agent %s: its sign-in could not be kept, and it could not be removed: %v", agent.PairwiseAID, derr)
			}
			_ = s.removeBrainSignInOf(agent.ID)
			jsonError(w, "the AI agent was not created: its sign-in could not be kept: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		*agent = kept
		cfg = agent.AgentConfig
	}

	// Endow the agent with a capability-grant credential: an ACDC the owner issues
	// to the agent's AID that formalizes the ceiling. The endpoint verifies it at
	// invoke time, so authority is credential-proven rather than a server-side list.
	// Non-fatal: on a driverless build the stored ceiling still governs.
	grantSAID, err := s.issueCapabilityGrant(agent, by)
	grantPending := false
	if errors.Is(err, errKeyElsewhere) {
		// The identity's key is on another device, which alone can issue the
		// grant. The AI agent is made, may do nothing, and says its grant is
		// waiting for that device, as a machine's does.
		grantPending, err = true, nil
	}
	if err != nil {
		// With an engine, a grant that cannot be issued, or does not rest on
		// the request that asked for it, ends the provisioning: an AI agent
		// with no grant would otherwise act on a ceiling nobody can show was
		// authorised. Only a build with no engine has no grants at all.
		if s.KeriDriver != nil {
			if derr := s.assetHandler.Store.DeleteAsset(agent.ID); derr != nil {
				log.Printf("[mcp] agent %s was not granted and could not be removed: %v", agent.PairwiseAID, derr)
			}
			jsonError(w, "the AI agent was not created: its grant could not be issued: "+err.Error(), http.StatusForbidden)
			return
		}
		log.Printf("[mcp] agent %s provisioned on a build with no engine, so with no grant: the stored ceiling governs", agent.PairwiseAID)
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
		GrantPending: grantPending,

		MadeByController: agent.MadeByController,
	})
	if err := s.saveMCPTokens(toks); err != nil {
		jsonError(w, "failed to persist agent token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"agent_name":      req.Name,
		"asset_id":        agent.ID,
		"agent_aid":       agent.PairwiseAID,
		"delegator_aid":   agent.DelegatorAID,
		"capabilities":    req.Capabilities,
		"agent_config":    cfg.ForDisplay(),
		"brain_signed_in": signIn != nil,
		"grant_said":      grantSAID,
		"grant_issued":    grantSAID != "",
		"grant_pending":   grantPending,
		"token":           plaintext,
		"note":            "store this token now; only its hash is kept. Every call it makes is recorded as this agent AID, chained to the owner root.",
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
	AssetID      string   `json:"asset_id"`
	Name         string   `json:"name"`
	AgentAID     string   `json:"agent_aid"`
	DelegatorAID string   `json:"delegator_aid"`
	Capabilities []string `json:"capabilities"`
	// ResourceConstraints are the grant's per-capability argument limits — who
	// it may message, among others — so a front end changing one keeps the rest.
	// Always present, empty when there are none: a front end reads its absence
	// as an Identity Agent too old to report them, and then leaves them alone.
	ResourceConstraints map[string]interface{} `json:"resource_constraints"`
	Config              *asset.AgentConfig     `json:"agent_config,omitempty"`
	// SignIn is the brain's sign-in as it may be shown — kind, provider,
	// account, expiry, cap and runs in use — never its secret. Absent when
	// the brain is not signed in here.
	SignIn    map[string]any `json:"brain_sign_in,omitempty"`
	Status    string         `json:"status"` // active | revoked
	CreatedAt time.Time      `json:"created_at"`
	// GrantPending says the AI agent may do nothing yet: its grant waits for
	// the device that holds the identity's key.
	GrantPending bool `json:"grant_pending,omitempty"`
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
	pending := map[string]bool{}
	mcpTokensMu.Lock()
	for _, t := range s.loadMCPTokens() {
		if t.GrantPending && t.GrantSAID == "" {
			pending[t.AssetID] = true
		}
	}
	mcpTokensMu.Unlock()
	out := make([]agentView, 0, len(agents))
	for _, a := range agents {
		out = append(out, agentView{
			AssetID:             a.ID,
			Name:                a.DisplayName,
			AgentAID:            a.PairwiseAID,
			DelegatorAID:        a.DelegatorAID,
			Capabilities:        a.Capabilities,
			ResourceConstraints: nonNilConstraints(a.GrantConstraints),
			Config:              a.AgentConfig.ForDisplay(),
			SignIn:              s.brainSignInShown(a),
			Status:              s.agentStatus(a.PairwiseAID),
			CreatedAt:           a.CreatedAt,
			GrantPending:        pending[a.ID],
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
	before, ok := s.aiAgentAsset(id)
	if !ok {
		jsonError(w, "agent not found", http.StatusBadRequest)
		return
	}
	// A key sent where the reference belongs goes into the vault. A change
	// that does not mention the sign-in keeps the one the brain has.
	brain, signIn := s.brainSecretFrom(cfg.Brain)
	// The only sign-in an AI agent's brain may name is its own.
	if brainsignin.IsRef(brain.CredentialRef) || (brain.CredentialRef == "" && signIn == nil) {
		brain.CredentialRef = ""
		if before.AgentConfig != nil && before.AgentConfig.Brain.CredentialRef == brainsignin.Ref(id) {
			brain.CredentialRef = brainsignin.Ref(id)
		}
	}
	cfg.Brain = brain
	if signIn != nil {
		if _, err := s.brainVault(); err != nil {
			jsonError(w, "nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
	}
	updated, err := s.assetHandler.UpdateAgentConfig(id, &cfg)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if signIn != nil {
		kept, err := s.keepBrainSignIn(*updated, *signIn, madeByController(r))
		if err != nil {
			jsonError(w, "the configuration changed, but the sign-in was not kept: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		updated = &kept
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"asset_id":     updated.ID,
		"agent_config": updated.AgentConfig.ForDisplay(),
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
	// App operation — authorized by the router-wide authorize gate (owner, or the
	// owner's authorized controller after the one score-and-permission check).
	// The ceiling only ever limits: a capability the owner
	// has not imported and enabled is refused at invoke regardless (defining new
	// capabilities via pack import stays owner-only), so this grants no authority the
	// owner has not already approved.
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	// Who asked, read before the body is: the request is kept as it was signed.
	by, release, err := s.authorityOf(r)
	if err != nil {
		jsonError(w, "who asked for this change: "+err.Error(), http.StatusForbidden)
		return
	}
	defer release()
	id := chi.URLParam(r, "id")
	by.About = id
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
	grantPending := false
	if s.KeriDriver != nil {
		// Where the key is on another device, an AI agent whose grant is
		// already issued is not re-granted: the grant it replaces could not be
		// withdrawn here, and both would stand. Refused before anything is
		// built or asked for.
		if kerr := s.keyCanSign(); kerr != nil && s.agentHasIssuedGrant(id) {
			jsonError(w, "the grant could not be re-issued, so nothing was changed: "+kerr.Error()+
				", and this AI agent's current grant could not be withdrawn here", keyErrorStatus(kerr))
			return
		}
		g, err := s.issueCapabilityGrant(&candidate, by)
		if errors.Is(err, errKeyElsewhere) {
			// Its grant waits for the device that holds the key, which has
			// been asked to sign it; the change is recorded and waits with it.
			err, grantPending = nil, true
		}
		if errors.Is(err, errKeyUnavailable) {
			jsonError(w, "the grant could not be re-issued, so nothing was changed: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
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
			if grantPending {
				toks[i].GrantPending = true
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
		if reg.VcpRawB64 != "" {
			return reg.RegistrySAID, nil
		}
		noteRegistryWithoutInception(reg)
	}
	if s.KeriDriver == nil {
		return "", fmt.Errorf("keri driver unavailable")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	// The inception is checked before it is kept: it has to verify and be the
	// registry it says it is. It is kept with its anchor in the issuer's key
	// log, together or not at all, and a registry that cannot be kept is not
	// used: nothing issued into it could be proved.
	keptInside := s.engineKeepsCredentialLogs()
	resp, err := s.KeriDriver.InceptRegistry(issuerRootAID)
	if err == nil && !keptInside {
		err = s.keepAfter(issuerRootAID, resp.SequenceNumber, resp.IxnRawBytesB64, resp.VcpJsonB64)
	}
	if err != nil {
		return "", fmt.Errorf("no registry was made: %w", err)
	}
	return resp.RegistrySaid, nil
}

// issueCapabilityGrant issues a capability-grant ACDC from the owner root to the
// agent's AID, persists the credential and its anchoring KEL event (so a verifier
// can resolve the issuer KEL), and returns the grant SAID. Requires the KERI
// driver; on any failure the caller falls back to the stored ceiling.
func (s *CoreServer) issueCapabilityGrant(agent *asset.Asset, by authority) (string, error) {
	agentAID, issuerRootAID := agent.PairwiseAID, agent.DelegatorAID
	capabilities := agent.Capabilities
	if capabilities == nil {
		capabilities = []string{}
	}
	claims := map[string]interface{}{
		"name":         agent.DisplayName,
		"capabilities": capabilities,
	}
	if len(agent.GrantConstraints) > 0 {
		claims["resource_constraints"] = agent.GrantConstraints
	}
	expiry := ""
	if agent.GrantValidUntil != nil {
		expiry = agent.GrantValidUntil.UTC().Format(time.RFC3339)
	}
	superseded := s.grantsHeldBy(agentAID, true)
	grantSAID, err := s.issueAssetCredential(schemas.AIAgentGrant, agentAID, issuerRootAID, claims, expiry, by)
	if err != nil {
		return "", err
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
		if _, _, err := s.withdrawCredential(&old); err != nil {
			log.Printf("[mcp] grant %s superseded by %s: its revocation was not recorded in the registry (%v); "+
				"it is marked superseded and no longer admits anything here", old.SAID, grantSAID, err)
			if err := s.DataStore.UpdateCredentialStatus(old.SAID, "superseded"); err != nil {
				log.Printf("[mcp] grant %s superseded by %s but not marked so: %v", old.SAID, grantSAID, err)
			}
		}
	}
	log.Printf("[mcp] issued capability grant %s to agent %s (%d capabilities)", grantSAID, agentAID, len(capabilities))
	return grantSAID, nil
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

func nonNilConstraints(c map[string]interface{}) map[string]interface{} {
	if c == nil {
		return map[string]interface{}{}
	}
	return c
}

// agentHasIssuedGrant reports whether an AI agent holds a grant already
// issued.
func (s *CoreServer) agentHasIssuedGrant(assetID string) bool {
	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	for _, t := range s.loadMCPTokens() {
		if t.AssetID == assetID && t.GrantSAID != "" {
			return true
		}
	}
	return false
}

// identityKeyHeldHere reports whether this Identity Agent holds the
// identity's key, so can sign what it writes into the identity's key log.
func (s *CoreServer) identityKeyHeldHere() bool {
	_, err := s.identitySigningSeed()
	return err == nil
}

// agentGrantPendingFor reports whether an AI agent's grant waits for the
// device that holds the identity's key.
func (s *CoreServer) agentGrantPendingFor(assetID string) bool {
	mcpTokensMu.Lock()
	defer mcpTokensMu.Unlock()
	for _, t := range s.loadMCPTokens() {
		if t.AssetID == assetID && t.GrantSAID == "" && t.GrantPending {
			return true
		}
	}
	return false
}

// keyErrorStatus is how a failure to sign as the identity is answered: the
// key held elsewhere is a conflict to resolve there; a key held here and
// unreadable right now is this machine's fault, and temporary.
func keyErrorStatus(err error) int {
	if errors.Is(err, errKeyUnavailable) {
		return http.StatusServiceUnavailable
	}
	return http.StatusConflict
}
