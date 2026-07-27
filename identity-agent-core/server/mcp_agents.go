package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"identity-agent-core/store"
)

// capabilityGrantSchemaSAID identifies the built-in Capability Grant schema (see
// the schema catalog). The owner issues an ACDC of this schema to a provisioned
// agent; the endpoint verifies it to prove the agent's authority at invoke time.
const capabilityGrantSchemaSAID = "ECapabilityGrant__placeholder__v1"

// Provisioning an AI-agent identity (the IA-mediated model). One
// local-owner call: mint a delegated agent AID chained to the owner root, bind
// an MCP token to it, and set the token's capability ceiling. The agent then
// authenticates with the bearer token (SDK-session-token mode — the agent never
// holds standalone signing authority), but every invocation now records the
// agent's REAL delegated AID and its lineage to the owner in the signed log —
// "owner -> agent -> action", third-party verifiable against the KELs.

// handleProvisionAgent creates an ai_agent asset (delegated AID) + a bound token.
func (s *CoreServer) handleProvisionAgent(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "agent provisioning is local-owner only", http.StatusForbidden)
		return
	}
	if s.assetHandler == nil {
		jsonError(w, "asset handler not initialized", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Name                string                 `json:"name"`
		Capabilities        []string               `json:"capabilities"`
		ResourceConstraints map[string]interface{} `json:"resource_constraints,omitempty"`
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

	// Endow the agent with a capability-grant credential: an ACDC the owner issues
	// to the agent's AID that formalizes the ceiling. The endpoint verifies it at
	// invoke time, so authority is credential-proven rather than a server-side list.
	// Non-fatal: on a driverless build the stored ceiling still governs.
	grantSAID, err := s.issueCapabilityGrant(agent.PairwiseAID, agent.DelegatorAID, req.Capabilities, req.ResourceConstraints)
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
		"grant_said":    grantSAID,
		"grant_issued":  grantSAID != "",
		"token":         plaintext,
		"note":          "store this token now; only its hash is kept. Every call it makes is recorded as this agent AID, chained to the owner root.",
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
	// Persist the registry-inception anchoring event to the issuer KEL so it survives reload.
	ixnJSON, _ := json.Marshal(resp.IxnEvent)
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID:            issuerRootAID,
		SequenceNumber: resp.SequenceNumber,
		EventType:      "ixn",
		EventJSON:      string(ixnJSON),
		PublicKey:      identity.PublicKey,
		NextKeyDigest:  identity.NextKeyDigest,
		Timestamp:      now,
	}); err != nil {
		log.Printf("[mcp] failed to persist registry anchor for %s: %v", resp.RegistrySaid, err)
	}
	log.Printf("[mcp] incepted TEL registry %s for issuer %s", resp.RegistrySaid, issuerRootAID)
	return resp.RegistrySaid, nil
}

// issueCapabilityGrant issues a capability-grant ACDC from the owner root to the
// agent's AID, persists the credential and its anchoring KEL event (so a verifier
// can resolve the issuer KEL), and returns the grant SAID. Requires the KERI
// driver; on any failure the caller falls back to the stored ceiling.
func (s *CoreServer) issueCapabilityGrant(agentAID, issuerRootAID string, capabilities []string, resourceConstraints map[string]interface{}) (string, error) {
	if s.KeriDriver == nil {
		return "", fmt.Errorf("keri driver unavailable")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return "", fmt.Errorf("no owner identity")
	}
	claims := map[string]interface{}{
		"i":            agentAID, // holder = the delegated agent
		"capabilities": capabilities,
		"issued_date":  time.Now().UTC().Format("2006-01-02"),
	}
	if len(resourceConstraints) > 0 {
		claims["resource_constraints"] = resourceConstraints
	}
	// Issue into the owner's TEL registry so the grant can be cryptographically
	// revoked (a `rev` event anchored in the owner KEL). A registry-issuance failure
	// is non-fatal — fall back to a legacy (non-revocable) issuance.
	registrySAID, rerr := s.ensureRegistry(issuerRootAID)
	if rerr != nil {
		log.Printf("[mcp] no TEL registry for %s (%v) — issuing grant without one", issuerRootAID, rerr)
	}
	result, err := s.KeriDriver.IssueCredentialInRegistry(issuerRootAID, claims, capabilityGrantSchemaSAID, agentAID, nil, registrySAID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
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
		CredentialType: "Capability Grant",
		RegistrySAID:   registrySAID,
		IssSAID:        result.IssSaid,
	}); err != nil {
		log.Printf("[mcp] failed to persist capability grant %s: %v", result.AcdcSaid, err)
	}
	// Persist the anchoring IXN event on the owner-root KEL so verification can
	// resolve the issuer KEL for this grant.
	ixnJSON, _ := json.Marshal(result.IxnEvent)
	if err := s.DataStore.SaveEvent(store.EventRecord{
		AID:            issuerRootAID,
		SequenceNumber: result.SequenceNumber,
		EventType:      "ixn",
		EventJSON:      string(ixnJSON),
		PublicKey:      identity.PublicKey,
		NextKeyDigest:  identity.NextKeyDigest,
		Timestamp:      now,
	}); err != nil {
		log.Printf("[mcp] failed to persist grant IXN event for %s: %v", result.AcdcSaid, err)
	}
	log.Printf("[mcp] issued capability grant %s to agent %s (%d capabilities)", result.AcdcSaid, agentAID, len(capabilities))
	return result.AcdcSaid, nil
}
