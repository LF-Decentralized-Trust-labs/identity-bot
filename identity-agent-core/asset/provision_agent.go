package asset

import (
	"fmt"
	"time"

	"identity-agent-core/iacrypto"
)

// ProvisionAgentAsset provisions an AI agent as a delegated asset: it mints a
// delegated AID (dip anchored to the owner's root AID — the KERI driver keys
// identities by AID, so the root AID IS the delegator name) and stores the agent
// with a capability ceiling. The agent's signing key is HD-derived from the root
// seed at a stable index, so the Identity Agent can sign on the agent's behalf
// (the IA-mediated model — the agent never holds standalone signing authority).
//
// The agent gets its OWN verifiable AID chained to the owner's root, so every
// action it takes through the endpoint is provably "owner -> this agent" in the
// signed invocation log.
func (h *Handler) ProvisionAgentAsset(displayName string, capabilities []string, cfg *AgentConfig) (*Asset, error) {
	if displayName == "" {
		return nil, fmt.Errorf("agent display name is required")
	}
	rootAID := ""
	if h.RootAID != nil {
		rootAID = h.RootAID()
	}
	if rootAID == "" {
		return nil, fmt.Errorf("delegated agent identity requires a root identity — complete identity setup first")
	}
	if h.KeriDriver == nil {
		return nil, fmt.Errorf("keri driver required to mint the delegated agent AID")
	}

	id := genID()
	signingIndex := signingIndexForID(id)
	pub, nextPub, err := deriveAssetKeypair(h.dataDir, signingIndex)
	if err != nil {
		return nil, fmt.Errorf("derive agent key: %w", err)
	}
	resp, err := h.KeriDriver.CreateDelegatedInception(
		iacrypto.VerkeyQB64(pub), iacrypto.VerkeyQB64(nextPub), displayName, rootAID)
	if err != nil {
		return nil, fmt.Errorf("mint delegated agent AID: %w", err)
	}
	// Persist the owner-root anchoring event, or the agent's delegation won't
	// survive a KEL reload and its capability grant will never verify.
	if err := h.persistDelegationAnchor(rootAID, resp.DelegatorIxn); err != nil {
		return nil, fmt.Errorf("persist delegation anchor: %w", err)
	}

	now := time.Now().UTC()
	asset := Asset{
		ID:              id,
		DisplayName:     displayName,
		AssetType:       "ai_agent",
		Origin:          "agent://" + id,
		PairwiseAID:     resp.AID,
		DelegationModel: "delegated",
		DelegatorAID:    resp.DelegatorAID,
		SigningIndex:    signingIndex,
		Capabilities:    capabilities,
		AgentConfig:     cfg,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	h.Store.UpsertAsset(asset)
	return &asset, nil
}

// UpdateAgentConfig replaces the operational config of an existing ai_agent asset
// (role, prompt, brain, exposure) without touching its identity or grant. Returns
// the updated asset, or an error if it isn't an ai_agent.
func (h *Handler) UpdateAgentConfig(assetID string, cfg *AgentConfig) (*Asset, error) {
	a, ok := h.Store.GetAsset(assetID)
	if !ok {
		return nil, fmt.Errorf("agent not found")
	}
	if a.AssetType != "ai_agent" {
		return nil, fmt.Errorf("asset %s is not an ai_agent", assetID)
	}
	a.AgentConfig = cfg
	a.UpdatedAt = time.Now().UTC()
	h.Store.UpsertAsset(a)
	return &a, nil
}

// ListAgents returns all ai_agent assets (owner-only surface; contains no secrets).
func (h *Handler) ListAgents() []Asset {
	out := make([]Asset, 0)
	for _, a := range h.Store.ListAssets() {
		if a.AssetType == "ai_agent" {
			out = append(out, a)
		}
	}
	return out
}
