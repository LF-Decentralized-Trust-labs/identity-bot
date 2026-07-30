package server

import (
	"net/http"

	"identity-agent-core/asset"
	"identity-agent-core/sandbox"
)

// Agent identity resolution — the foundational primitives for treating a provisioned
// AI agent as a governed KERI identity. These are the seams an agent-workforce product
// (orchestrator, access policy) builds on; the product logic itself lives outside the
// core (an overlay), wired via MountExtraRoutes + SetAuthorizer.

// ResolveEndpointCaller resolves who is calling an endpoint (bearer token or
// signed-request envelope), enriching an envelope-proven agent with its lineage +
// capability ceiling. Returns an error only when a present envelope is invalid.
// Exported so an overlay handler can authenticate a caller the same way the core does.
func (s *CoreServer) ResolveEndpointCaller(r *http.Request, method string, body []byte) (sandbox.CallerContext, error) {
	caller := s.resolveCaller(r)
	if err := s.verifyRequestEnvelope(r, method, body, &caller); err != nil {
		return caller, err
	}
	s.enrichCallerFromIdentity(&caller)
	return caller, nil
}

// ResolveAgentCaller returns the governed caller context for a provisioned agent — its
// delegated AID, delegation lineage to the owner root, and credential-proven capability
// ceiling (from its capability-grant ACDC, falling back to the stored ceiling). Returns
// false if aid is not a provisioned agent. Exported so an overlay can act as an agent.
func (s *CoreServer) ResolveAgentCaller(aid string) (sandbox.CallerContext, bool) {
	agent := s.findAgentAssetByAID(aid)
	if agent == nil {
		return sandbox.CallerContext{}, false
	}
	cc := sandbox.CallerContext{
		Remote:          true,
		CallerAID:       aid,
		DelegationChain: []string{agent.PairwiseAID},
		Scopes:          append([]string(nil), agent.Capabilities...),
	}
	if agent.DelegatorAID != "" {
		cc.DelegationChain = append(cc.DelegationChain, agent.DelegatorAID)
	}
	if grant := s.findCapabilityGrant(aid); grant != nil {
		s.applyGrantScopes(mcpToken{
			AgentAID:     agent.PairwiseAID,
			DelegatorAID: agent.DelegatorAID,
			AssetID:      agent.ID,
			GrantSAID:    grant.SAID,
			Scopes:       agent.Capabilities,
		}, &cc)
	}
	return cc, true
}

// AgentConfigByAID returns a provisioned agent's stored operational config (role,
// system prompt, brain, exposure) by its delegated AID, or nil. Exported so an overlay
// (e.g. the agent-brain runner) can read how an agent is meant to operate.
func (s *CoreServer) AgentConfigByAID(aid string) *asset.AgentConfig {
	if s.assetHandler == nil || aid == "" {
		return nil
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.AssetType == "ai_agent" && a.PairwiseAID == aid {
			return a.AgentConfig
		}
	}
	return nil
}

// OwnerRootAID returns the owner's root AID (the delegator every provisioned agent
// chains to), or "" if no identity is established. Exported for overlay governance.
func (s *CoreServer) OwnerRootAID() string {
	if s.DataStore == nil {
		return ""
	}
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		return ""
	}
	return id.AID
}

// HoldsValidCredential reports whether aid holds an unrevoked credential of the given
// schema (and, when issuer != "", from that issuer). Exported so an overlay's
// credential-gated access policy can consult it. Trusts the stored credential's status
// (sound for credentials this agent issued; verifying a foreign-issuer presented
// credential is a separate extension).
func (s *CoreServer) HoldsValidCredential(aid, schema, issuer string) bool {
	if s.DataStore == nil || aid == "" || schema == "" {
		return false
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return false
	}
	for _, c := range creds {
		if c.HolderAID == aid && c.SchemaSAID == schema && isUsableStatus(c.Status) {
			if issuer == "" || c.IssuerAID == issuer {
				return true
			}
		}
	}
	return false
}

// enrichCallerFromIdentity gives an envelope-proven caller its delegation lineage and
// capability ceiling from its provisioned agent asset — so an agent that authenticates
// by AID alone (no bearer token) carries the same governance context as a token-bound
// one. No-op unless the caller proved an AID by envelope and has no chain yet.
func (s *CoreServer) enrichCallerFromIdentity(caller *sandbox.CallerContext) {
	if !caller.EnvelopeVerified || caller.CallerAID == "" || len(caller.DelegationChain) > 0 {
		return
	}
	cc, ok := s.ResolveAgentCaller(caller.CallerAID)
	if !ok {
		return // a proven AID that is not one of our provisioned agents: no scope granted
	}
	caller.DelegationChain = cc.DelegationChain
	caller.Scopes = cc.Scopes
	caller.GrantSAID = cc.GrantSAID
	caller.ResourceConstraints = cc.ResourceConstraints
}

// findAgentAssetByAID returns the provisioned ai_agent asset whose delegated AID is aid.
func (s *CoreServer) findAgentAssetByAID(aid string) *assetAgentRef {
	if s.assetHandler == nil || aid == "" {
		return nil
	}
	for _, a := range s.assetHandler.Store.ListAssets() {
		if a.AssetType == "ai_agent" && a.PairwiseAID == aid {
			return &assetAgentRef{ID: a.ID, PairwiseAID: a.PairwiseAID, DelegatorAID: a.DelegatorAID, Capabilities: a.Capabilities}
		}
	}
	return nil
}

type assetAgentRef struct {
	ID           string
	PairwiseAID  string
	DelegatorAID string
	Capabilities []string
}

// findCapabilityGrant returns the newest usable capability-grant credential held by aid.
func (s *CoreServer) findCapabilityGrant(aid string) *grantRef {
	if s.DataStore == nil || aid == "" {
		return nil
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return nil
	}
	for i := range creds {
		c := creds[i]
		if c.HolderAID == aid && c.SchemaSAID == capabilityGrantSchemaSAID && isUsableStatus(c.Status) {
			return &grantRef{SAID: c.SAID}
		}
	}
	return nil
}

type grantRef struct{ SAID string }
