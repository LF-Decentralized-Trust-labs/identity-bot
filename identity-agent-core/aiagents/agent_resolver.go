package aiagents

import (
	"identity-agent-core/asset"
	"identity-agent-core/permission"
)

// Agent identity resolution — the foundational primitives for treating a provisioned
// AI agent as a governed KERI identity. These are the seams an agent-workforce product
// (orchestrator, access policy) builds on; the product logic itself lives outside the
// core (an overlay), wired via MountExtraRoutes + SetAuthorizer.

// ResolveAgentCaller returns the governed caller context for a provisioned agent — its
// delegated AID, delegation lineage to the owner root, and credential-proven capability
// ceiling (from its capability-grant ACDC, falling back to the stored ceiling). Returns
// false if aid is not a provisioned agent. Exported so an overlay can act as an agent.
func (s *aiAgents) ResolveAgentCaller(aid string) (permission.CallerContext, bool) {
	agent := s.FindAgentAssetByAID(aid)
	if agent == nil {
		return permission.CallerContext{}, false
	}
	cc := permission.CallerContext{
		Remote:          true,
		CallerAID:       aid,
		DelegationChain: []string{agent.PairwiseAID},
		Scopes:          append([]string(nil), agent.Capabilities...),
	}
	if agent.DelegatorAID != "" {
		cc.DelegationChain = append(cc.DelegationChain, agent.DelegatorAID)
	}
	if _, revoked := s.revokedAIAgents().Get(agent.ID); revoked {
		cc.Scopes = nil
		cc.NoScopesBecause = "this AI agent was revoked"
	} else if grant := s.FindCapabilityGrant(aid); grant != nil {
		s.applyGrantScopes(mcpToken{
			AgentAID:     agent.PairwiseAID,
			DelegatorAID: agent.DelegatorAID,
			AssetID:      agent.ID,
			GrantSAID:    grant.SAID,
			Scopes:       agent.Capabilities,
		}, &cc)
	} else if s.KeriDriver != nil {
		// Where grants can be issued and verified, no usable grant means no
		// authority. Falling back to the stored ceiling here gave a revoked AI
		// agent its ceiling back the moment it authenticated by its own
		// signature instead of its token. A build with no engine has no grants
		// at all, and there the stored ceiling is the only statement there is.
		cc.Scopes = nil
		if s.agentGrantLapsed(aid) {
			cc.NoScopesBecause = "this AI agent's grant has expired"
		} else {
			cc.NoScopesBecause = "this AI agent is " + helpers.AwaitingPhrase(s.agentGrantPendingFor(agent.ID))
		}
	}
	return cc, true
}

// AgentConfigByAID returns a provisioned agent's stored operational config (role,
// system prompt, brain, exposure) by its delegated AID, or nil. Exported so an overlay
// (e.g. the agent-brain runner) can read how an agent is meant to operate.
func (s *aiAgents) AgentConfigByAID(aid string) *asset.AgentConfig {
	if s.AssetHandler() == nil || aid == "" {
		return nil
	}
	for _, a := range s.AssetHandler().Store.ListAssets() {
		if a.AssetType == "ai_agent" && a.PairwiseAID == aid {
			return a.AgentConfig
		}
	}
	return nil
}

// enrichCallerFromIdentity gives an envelope-proven caller its delegation lineage and
// capability ceiling from its provisioned agent asset — so an agent that authenticates
// by AID alone (no bearer token) carries the same governance context as a token-bound
// one. The core asks it only of a caller that proved an AID by envelope and has no
// chain yet; it reports whether the AID is one of this Identity Agent's AI agents.
func (s *aiAgents) enrichCallerFromIdentity(caller *permission.CallerContext) bool {
	cc, ok := s.ResolveAgentCaller(caller.CallerAID)
	if !ok {
		return false // a proven AID that is not one of our provisioned agents: no scope granted
	}
	caller.DelegationChain = cc.DelegationChain
	caller.Scopes = cc.Scopes
	caller.GrantSAID = cc.GrantSAID
	caller.ResourceConstraints = cc.ResourceConstraints
	return true
}
