package server

import (
	"context"
	"fmt"

	"identity-agent-core/sandbox"
)

// accessAuthorizer is the real governance-gateway ingress decision, injected into the
// sandbox Manager in place of the structural default. It enforces, in order:
//
//  1. the structural invariants that hold regardless of per-capability policy
//     (a host_control capability is never remote-invocable; a capability flagged
//     RequireSignedRequest demands a verified envelope);
//  2. the WHAT gate — a remote caller must hold the capability in its granted scope
//     (the capability grant's ceiling);
//  3. the WHO gate — the owner's access policy for this capability (the four modes).
//
// The local owner is unrestricted. Egress is pass-through for now (disclosure/filter
// rules land with the broader gateway build).
type accessAuthorizer struct{ s *CoreServer }

func (a accessAuthorizer) AuthorizeIngress(ctx context.Context, caller sandbox.CallerContext, capDef sandbox.ProvidedCapability) error {
	// (1) Structural invariants.
	if capDef.HostControl && caller.Remote {
		return fmt.Errorf("%w: host_control capability %q is not invocable by a remote caller", sandbox.ErrDenied, capDef.ID)
	}
	if capDef.RequireSignedRequest && !caller.EnvelopeVerified {
		return fmt.Errorf("%w: capability %q requires a signed request envelope", sandbox.ErrDenied, capDef.ID)
	}

	// The local owner invokes without restriction.
	if !caller.Remote {
		return nil
	}

	// (2) WHAT — the granted scope ceiling. A remote caller without this capability in
	// its scope is default-denied before any WHO evaluation.
	if !containsString(caller.Scopes, capDef.ID) {
		return fmt.Errorf("%w: caller lacks scope for capability %q", sandbox.ErrDenied, capDef.ID)
	}

	// (3) WHO — the owner's access policy for this capability.
	policy := a.s.accessPolicyFor(capDef.ID)
	ownerRoot := a.s.ownerRootAID()
	holds := func(schema, issuer string) bool {
		return a.s.callerHoldsValidCredential(caller.CallerAID, schema, issuer)
	}
	if reason := evaluateAccessPolicy(policy, caller, ownerRoot, holds); reason != "" {
		return fmt.Errorf("%w: %s (capability %q, mode %s)", sandbox.ErrDenied, reason, capDef.ID, policy.Mode)
	}
	return nil
}

func (a accessAuthorizer) FilterEgress(ctx context.Context, caller sandbox.CallerContext, capDef sandbox.ProvidedCapability, res *sandbox.InvokeResult) *sandbox.InvokeResult {
	return res // TODO(gateway): disclosure/filter rules + audit. Pass-through until implemented.
}

// ownerRootAID returns the owner's root AID (the delegator every provisioned agent
// chains to), or "" if no identity is established.
func (s *CoreServer) ownerRootAID() string {
	if s.DataStore == nil {
		return ""
	}
	id, err := s.DataStore.GetIdentity()
	if err != nil || id == nil {
		return ""
	}
	return id.AID
}

// enrichCallerFromIdentity gives an envelope-proven caller its delegation lineage and
// capability ceiling from its provisioned agent asset — so an agent that authenticates
// by AID alone (no bearer token) carries the same governance context as a token-bound
// one. It is a no-op unless the caller proved an AID by envelope and has no chain yet
// (i.e. it is not already a token-bound agent). Identity-first depends on this: without
// it an envelope-only agent would have no scope and be denied at the WHAT gate.
func (s *CoreServer) enrichCallerFromIdentity(caller *sandbox.CallerContext) {
	if !caller.EnvelopeVerified || caller.CallerAID == "" || len(caller.DelegationChain) > 0 {
		return
	}
	agent := s.findAgentAssetByAID(caller.CallerAID)
	if agent == nil {
		return // a proven AID that is not one of our provisioned agents: no scope granted
	}
	caller.DelegationChain = []string{agent.PairwiseAID}
	if agent.DelegatorAID != "" {
		caller.DelegationChain = append(caller.DelegationChain, agent.DelegatorAID)
	}
	// Base ceiling = the asset's stored capabilities; upgrade to credential-proven
	// scope from the agent's capability grant when one is resolvable.
	caller.Scopes = append([]string(nil), agent.Capabilities...)
	if grant := s.findCapabilityGrant(caller.CallerAID); grant != nil {
		s.applyGrantScopes(mcpToken{
			AgentAID:     agent.PairwiseAID,
			DelegatorAID: agent.DelegatorAID,
			AssetID:      agent.ID,
			GrantSAID:    grant.SAID,
			Scopes:       agent.Capabilities,
		}, caller)
	}
}

// findAgentAssetByAID returns the provisioned ai_agent asset whose delegated AID is
// aid, or nil.
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

// assetAgentRef is the minimal agent-asset shape the resolver needs, decoupled from the
// asset package's full struct.
type assetAgentRef struct {
	ID           string
	PairwiseAID  string
	DelegatorAID string
	Capabilities []string
}

// findCapabilityGrant returns the newest usable capability-grant credential held by
// aid, or nil.
func (s *CoreServer) findCapabilityGrant(aid string) *grantRef {
	if s.DataStore == nil || aid == "" {
		return nil
	}
	creds, err := s.DataStore.GetCredentials()
	if err != nil {
		return nil
	}
	var found *grantRef
	for i := range creds {
		c := creds[i]
		if c.HolderAID == aid && c.SchemaSAID == capabilityGrantSchemaSAID && isUsableStatus(c.Status) {
			// GetCredentials returns newest-first in practice; take the first usable.
			found = &grantRef{SAID: c.SAID}
			break
		}
	}
	return found
}

type grantRef struct{ SAID string }

// callerHoldsValidCredential reports whether aid holds an unrevoked credential of the
// given schema (and, when issuer != "", from that issuer). Used by the by_credential
// access mode. This mirrors the login-time credential gate (Asset.RequiredCredSchema):
// a stored, usable credential of the required schema/issuer satisfies it.
//
// NOTE (follow-up): this trusts the stored credential's status; it does not re-verify
// the ACDC's anchoring the way grantCredentialValid does for capability grants. For
// credentials this agent issued (e.g. an employee credential) that is sound; verifying
// a foreign-issuer credential presented over the wire (OOBI-resolved) is the extension.
func (s *CoreServer) callerHoldsValidCredential(aid, schema, issuer string) bool {
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
