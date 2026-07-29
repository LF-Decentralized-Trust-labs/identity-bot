package server

import (
	"testing"

	"identity-agent-core/sandbox"
)

const (
	tOwnerRoot = "EOwnerRoot0000000000000000000000000000000000"
	tAgentAID  = "EAgent00000000000000000000000000000000000000"
	tOtherAID  = "EOther00000000000000000000000000000000000000"
)

// ownerAgentEnvelope: an agent delegated from the owner, authenticated by a verified
// signed-request envelope (the strongest, identity-first proof — no token).
func ownerAgentEnvelope() sandbox.CallerContext {
	return sandbox.CallerContext{
		Remote:           true,
		CallerAID:        tAgentAID,
		DelegationChain:  []string{tAgentAID, tOwnerRoot},
		EnvelopeVerified: true,
		Scopes:           []string{"infra.zone.list"},
	}
}

// ownerAgentToken: the same agent authenticated by a bearer token bound to its identity
// (AID + chain resolved from the token, but no per-request signature).
func ownerAgentToken() sandbox.CallerContext {
	cc := ownerAgentEnvelope()
	cc.EnvelopeVerified = false
	return cc
}

// bareToken: an anonymous owner-minted token with scope but no resolved identity.
func bareToken() sandbox.CallerContext {
	return sandbox.CallerContext{
		Remote:    true,
		CallerAID: "token:ci",
		Scopes:    []string{"infra.zone.list"},
	}
}

func neverHolds(string, string) bool  { return false }
func alwaysHolds(string, string) bool { return true }

func TestAccess_SameOwner(t *testing.T) {
	p := AccessPolicy{Mode: AccessSameOwner, TokenAllowed: true}

	if r := evaluateAccessPolicy(p, ownerAgentEnvelope(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("envelope-proven owner agent should pass same_owner, got: %s", r)
	}
	if r := evaluateAccessPolicy(p, ownerAgentToken(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("token-bound owner agent should pass same_owner when TokenAllowed, got: %s", r)
	}
	// TokenAllowed=false demands a signature: the token-only agent is denied, the
	// envelope one still passes.
	strict := AccessPolicy{Mode: AccessSameOwner, TokenAllowed: false}
	if r := evaluateAccessPolicy(strict, ownerAgentToken(), tOwnerRoot, neverHolds); r == "" {
		t.Fatal("token-only agent must be denied same_owner when TokenAllowed=false")
	}
	if r := evaluateAccessPolicy(strict, ownerAgentEnvelope(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("envelope agent should still pass strict same_owner, got: %s", r)
	}
	// A bare anonymous token never satisfies an identity mode.
	if r := evaluateAccessPolicy(p, bareToken(), tOwnerRoot, neverHolds); r == "" {
		t.Fatal("bare token must be denied same_owner (token off by default)")
	}
	// An agent whose chain does not reach this owner is denied.
	foreign := ownerAgentEnvelope()
	foreign.DelegationChain = []string{tAgentAID, "EDifferentOwner00000000000000000000000000000"}
	if r := evaluateAccessPolicy(p, foreign, tOwnerRoot, neverHolds); r == "" {
		t.Fatal("agent from a different owner must be denied same_owner")
	}
}

func TestAccess_SpecificIdentities(t *testing.T) {
	p := AccessPolicy{Mode: AccessSpecificIdentities, AllowedAIDs: []string{tAgentAID}, TokenAllowed: true}

	if r := evaluateAccessPolicy(p, ownerAgentEnvelope(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("allowlisted agent should pass, got: %s", r)
	}
	other := ownerAgentEnvelope()
	other.CallerAID = tOtherAID
	if r := evaluateAccessPolicy(p, other, tOwnerRoot, neverHolds); r == "" {
		t.Fatal("non-allowlisted identity must be denied")
	}
	if r := evaluateAccessPolicy(p, bareToken(), tOwnerRoot, neverHolds); r == "" {
		t.Fatal("bare token must be denied specific_identities")
	}
}

func TestAccess_ByCredential(t *testing.T) {
	p := AccessPolicy{Mode: AccessByCredential, RequiredCredSchema: "ESchema", TokenAllowed: true}

	if r := evaluateAccessPolicy(p, ownerAgentEnvelope(), tOwnerRoot, alwaysHolds); r != "" {
		t.Fatalf("credential-holding agent should pass, got: %s", r)
	}
	if r := evaluateAccessPolicy(p, ownerAgentEnvelope(), tOwnerRoot, neverHolds); r == "" {
		t.Fatal("agent lacking the credential must be denied")
	}
	if r := evaluateAccessPolicy(p, bareToken(), tOwnerRoot, alwaysHolds); r == "" {
		t.Fatal("bare token (no proven identity) must be denied by_credential even if a cred exists")
	}
}

func TestAccess_OpenToken(t *testing.T) {
	p := AccessPolicy{Mode: AccessOpenToken}

	// The permissive mode: any authenticated caller (bare token included) passes.
	if r := evaluateAccessPolicy(p, bareToken(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("bare token should pass open_token, got: %s", r)
	}
	if r := evaluateAccessPolicy(p, ownerAgentEnvelope(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("envelope agent should pass open_token, got: %s", r)
	}
	// A totally unauthenticated caller (no AID at all) is still refused.
	anon := sandbox.CallerContext{Remote: true, Scopes: []string{"infra.zone.list"}}
	if r := evaluateAccessPolicy(p, anon, tOwnerRoot, neverHolds); r == "" {
		t.Fatal("an unauthenticated caller must be denied even under open_token")
	}
}

func TestAccess_BuiltinDefaultIsPrivate(t *testing.T) {
	p := builtinDefaultAccessPolicy()
	if p.Mode != AccessSameOwner {
		t.Fatalf("built-in default should be same_owner, got %s", p.Mode)
	}
	// The default admits a same-owner agent but not an anonymous token.
	if r := evaluateAccessPolicy(p, ownerAgentToken(), tOwnerRoot, neverHolds); r != "" {
		t.Fatalf("default should admit a same-owner agent token, got: %s", r)
	}
	if r := evaluateAccessPolicy(p, bareToken(), tOwnerRoot, neverHolds); r == "" {
		t.Fatal("default must deny an anonymous token (token off by default)")
	}
}

func TestValidateAccessPolicy(t *testing.T) {
	cases := []struct {
		name string
		p    AccessPolicy
		ok   bool
	}{
		{"same_owner", AccessPolicy{Mode: AccessSameOwner}, true},
		{"open_token", AccessPolicy{Mode: AccessOpenToken}, true},
		{"specific ok", AccessPolicy{Mode: AccessSpecificIdentities, AllowedAIDs: []string{"E1"}}, true},
		{"specific empty", AccessPolicy{Mode: AccessSpecificIdentities}, false},
		{"by_cred ok", AccessPolicy{Mode: AccessByCredential, RequiredCredSchema: "E1"}, true},
		{"by_cred no schema", AccessPolicy{Mode: AccessByCredential}, false},
		{"unknown", AccessPolicy{Mode: "bogus"}, false},
	}
	for _, c := range cases {
		if got := validateAccessPolicy(c.p) == ""; got != c.ok {
			t.Errorf("%s: validate ok=%v, want %v", c.name, got, c.ok)
		}
	}
}
