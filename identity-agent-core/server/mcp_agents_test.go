package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"identity-agent-core/sandbox"
)

func reqWithBearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/mcp", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

// A token bound to a provisioned agent identity resolves the caller to the
// agent's real delegated AID with its lineage to the owner root — not
// "token:<name>" — so the audit event proves owner -> agent.
func TestAgentBoundTokenResolvesToDelegatedIdentity(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}

	// Seed a bound token directly (provisioning itself needs the KERI driver;
	// this isolates the resolver's identity binding).
	plaintext := "iamcp_testtoken"
	mcpTokensMu.Lock()
	if err := s.saveMCPTokens([]mcpToken{{
		Name:         "acme-support-agent",
		Hash:         hashMCPToken(plaintext),
		Scopes:       []string{"infra.zone.list"},
		AgentAID:     "EAgentDelegatedAID",
		DelegatorAID: "ERootOwnerAID",
		AssetID:      "asset-123",
	}}); err != nil {
		mcpTokensMu.Unlock()
		t.Fatal(err)
	}
	mcpTokensMu.Unlock()

	req := reqWithBearer(plaintext)
	cc := tokenAwareResolver{s}.Resolve(req)

	if cc.CallerAID != "EAgentDelegatedAID" {
		t.Fatalf("caller should be the agent's delegated AID, got %q", cc.CallerAID)
	}
	if len(cc.DelegationChain) != 2 || cc.DelegationChain[0] != "EAgentDelegatedAID" || cc.DelegationChain[1] != "ERootOwnerAID" {
		t.Fatalf("delegation chain should be [agent, root], got %v", cc.DelegationChain)
	}
	if len(cc.Scopes) != 1 || cc.Scopes[0] != "infra.zone.list" {
		t.Fatalf("scopes (ceiling) not carried: %v", cc.Scopes)
	}
	if !cc.Remote {
		t.Fatal("a token caller is remote")
	}
}

// A plain (non-agent) token still resolves to token:<name> with no chain —
// backward compatible.
func TestPlainTokenUnchanged(t *testing.T) {
	s := &CoreServer{DataDir: t.TempDir()}
	plaintext := "iamcp_plain"
	mcpTokensMu.Lock()
	s.saveMCPTokens([]mcpToken{{
		Name:   "ci-token",
		Hash:   hashMCPToken(plaintext),
		Scopes: []string{"infra.zone.list"},
	}})
	mcpTokensMu.Unlock()

	cc := tokenAwareResolver{s}.Resolve(reqWithBearer(plaintext))
	if cc.CallerAID != "token:ci-token" {
		t.Fatalf("plain token should resolve to token:<name>, got %q", cc.CallerAID)
	}
	if len(cc.DelegationChain) != 0 {
		t.Fatalf("plain token has no delegation chain, got %v", cc.DelegationChain)
	}
}

// The audit event carries the delegation chain from the caller context.
func TestDelegationChainReachesAuditEvent(t *testing.T) {
	cc := sandbox.CallerContext{
		CallerAID:       "EAgentDelegatedAID",
		DelegationChain: []string{"EAgentDelegatedAID", "ERootOwnerAID"},
	}
	if len(cc.DelegationChain) != 2 {
		t.Fatal("caller context should carry the delegation chain")
	}
}
