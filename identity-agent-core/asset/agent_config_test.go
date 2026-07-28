package asset

import "testing"

func TestAgentConfigListAndUpdate(t *testing.T) {
	h, err := NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// An ai_agent with full config, and a non-agent asset to prove filtering.
	h.Store.UpsertAsset(Asset{
		ID: "a1", DisplayName: "dns-steward", AssetType: "ai_agent",
		PairwiseAID: "EAgent", DelegatorAID: "ERoot", Capabilities: []string{"infra.zone.list"},
		AgentConfig: &AgentConfig{
			Role: "Infrastructure Steward", SystemPrompt: "keep dns tidy",
			Brain:    BrainConfig{Kind: "cli", Provider: "claude-code"},
			Exposure: Exposure{MCP: true},
		},
	})
	h.Store.UpsertAsset(Asset{ID: "d1", DisplayName: "example.com", AssetType: "domain"})

	agents := h.ListAgents()
	if len(agents) != 1 || agents[0].ID != "a1" {
		t.Fatalf("ListAgents must return only ai_agents, got %d", len(agents))
	}
	if agents[0].AgentConfig == nil || agents[0].AgentConfig.Brain.Provider != "claude-code" {
		t.Fatal("agent config not stored / returned")
	}

	upd, err := h.UpdateAgentConfig("a1", &AgentConfig{
		Role: "Infrastructure Steward", SystemPrompt: "new prompt",
		Brain:    BrainConfig{Kind: "remote", Provider: "anthropic", Model: "claude-sonnet-4-6"},
		Exposure: Exposure{MCP: true, DirectAPI: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if upd.AgentConfig.SystemPrompt != "new prompt" || upd.AgentConfig.Brain.Kind != "remote" {
		t.Fatal("update did not apply")
	}
	got, _ := h.Store.GetAsset("a1")
	if got.AgentConfig == nil || got.AgentConfig.Brain.Model != "claude-sonnet-4-6" {
		t.Fatal("update not persisted")
	}
	if _, err := h.UpdateAgentConfig("d1", &AgentConfig{}); err == nil {
		t.Fatal("updating a non-agent asset must error")
	}
}
