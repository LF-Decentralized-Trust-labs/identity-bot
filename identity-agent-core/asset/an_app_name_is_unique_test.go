package asset

import (
	"errors"
	"testing"
)

// An agent and an app share the engine's namespace of names, so neither may
// take a name the other holds, however it is spaced or cased.
func TestAnAppCannotTakeAnAgentsNameNorAnAgentAnApps(t *testing.T) {
	h, _ := newAgentForTest(t, nil)
	if _, err := h.ProvisionAppAsset(" TEST-agent ", nil, nil, nil); !errors.Is(err, ErrAppNameTaken) {
		t.Fatalf("an app took an AI agent's name: %v", err)
	}
	if err := h.Store.UpsertAsset(Asset{ID: "app-1", DisplayName: "Task console", AssetType: "app", PairwiseAID: "EApp"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ProvisionAppAsset("task console", nil, nil, nil); !errors.Is(err, ErrAppNameTaken) {
		t.Fatalf("a second app took an app's name: %v", err)
	}
	if _, err := h.ProvisionAgentAsset("Task Console", nil, nil, nil, nil); !errors.Is(err, ErrAgentNameTaken) {
		t.Fatalf("an AI agent took an app's name: %v", err)
	}
	if _, err := h.ProvisionAppAsset("   ", nil, nil, nil); err == nil {
		t.Fatal("an app with no name was provisioned")
	}
	apps := 0
	all, err := h.Store.ListAssets()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range all {
		if a.AssetType == "app" {
			apps++
		}
	}
	if apps != 1 {
		t.Fatalf("%d apps stored, want 1", apps)
	}
	if agents, _ := h.ListAgents(); len(agents) != 1 {
		t.Fatalf("an app is listed among the AI agents: %d", len(agents))
	}
}
