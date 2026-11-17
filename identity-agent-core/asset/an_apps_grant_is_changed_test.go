package asset

import (
	"errors"
	"testing"
)

// What an app's changed grant may say is checked as when it was made, nothing
// is stored by the check, and an AI agent is not an app.
func TestAnAppsChangedGrantIsCheckedAsAMadeOneIsAndStoresNothing(t *testing.T) {
	h, _ := newAgentForTest(t, nil)
	app := Asset{ID: "app-1", DisplayName: "Task console", AssetType: "app", PairwiseAID: "EApp", Capabilities: []string{"app.network.request"}}
	if err := h.Store.UpsertAsset(app); err != nil {
		t.Fatal(err)
	}
	got, err := h.AppAsChanged(app.ID, []string{"ai_agent.watch_feed", "app.network.request", "ai_agent.watch_feed"}, nil)
	if err != nil || len(got.Capabilities) != 2 {
		t.Fatalf("a widened grant: %v %v", got.Capabilities, err)
	}
	if stored, _, _ := h.Store.GetAsset(app.ID); len(stored.Capabilities) != 1 {
		t.Fatalf("checking a change stored it: %v", stored.Capabilities)
	}
	if _, err := h.AppAsChanged(app.ID, nil, nil); !errors.Is(err, ErrNoCapabilities) {
		t.Fatalf("a grant that gives nothing: %v", err)
	}
	bad := map[string]interface{}{"infra.zone.list": map[string]interface{}{"zone": []interface{}{"a"}}}
	if _, err := h.AppAsChanged(app.ID, []string{"app.network.request"}, &bad); err == nil {
		t.Fatal("a limit on a capability the grant does not give was accepted")
	}
	if _, err := h.AppAsChanged("agent-1", []string{"agent.message.send"}, nil); !errors.Is(err, ErrNotAnApp) {
		t.Fatalf("an AI agent was changed as an app: %v", err)
	}
	if _, err := h.SetAppGrant(app.ID, []string{"app.network.request", "ai_agent.watch_feed"}, nil); err != nil {
		t.Fatal(err)
	}
	if stored, _, _ := h.Store.GetAsset(app.ID); len(stored.Capabilities) != 2 {
		t.Fatalf("the record does not say what the grant gives: %v", stored.Capabilities)
	}
}
