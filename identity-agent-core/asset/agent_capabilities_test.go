package asset

import (
	"testing"
)

func newAgentForTest(t *testing.T, caps []string) (*Handler, string) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	h := &Handler{Store: store}
	a := Asset{
		ID: "agent-1", DisplayName: "test-agent", AssetType: "ai_agent",
		PairwiseAID: "EAgent", DelegatorAID: "ERoot", Capabilities: caps,
	}
	if err := store.UpsertAsset(a); err != nil {
		t.Fatalf("seeding agent: %v", err)
	}
	return h, a.ID
}

func TestSetAgentCapabilitiesReplacesTheCeiling(t *testing.T) {
	h, id := newAgentForTest(t, []string{"infra.zone.list"})

	got, err := h.SetAgentCapabilities(id, []string{"dev.code.write", "infra.zone.list"})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	want := []string{"dev.code.write", "infra.zone.list"} // sorted
	if len(got.Capabilities) != len(want) {
		t.Fatalf("capabilities = %v, want %v", got.Capabilities, want)
	}
	for i := range want {
		if got.Capabilities[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v (sorted)", got.Capabilities, want)
		}
	}
}

// Replacing, not merging: a capability left out of the new list must be gone. This
// is the property that makes a ceiling readable — if the call only ever added, no
// owner could take anything away without deleting the agent.
func TestSetAgentCapabilitiesRemovesWhatIsOmitted(t *testing.T) {
	h, id := newAgentForTest(t, []string{"a.b.c", "d.e.f", "g.h.i"})

	got, err := h.SetAgentCapabilities(id, []string{"d.e.f"})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if len(got.Capabilities) != 1 || got.Capabilities[0] != "d.e.f" {
		t.Errorf("capabilities = %v, want exactly [d.e.f]", got.Capabilities)
	}
}

// An explicitly empty list strips an agent of everything without revoking it — a
// legitimate way to park an agent, so it must not be treated as an error.
func TestSetAgentCapabilitiesAcceptsEmpty(t *testing.T) {
	h, id := newAgentForTest(t, []string{"a.b.c"})

	got, err := h.SetAgentCapabilities(id, []string{})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if len(got.Capabilities) != 0 {
		t.Errorf("capabilities = %v, want empty", got.Capabilities)
	}
}

func TestSetAgentCapabilitiesNormalises(t *testing.T) {
	h, id := newAgentForTest(t, nil)

	got, err := h.SetAgentCapabilities(id, []string{"b.b.b", "a.a.a", "b.b.b", "  ", "", " c.c.c "})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	want := []string{"a.a.a", "b.b.b", "c.c.c"}
	if len(got.Capabilities) != len(want) {
		t.Fatalf("capabilities = %v, want %v (deduped, trimmed, sorted)", got.Capabilities, want)
	}
	for i := range want {
		if got.Capabilities[i] != want[i] {
			t.Fatalf("capabilities = %v, want %v", got.Capabilities, want)
		}
	}
}

func TestSetAgentCapabilitiesPersists(t *testing.T) {
	h, id := newAgentForTest(t, []string{"a.b.c"})

	if _, err := h.SetAgentCapabilities(id, []string{"x.y.z"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	reloaded, ok := h.Store.GetAsset(id)
	if !ok {
		t.Fatal("agent vanished after update")
	}
	if len(reloaded.Capabilities) != 1 || reloaded.Capabilities[0] != "x.y.z" {
		t.Errorf("persisted capabilities = %v, want [x.y.z]", reloaded.Capabilities)
	}
}

func TestSetAgentCapabilitiesRejectsNonAgents(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	h := &Handler{Store: store}
	if err := store.UpsertAsset(Asset{ID: "site-1", AssetType: "domain"}); err != nil {
		t.Fatalf("seeding: %v", err)
	}

	if _, err := h.SetAgentCapabilities("site-1", []string{"a.b.c"}); err == nil {
		t.Error("a domain asset should not accept a capability ceiling")
	}
	if _, err := h.SetAgentCapabilities("missing", []string{"a.b.c"}); err == nil {
		t.Error("an unknown asset id should be an error")
	}
}
