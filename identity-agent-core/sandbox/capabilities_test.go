package sandbox

import "testing"

func TestProvidedCapabilities(t *testing.T) {
	m := &Manager{manifests: map[string]*AppManifest{
		"native-computer-use": {
			ID: "native-computer-use",
			Provides: []ProvidedCapability{
				{ID: "native-computer-use", Name: "Native Computer Use", HostControl: true, RequestContract: "contracts/native-computer-use-request.md"},
			},
		},
		"headless-browser": {
			ID: "headless-browser",
			Provides: []ProvidedCapability{
				{ID: "headless-browser", Name: "Headless Browser", HostControl: false},
			},
		},
	}}

	caps := m.ProvidedCapabilities()
	if len(caps) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(caps))
	}
	// Sorted by id: "headless-browser" before "native-computer-use".
	if caps[0].ID != "headless-browser" || caps[1].ID != "native-computer-use" {
		t.Fatalf("not sorted by id: %s, %s", caps[0].ID, caps[1].ID)
	}
	if caps[0].ProvidedBy != "headless-browser" || caps[0].HostControl {
		t.Errorf("headless: providedBy=%s host_control=%v", caps[0].ProvidedBy, caps[0].HostControl)
	}
	if !caps[1].HostControl || caps[1].RequestContract == "" {
		t.Errorf("native-computer-use should be host_control with a request contract")
	}
}

func TestProvidedCapabilitiesEmpty(t *testing.T) {
	m := &Manager{manifests: map[string]*AppManifest{}}
	if got := m.ProvidedCapabilities(); len(got) != 0 {
		t.Fatalf("expected none, got %d", len(got))
	}
}
