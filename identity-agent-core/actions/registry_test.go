package actions

import "testing"

func TestLoadParsesEmbeddedRegistry(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(reg.Actions) == 0 {
		t.Fatal("expected at least one action")
	}
	// Every active entry must have a wire code and a key.
	for _, a := range reg.Actions {
		if a.Key == "" {
			t.Errorf("action has empty key: %+v", a)
		}
		if a.Status == "active" && a.Code == nil {
			t.Errorf("active action %q has no wire code", a.Key)
		}
	}
}

func TestShareMenuActionsFilters(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	menu := reg.ShareMenuActions()
	if len(menu) == 0 {
		t.Fatal("expected at least one share-menu action")
	}
	for _, a := range menu {
		if !a.UI.ShareMenu {
			t.Errorf("ShareMenuActions returned non-menu action %q", a.Key)
		}
	}
	// add_contact (t=2) is a share-menu action in v1.0.
	found := false
	for _, a := range menu {
		if a.Key == "add_contact" {
			found = true
			if a.Code == nil || *a.Code != 2 {
				t.Errorf("add_contact expected code 2, got %v", a.Code)
			}
		}
	}
	if !found {
		t.Error("expected add_contact in share-menu actions")
	}
}
