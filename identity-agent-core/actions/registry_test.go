package actions

import (
	"encoding/json"
	"os"
	"testing"
)

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

// Every active action must state what it discloses. The consent screen is
// rendered from that list, so an action that says nothing cannot be shown
// honestly — and silence must never be read as "send anything".
func TestEveryActiveActionDeclaresItsDisclosure(t *testing.T) {
	reg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, a := range reg.Actions {
		if a.Status != "active" {
			continue
		}
		if a.Discloses == nil {
			t.Errorf("action %q does not declare `discloses`", a.Key)
			continue
		}
		for _, f := range *a.Discloses {
			if !IsDisclosureField(f) {
				t.Errorf("action %q declares unknown disclosure field %q", a.Key, f)
			}
		}
	}
}

// Load must refuse a registry with an undeclared or misspelled disclosure
// rather than run with one.
func TestValidateRejectsBadDisclosures(t *testing.T) {
	code := 1
	missing := &Registry{Actions: []Action{{Code: &code, Key: "x", Status: "active"}}}
	if err := missing.Validate(); err == nil {
		t.Error("an action with no `discloses` should not validate")
	}
	bogus := []string{"home_address"}
	unknown := &Registry{Actions: []Action{{Code: &code, Key: "x", Status: "active", Discloses: &bogus}}}
	if err := unknown.Validate(); err == nil {
		t.Error("an unknown disclosure field should not validate")
	}
	none := []string{}
	empty := &Registry{Actions: []Action{{Code: &code, Key: "x", Status: "active", Discloses: &none}}}
	if err := empty.Validate(); err != nil {
		t.Errorf("an explicit empty declaration is valid: %v", err)
	}
}

// The schema is the spec external proposals are held to, so it has to require
// the same thing the code does.
func TestSchemaRequiresDiscloses(t *testing.T) {
	raw, err := os.ReadFile("registry.schema.json")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema struct {
		Defs struct {
			Action struct {
				Required   []string `json:"required"`
				Properties struct {
					Discloses struct {
						Items struct {
							Enum []string `json:"enum"`
						} `json:"items"`
					} `json:"discloses"`
				} `json:"properties"`
			} `json:"action"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	required := false
	for _, r := range schema.Defs.Action.Required {
		if r == "discloses" {
			required = true
		}
	}
	if !required {
		t.Error("registry.schema.json does not require `discloses`")
	}
	got := schema.Defs.Action.Properties.Discloses.Items.Enum
	if len(got) != len(DisclosureVocabulary) {
		t.Fatalf("schema enum %v does not match DisclosureVocabulary %v", got, DisclosureVocabulary)
	}
	for i, v := range DisclosureVocabulary {
		if got[i] != v {
			t.Errorf("schema enum drifted from the code at %d: %q vs %q", i, got[i], v)
		}
	}
}
