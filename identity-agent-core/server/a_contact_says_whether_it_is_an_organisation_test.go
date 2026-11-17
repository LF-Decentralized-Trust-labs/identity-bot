package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"identity-agent-core/store"
	"identity-agent-core/witness"
)

func getContactEntityType(t *testing.T, base, aid string) string {
	t.Helper()
	resp, err := http.Get(base + "/api/contacts/" + aid)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get contact: %d", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	s, _ := got["entity_type"].(string)
	return s
}

func listContactEntityType(t *testing.T, base, aid string) string {
	t.Helper()
	resp, err := http.Get(base + "/api/contacts")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		Contacts []map[string]any `json:"contacts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	for _, c := range got.Contacts {
		if c["aid"] == aid {
			s, _ := c["entity_type"].(string)
			return s
		}
	}
	t.Fatalf("contact %s not listed", aid)
	return ""
}

// What a contact published about itself — a person or an organisation — is on
// the contact the owner's routes return, so a screen that only makes sense for
// an organisation can be shown for exactly those contacts.
func TestAContactSaysWhetherItIsAnOrganisationOrAPerson(t *testing.T) {
	cases := []struct{ published, want string }{
		{"organization", "organization"},
		{"individual", "individual"},
		{"", "individual"}, // the peer helper publishes "individual" when none is set
		{"company", ""},    // unrecognised is unknown, never guessed
	}
	for i, c := range cases {
		a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
		b := startOwnerPeer(t, "EAgentB0000000000000000000000000000000000002")
		b.entityType = c.published

		resp := postJSON(t, a.base+"/api/contacts", map[string]any{"oobi_url": b.oobi(), "trusted": true})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("case %d: add-contact: %d", i, resp.StatusCode)
		}
		var added map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&added)
		resp.Body.Close()
		if got, _ := added["entity_type"].(string); got != c.want {
			t.Errorf("published %q: add-contact answered %q, want %q", c.published, got, c.want)
		}
		if got := getContactEntityType(t, a.base, b.aid); got != c.want {
			t.Errorf("published %q: contact says %q, want %q", c.published, got, c.want)
		}
		if got := listContactEntityType(t, a.base, b.aid); got != c.want {
			t.Errorf("published %q: contact list says %q, want %q", c.published, got, c.want)
		}
	}
}

// The kind is read from the one record the witnessing boundary also decides
// from, so a contact added before this was returned shows its kind as soon as
// it has been recorded, and a contact whose address was never resolved is
// unknown rather than a person.
func TestAContactsKindComesFromWhatWasRecordedWhenItsAddressWasResolved(t *testing.T) {
	a := startOwnerPeer(t, "EAgentA0000000000000000000000000000000000001")
	const aid = "EAgentC0000000000000000000000000000000000003"
	if err := a.core.DataStore.SaveContact(store.ContactRecord{AID: aid, Alias: "c", Status: "accepted"}); err != nil {
		t.Fatal(err)
	}
	if got := getContactEntityType(t, a.base, aid); got != "" {
		t.Fatalf("a contact that never said reads as %q, want unknown", got)
	}
	a.svc.RecordContactCapability(aid, witness.BackendDesktop, "", "organization")
	if got := getContactEntityType(t, a.base, aid); got != "organization" {
		t.Fatalf("after its address was resolved the contact reads as %q, want organization", got)
	}
}
