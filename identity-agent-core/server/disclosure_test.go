package server

import (
	"strings"
	"testing"

	"identity-agent-core/store"
)

// fullProfile has every disclosable field set, so a test that expects a field
// to be withheld is really testing the filter and not an empty profile.
func fullProfile() *store.ProfileData {
	return &store.ProfileData{
		FullName:   "Ada Lovelace",
		GivenName:  "Ada",
		FamilyName: "Lovelace",
		Org:        "Analytical Engines Ltd",
		Title:      "Chief Programmer",
		Email:      "ada@example.org",
		Tel:        "+44 20 7946 0000",
		Note:       "prefers correspondence by post",
		Photo:      "data:image/png;base64,AAAA",
		UID:        "urn:uuid:1",
	}
}

// The regression this whole mechanism exists for: accepting a contact request
// used to attach the entire profile to the introduction while the consent
// screen said only "X wants to be your contact".
func TestAddContactDisclosesOnlyDeclaredFields(t *testing.T) {
	fields, err := declaredDisclosure(2)
	if err != nil {
		t.Fatalf("add_contact disclosure declaration: %v", err)
	}
	jc, photo := buildDisclosure(fields, fullProfile(), "EAID", "https://host/public/oobi/EAID")

	if jc.FullName != "Ada Lovelace" {
		t.Errorf("declared name was not sent: %q", jc.FullName)
	}
	if photo == "" {
		t.Error("declared photo was not sent")
	}
	for _, undeclared := range []struct {
		name, got string
	}{
		{"email", jc.Email},
		{"phone", jc.Tel},
		{"organization", jc.Org},
		{"job title", jc.Title},
		{"note", jc.Note},
		{"uid", jc.UID},
	} {
		if undeclared.got != "" {
			t.Errorf("add_contact sent undeclared %s: %q", undeclared.name, undeclared.got)
		}
	}
}

// Routing information is how the peer reaches you and is already public in the
// OOBI record, so it travels regardless of the declaration.
func TestDisclosureAlwaysCarriesRouting(t *testing.T) {
	jc, _ := buildDisclosure(nil, fullProfile(), "EAID", "https://host/public/oobi/EAID")
	if jc.XKeriAID != "EAID" || jc.XKeriOOBI != "https://host/public/oobi/EAID" {
		t.Fatalf("routing fields missing: %+v", jc)
	}
	if jc.FullName != "" || jc.Email != "" {
		t.Errorf("empty declaration still sent personal data: %+v", jc)
	}
}

// The consent screen and the payload are built from one list, so every row the
// user reads corresponds to something actually sent, and nothing is sent that
// has no row.
func TestDisclosureRowsMatchWhatIsSent(t *testing.T) {
	fields, err := declaredDisclosure(2)
	if err != nil {
		t.Fatalf("declaration: %v", err)
	}
	rows := disclosureRows(fields, fullProfile())
	if len(rows) != len(fields) {
		t.Fatalf("rows %d != declared fields %d", len(rows), len(fields))
	}
	labels := map[string]bool{}
	for _, r := range rows {
		labels[r.Label] = true
	}
	for _, f := range fields {
		if !labels[disclosureLabels[f]] {
			t.Errorf("declared %q has no row on the consent screen", f)
		}
	}
}

// A declared-but-unset field is still shown. The user is consenting to the
// field, so a profile filled in later must not start sending something that
// was never on screen.
func TestDisclosureShowsDeclaredButEmptyFields(t *testing.T) {
	rows := disclosureRows([]string{discloseName, discloseEmail}, &store.ProfileData{FullName: "Ada"})
	var email string
	for _, r := range rows {
		if r.Label == "Email" {
			email = r.Value
		}
	}
	if email != "not set" {
		t.Errorf("empty declared field should read \"not set\", got %q", email)
	}
}

// The photo is shown as a presence, not as a base64 blob the user cannot read.
func TestDisclosureRowsDoNotLeakPhotoBytes(t *testing.T) {
	rows := disclosureRows([]string{disclosePhoto}, fullProfile())
	if rows[0].Value != "included" {
		t.Errorf("photo row should read \"included\", got %q", rows[0].Value)
	}
}

// An action that names a field outside the canonical vocabulary is a registry
// error. It must fail loudly rather than silently disclose nothing (or, worse,
// be read as unrestricted).
func TestUnknownDisclosureFieldIsRejected(t *testing.T) {
	if _, err := declaredDisclosure(999999); err == nil {
		t.Fatal("unregistered action code should not resolve a disclosure")
	}
}

func TestDisclosureSummaryReadsAsASentence(t *testing.T) {
	got := disclosureSummary([]string{disclosePhoto, discloseName})
	if !strings.Contains(got, "name and photo") {
		t.Errorf("summary should list fields in display order: %q", got)
	}
	if none := disclosureSummary(nil); !strings.Contains(none, "Nothing") {
		t.Errorf("empty declaration should say nothing is shared: %q", none)
	}
}

// Every action in the registry must declare only canonical field names —
// catches a typo in registry.json at test time rather than at send time.
func TestEveryRegisteredActionHasAValidDeclaration(t *testing.T) {
	for _, code := range []int{1, 2, 3, 4} {
		if _, err := declaredDisclosure(code); err != nil {
			t.Errorf("action %d: %v", code, err)
		}
	}
}
