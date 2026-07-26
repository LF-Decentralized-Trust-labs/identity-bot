package server

import (
	"fmt"
	"strings"

	"identity-agent-core/actions"
	"identity-agent-core/store"
)

// What an action sends about you.
//
// The rule is that an action declares its own disclosure. The registry entry
// carries a `discloses` list naming the profile fields that leave this agent
// when the action executes; the consent screen shows that same list; and the
// outbound payload is built from it. Nothing is sent because a struct happened
// to have a field set.
//
// This exists because the previous behaviour was to attach the whole profile —
// name, org, title, email, phone, note and photo — to an add-contact
// introduction, while the consent screen said only "X wants to be your
// contact". The user approved a sentence and sent a dossier.

// Canonical disclosable field names. An action's `discloses` list may only
// name these; an unknown name is a registry error, not a silently ignored one.
const (
	discloseName  = "name"
	disclosePhoto = "photo"
	discloseEmail = "email"
	disclosePhone = "phone"
	discloseOrg   = "organization"
	discloseTitle = "title"
	discloseNote  = "note"
)

// disclosureLabels is the human wording for each field, used verbatim on the
// consent screen so what the user reads and what the code sends cannot drift.
var disclosureLabels = map[string]string{
	discloseName:  "Name",
	disclosePhoto: "Photo",
	discloseEmail: "Email",
	disclosePhone: "Phone",
	discloseOrg:   "Organization",
	discloseTitle: "Job title",
	discloseNote:  "Note",
}

// disclosureOrder fixes the display order regardless of how the registry lists
// them, so the consent screen reads the same way every time.
var disclosureOrder = []string{
	discloseName, disclosePhoto, discloseOrg, discloseTitle,
	discloseEmail, disclosePhone, discloseNote,
}

// declaredDisclosure returns the profile fields action `code` declares it
// sends. An action with no `discloses` list sends nothing about you — absence
// is read as "discloses nothing", never as "unrestricted".
func declaredDisclosure(code int) ([]string, error) {
	reg, err := actions.Load()
	if err != nil {
		return nil, err
	}
	for _, a := range reg.Actions {
		if a.Code == nil || *a.Code != code {
			continue
		}
		for _, f := range a.Discloses {
			if _, ok := disclosureLabels[f]; !ok {
				return nil, fmt.Errorf("action %d (%s) declares unknown disclosure field %q", code, a.Key, f)
			}
		}
		return a.Discloses, nil
	}
	return nil, fmt.Errorf("action %d is not in the action registry", code)
}

// disclosureValue reads one declared field off the profile.
func disclosureValue(p *store.ProfileData, field string) string {
	if p == nil {
		return ""
	}
	switch field {
	case discloseName:
		return p.FullName
	case disclosePhoto:
		return p.Photo
	case discloseEmail:
		return p.Email
	case disclosePhone:
		return p.Tel
	case discloseOrg:
		return p.Org
	case discloseTitle:
		return p.Title
	case discloseNote:
		return p.Note
	}
	return ""
}

// disclosureRows describes, for the consent screen, exactly what this action
// will send about you. Declared-but-empty fields are listed as "not set" rather
// than hidden: the user is consenting to the field, and a profile edited later
// would otherwise start sending something they never saw.
func disclosureRows(fields []string, p *store.ProfileData) []PreviewDetail {
	rows := make([]PreviewDetail, 0, len(fields))
	for _, f := range orderedDisclosure(fields) {
		v := disclosureValue(p, f)
		switch {
		case f == disclosePhoto && v != "":
			v = "included"
		case v == "":
			v = "not set"
		}
		rows = append(rows, PreviewDetail{Label: disclosureRowLabel(f), Value: v})
	}
	return rows
}

// disclosureRowLabel says whose data a row describes. A consent screen also
// lists facts about the request ("Organization: Acme"), so a bare "Name" would
// be ambiguous — every disclosure row reads "Your name", "Your photo".
func disclosureRowLabel(field string) string {
	return "Your " + strings.ToLower(disclosureLabels[field])
}

// disclosureBody adds the declared profile fields to an outbound body under
// their canonical names. Used by the flows that post a small JSON body rather
// than a jCard.
func disclosureBody(fields []string, p *store.ProfileData, into map[string]string) map[string]string {
	if into == nil {
		into = map[string]string{}
	}
	for _, f := range orderedDisclosure(fields) {
		into[f] = disclosureValue(p, f)
	}
	return into
}

// disclosureSummary is the one-line form for a preview subtitle or warning.
func disclosureSummary(fields []string) string {
	ordered := orderedDisclosure(fields)
	if len(ordered) == 0 {
		return "Nothing about you is shared."
	}
	labels := make([]string, 0, len(ordered))
	for _, f := range ordered {
		labels = append(labels, strings.ToLower(disclosureLabels[f]))
	}
	return "Shares your " + joinWithAnd(labels) + " — nothing else."
}

// buildDisclosure produces the outbound personal data for an action: a jCard
// narrowed to the declared fields, and the photo only if declared. The AID,
// OOBI and role are routing information rather than personal data — they are
// how the peer reaches you, and are already public in the OOBI record — so they
// are always present and are not part of the declaration.
func buildDisclosure(fields []string, p *store.ProfileData, aid, oobi string) (*store.JCard, string) {
	jc := &store.JCard{XKeriAID: aid, XKeriOOBI: oobi, XKeriRole: "transactional"}
	photo := ""
	for _, f := range fields {
		v := disclosureValue(p, f)
		if v == "" {
			continue
		}
		switch f {
		case discloseName:
			jc.FullName = v
			if p != nil {
				jc.GivenName = p.GivenName
				jc.FamilyName = p.FamilyName
			}
		case disclosePhoto:
			photo = v
		case discloseEmail:
			jc.Email = v
		case disclosePhone:
			jc.Tel = v
		case discloseOrg:
			jc.Org = v
		case discloseTitle:
			jc.Title = v
		case discloseNote:
			jc.Note = v
		}
	}
	return jc, photo
}

// orderedDisclosure puts a declared set into canonical display order and drops
// duplicates.
func orderedDisclosure(fields []string) []string {
	want := make(map[string]bool, len(fields))
	for _, f := range fields {
		want[f] = true
	}
	out := make([]string, 0, len(fields))
	for _, f := range disclosureOrder {
		if want[f] {
			out = append(out, f)
		}
	}
	return out
}

func joinWithAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
