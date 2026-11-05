// Package schemas provides a built-in catalog of Identity Agent credential schemas.
//
// Each schema is a JSON Schema document whose SAID (self-addressing identifier)
// is computed from its content and hardcoded here. The Go backend serves these
// schemas at GET /api/schemas/{said} so any KERI verifier can resolve them
// without a central registry.
//
// Every schema here is identified by the Blake3-256 digest the KERI library
// computes over the document (keri.BuildSchema), never by a hand-written
// identifier, and is served for verifiers at /public/schemas/{said}. Asset
// grants (asset_grant.go) and the credential schemas in this file share one
// document skeleton. The six credential schemas were first published under
// placeholder identifiers such as "EGuardianship__placeholder__v1", which
// prove nothing about content; credentials already issued under them are
// still honoured (see Legacy) but none is issued or served under them.
package schemas

import (
	"fmt"

	keri "github.com/grapeid/keri-go"
)

// BuiltinSchema describes one bundled credential schema.
type BuiltinSchema struct {
	SAID        string // Blake3-256 self-addressing identifier of the schema JSON
	Name        string // Human-readable credential type name
	Description string // Short description shown in the issue UI
	Fields      []SchemaField
	JSON        string // Raw JSON Schema document
}

// SchemaField describes one claim field for the issue UI form.
type SchemaField struct {
	Key         string // JSON key name in the ACDC attributes block
	Label       string // Human-readable label
	Type        string // "string" | "boolean" | "date" | "aid"
	Required    bool
	Placeholder string
}

// ── Credential schemas ────────────────────────────────────────────────────────
//
// Each is built, not written: the identifier is computed over the document.

// ProofOfAge is the Proof of Age schema.
var ProofOfAge = mustCredentialSchema(credentialKind{
	title:       "Proof of Age",
	description: "Asserts that the credential subject meets a minimum age requirement.",
	legacyID:    "EProofOfAge__placeholder__v1",
	summary:     "Asserts that the holder is 21 or older (or meets a minimum age threshold). The verifier learns only the boolean — not your date of birth.",
	attributes: []grantAttribute{
		{"over_21", `{"type": "boolean", "description": "True if holder is 21 years of age or older"}`},
		{"minimum_age", `{"type": "integer", "description": "Minimum age threshold asserted"}`},
		{"verified_by", `{"type": "string", "description": "Method used to verify age (document, biometric, etc.)"}`},
		{"issued_date", `{"type": "string", "format": "date", "description": "ISO 8601 date credential was issued"}`},
	},
	required: []string{"over_21"},
	fields: []SchemaField{
		{Key: "over_21", Label: "Over 21", Type: "boolean", Required: true, Placeholder: ""},
		{Key: "minimum_age", Label: "Minimum Age", Type: "string", Required: false, Placeholder: "21"},
		{Key: "verified_by", Label: "Verified By", Type: "string", Required: false, Placeholder: "government ID"},
		{Key: "issued_date", Label: "Issued Date", Type: "date", Required: false, Placeholder: ""},
	},
})

// ContactAttestation is the Contact Attestation schema.
var ContactAttestation = mustCredentialSchema(credentialKind{
	title:       "Contact Attestation",
	description: "Issuer attests that they have personally verified the credential subject's identity.",
	legacyID:    "EContactAttestation__placeholder__v1",
	summary:     "Attests that you have personally verified this person's identity. Useful for bootstrapping trust in a network of known contacts.",
	attributes: []grantAttribute{
		{"attestation", `{"type": "string", "enum": ["in_person_verified", "video_verified", "document_verified"], "description": "Verification method"}`},
		{"subject_name", `{"type": "string", "description": "Full name of the verified person"}`},
		{"relationship", `{"type": "string", "description": "Issuer's relationship to the subject (colleague, friend, attorney, etc.)"}`},
		{"verified_date", `{"type": "string", "format": "date", "description": "ISO 8601 date verification took place"}`},
		{"notes", `{"type": "string", "description": "Optional additional context"}`},
	},
	required: []string{"attestation", "subject_name"},
	fields: []SchemaField{
		{Key: "attestation", Label: "Verification Method", Type: "string", Required: true, Placeholder: "in_person_verified"},
		{Key: "subject_name", Label: "Subject Name", Type: "string", Required: true, Placeholder: "Full legal name"},
		{Key: "relationship", Label: "Relationship", Type: "string", Required: false, Placeholder: "colleague, friend, attorney…"},
		{Key: "verified_date", Label: "Date Verified", Type: "date", Required: false, Placeholder: ""},
		{Key: "notes", Label: "Notes", Type: "string", Required: false, Placeholder: "Optional context"},
	},
})

// SchoolPickupAuthorization is the School Pickup Authorization schema.
var SchoolPickupAuthorization = mustCredentialSchema(credentialKind{
	title:       "School Pickup Authorization",
	description: "Authorizes a named individual to pick up a child from school on behalf of the issuer.",
	legacyID:    "ESchoolPickupAuth__placeholder__v1",
	summary:     "Authorizes a named person to pick up your child from school. Can reference a guardianship credential for chain-of-trust verification.",
	attributes: []grantAttribute{
		{"child_name", `{"type": "string", "description": "Full name of the child"}`},
		{"child_aid", `{"type": "string", "description": "Child's AID (if they have an Identity Agent)"}`},
		{"school_name", `{"type": "string", "description": "Name of the school"}`},
		{"school_aid", `{"type": "string", "description": "School's organizational AID (if registered)"}`},
		{"authorized_from", `{"type": "string", "format": "date", "description": "Start date of authorization"}`},
		{"authorized_until", `{"type": "string", "format": "date", "description": "Expiry date of authorization"}`},
		{"is_recurring", `{"type": "boolean", "description": "True for standing authorization; false for one-off pickup"}`},
		{"authorized_days", `{"type": "array", "items": {"type": "string"}, "description": "Days of week authorized (e.g. [\"Monday\",\"Wednesday\"]). Empty means any day."}`},
		{"guardian_credential_id", `{"type": "string", "description": "SAID of the guardianship credential proving issuer's legal guardianship of the child. Enables chain-of-trust verification."}`},
		{"notes", `{"type": "string", "description": "Optional additional instructions for the school"}`},
	},
	required: []string{"child_name", "school_name", "authorized_until"},
	fields: []SchemaField{
		{Key: "child_name", Label: "Child's Full Name", Type: "string", Required: true, Placeholder: ""},
		{Key: "school_name", Label: "School Name", Type: "string", Required: true, Placeholder: ""},
		{Key: "authorized_until", Label: "Authorized Until", Type: "date", Required: true, Placeholder: ""},
		{Key: "authorized_from", Label: "Authorized From", Type: "date", Required: false, Placeholder: ""},
		{Key: "is_recurring", Label: "Recurring Authorization", Type: "boolean", Required: false, Placeholder: ""},
		{Key: "authorized_days", Label: "Authorized Days", Type: "string", Required: false, Placeholder: "Monday, Wednesday, Friday"},
		{Key: "child_aid", Label: "Child's AID", Type: "aid", Required: false, Placeholder: "E…"},
		{Key: "school_aid", Label: "School AID", Type: "aid", Required: false, Placeholder: "E…"},
		{Key: "guardian_credential_id", Label: "Guardianship Credential SAID", Type: "string", Required: false, Placeholder: "Links to guardianship credential for chain verification"},
		{Key: "notes", Label: "Notes for School", Type: "string", Required: false, Placeholder: ""},
	},
})

// Guardianship is the Guardianship Credential schema.
var Guardianship = mustCredentialSchema(credentialKind{
	title:       "Guardianship Credential",
	description: "Certifies a legal guardianship relationship between the issuer (guardian) and a named dependent. Used as a chain-of-trust anchor for credentials involving the dependent.",
	legacyID:    "EGuardianship__placeholder__v1",
	summary:     "Certifies a legal guardianship relationship. Used as a chain-of-trust anchor for credentials involving a dependent (child, elderly, disability, temporary).",
	attributes: []grantAttribute{
		{"dependent_name", `{"type": "string", "description": "Full legal name of the dependent"}`},
		{"dependent_aid", `{"type": "string", "description": "Dependent's AID (if they have an Identity Agent)"}`},
		{"guardian_type", `{"type": "string", "enum": ["minor_child", "elderly", "disability", "temporary"], "description": "Nature of the guardianship"}`},
		{"effective_date", `{"type": "string", "format": "date", "description": "Date guardianship became effective"}`},
		{"expiry_date", `{"type": "string", "format": "date", "description": "Date guardianship expires (omit for indefinite)"}`},
		{"jurisdiction", `{"type": "string", "description": "Legal jurisdiction where guardianship was established"}`},
		{"notes", `{"type": "string", "description": "Optional additional context"}`},
	},
	required: []string{"dependent_name", "guardian_type"},
	fields: []SchemaField{
		{Key: "dependent_name", Label: "Dependent's Full Name", Type: "string", Required: true, Placeholder: "Full legal name"},
		{Key: "dependent_aid", Label: "Dependent's AID", Type: "aid", Required: false, Placeholder: "E… (if they have an Identity Agent)"},
		{Key: "guardian_type", Label: "Guardianship Type", Type: "string", Required: true, Placeholder: "minor_child | elderly | disability | temporary"},
		{Key: "effective_date", Label: "Effective Date", Type: "date", Required: false, Placeholder: ""},
		{Key: "expiry_date", Label: "Expiry Date", Type: "date", Required: false, Placeholder: "Leave blank if indefinite"},
		{Key: "jurisdiction", Label: "Legal Jurisdiction", Type: "string", Required: false, Placeholder: "e.g. State of California"},
		{Key: "notes", Label: "Notes", Type: "string", Required: false, Placeholder: "Optional additional context"},
	},
})

// IdentityAttestation is the Identity Attestation schema.
var IdentityAttestation = mustCredentialSchema(credentialKind{
	title:       "Identity Attestation",
	description: "Attests that the holder's real-world identity has been verified to a stated assurance level. Bridges KERI cryptographic identity with human identity verification. Compatible with SEDI (State Endorsed Digital Identity) frameworks.",
	legacyID:    "EIdentityAttestation__placeholder__v1",
	summary:     "Attests that the holder's real-world identity has been verified to a stated assurance level. Bridges KERI cryptographic identity with human identity verification. Compatible with SEDI frameworks.",
	attributes: []grantAttribute{
		{"subject_name", `{"type": "string", "description": "Full legal name of the verified individual"}`},
		{"assurance_level", `{"type": "string", "enum": ["ial1", "ial2", "ial3", "ial4"], "description": "NIST Identity Assurance Level achieved"}`},
		{"auth_assurance", `{"type": "string", "enum": ["aal1", "aal2", "aal3", "aal4"], "description": "NIST Authentication Assurance Level achieved"}`},
		{"confidence_score", `{"type": "integer", "minimum": 0, "maximum": 100, "description": "OmniFactor confidence score (0-100) at time of attestation"}`},
		{"verification_methods", `{"type": "array", "items": {"type": "string"}, "description": "Methods used to verify identity (e.g. government_id, biometric_liveness, in_person, witness_attestation)"}`},
		{"jurisdiction", `{"type": "string", "description": "Legal jurisdiction of identity verification (e.g. US-UT for Utah)"}`},
		{"issued_date", `{"type": "string", "format": "date", "description": "ISO 8601 date credential was issued"}`},
		{"expiry_date", `{"type": "string", "format": "date", "description": "ISO 8601 date credential expires"}`},
		{"issuer_type", `{"type": "string", "enum": ["self", "witness", "organization", "government"], "description": "Type of entity that issued this attestation"}`},
		{"notes", `{"type": "string", "description": "Optional additional context"}`},
	},
	required: []string{"subject_name", "assurance_level"},
	fields: []SchemaField{
		{Key: "subject_name", Label: "Full Legal Name", Type: "string", Required: true, Placeholder: "Full legal name"},
		{Key: "assurance_level", Label: "Identity Assurance Level", Type: "string", Required: true, Placeholder: "ial1 | ial2 | ial3 | ial4"},
		{Key: "auth_assurance", Label: "Auth Assurance Level", Type: "string", Required: false, Placeholder: "aal1 | aal2 | aal3 | aal4"},
		{Key: "confidence_score", Label: "Confidence Score (0-100)", Type: "string", Required: false, Placeholder: "87"},
		{Key: "verification_methods", Label: "Verification Methods", Type: "string", Required: false, Placeholder: "government_id, biometric_liveness"},
		{Key: "jurisdiction", Label: "Jurisdiction", Type: "string", Required: false, Placeholder: "US-UT"},
		{Key: "issued_date", Label: "Issued Date", Type: "date", Required: false, Placeholder: ""},
		{Key: "expiry_date", Label: "Expiry Date", Type: "date", Required: false, Placeholder: ""},
		{Key: "issuer_type", Label: "Issuer Type", Type: "string", Required: false, Placeholder: "self | witness | organization | government"},
		{Key: "notes", Label: "Notes", Type: "string", Required: false, Placeholder: "Optional context"},
	},
})

// EmployeeAuthorization is the Employee Authorization schema.
var EmployeeAuthorization = mustCredentialSchema(credentialKind{
	title:       "Employee Authorization",
	description: "Authorizes an individual to act on behalf of an organization. Issued by an organization's identity agent to an employee's personal identity agent. The employee presents this credential to prove organizational affiliation.",
	legacyID:    "EEmployeeAuth__placeholder__v1",
	summary:     "Authorizes an individual to act on behalf of an organization. Issued by the organization to an employee's personal Identity Agent, which presents it to prove organizational authority.",
	attributes: []grantAttribute{
		{"org_name", `{"type": "string", "description": "Legal name of the organization"}`},
		{"org_aid", `{"type": "string", "description": "Organization's AID"}`},
		{"employee_name", `{"type": "string", "description": "Full legal name of the employee"}`},
		{"role", `{"type": "string", "description": "Employee's role or title within the organization"}`},
		{"department", `{"type": "string", "description": "Department within the organization"}`},
		{"permissions", `{"type": "array", "items": {"type": "string"}, "description": "Specific permissions granted (e.g. verify_credentials, sign_contracts, manage_employees)"}`},
		{"effective_date", `{"type": "string", "format": "date", "description": "Date authorization became effective"}`},
		{"expiry_date", `{"type": "string", "format": "date", "description": "Date authorization expires"}`},
		{"jurisdiction", `{"type": "string", "description": "Legal jurisdiction of the organization"}`},
		{"notes", `{"type": "string", "description": "Optional additional context"}`},
	},
	required: []string{"org_name", "org_aid", "employee_name", "role"},
	fields: []SchemaField{
		{Key: "org_name", Label: "Organization Name", Type: "string", Required: true, Placeholder: "Legal name of the organization"},
		{Key: "org_aid", Label: "Organization AID", Type: "aid", Required: true, Placeholder: "E…"},
		{Key: "employee_name", Label: "Employee Name", Type: "string", Required: true, Placeholder: "Full legal name"},
		{Key: "role", Label: "Role", Type: "string", Required: true, Placeholder: "Role or title"},
		{Key: "department", Label: "Department", Type: "string", Required: false, Placeholder: ""},
		{Key: "permissions", Label: "Permissions", Type: "string", Required: false, Placeholder: "verify_credentials, sign_contracts"},
		{Key: "effective_date", Label: "Effective Date", Type: "date", Required: false, Placeholder: ""},
		{Key: "expiry_date", Label: "Expiry Date", Type: "date", Required: false, Placeholder: ""},
		{Key: "jurisdiction", Label: "Jurisdiction", Type: "string", Required: false, Placeholder: ""},
		{Key: "notes", Label: "Notes", Type: "string", Required: false, Placeholder: "Optional context"},
	},
})

// credentialKind is what one credential schema adds to the shared skeleton.
type credentialKind struct {
	title       string
	description string // the schema document's own description
	summary     string // shown beside the schema in the issue UI
	legacyID    string // the placeholder identifier this schema replaced
	attributes  []grantAttribute
	required    []string
	fields      []SchemaField
}

// credentialAttributes are the attributes every one of these credentials
// carries ahead of its own, in order, which is part of each schema's identifier.
// "dt" is written by the issuing engine; "u" is present when the block is private.
var credentialAttributes = []grantAttribute{
	{"d", `{"description": "Attributes block identifier", "type": "string"}`},
	{"u", `{"description": "Salt, when the attributes are issued private", "type": "string"}`},
	{"i", `{"description": "The holder's identifier", "type": "string"}`},
	{"dt", `{"description": "When the credential was issued", "type": "string", "format": "date-time"}`},
}

// legacyIDs maps each retired placeholder identifier to the schema that replaced it.
var legacyIDs = map[string]*BuiltinSchema{}

func buildCredentialSchema(k credentialKind) (*BuiltinSchema, error) {
	attrs := append(append([]grantAttribute{}, credentialAttributes...), k.attributes...)
	props := make([]string, len(attrs))
	for i, a := range attrs {
		props[i] = fmt.Sprintf("%q: %s", a.name, a.definition)
	}
	required := append([]string{"d"}, k.required...)
	doc := credentialSchemaDocument(k.title, k.description, "1.0.0",
		"Issuer: the identity that issued the credential",
		"The registry the credential is issued in, where its revocation is recorded",
		props, required, edgesPropertyJSON)
	built, err := keri.BuildSchema(keri.SchemaInput{Schema: []byte(doc)})
	if err != nil {
		return nil, fmt.Errorf("building the %s schema: %w", k.title, err)
	}
	said, err := keri.VerifySchema(built)
	if err != nil {
		return nil, fmt.Errorf("the %s schema does not match its own identifier: %w", k.title, err)
	}
	return &BuiltinSchema{SAID: said, Name: k.title, Description: k.summary, Fields: k.fields, JSON: string(built)}, nil
}

func mustCredentialSchema(k credentialKind) *BuiltinSchema {
	sch, err := buildCredentialSchema(k)
	if err != nil {
		// The template is a constant; a failure is a defect in this file, and
		// starting without the schema would issue credentials nobody can resolve.
		panic(err)
	}
	legacyIDs[k.legacyID] = sch
	return sch
}

// Catalog is the authoritative map of SAID → BuiltinSchema for all bundled
// schemas, keyed by the digest each schema's "$id" carries. It is filled in
// init, from the schemas built in this package.
var Catalog = map[string]*BuiltinSchema{}

func init() {
	for _, s := range []*BuiltinSchema{Guardianship, ProofOfAge, ContactAttestation, IdentityAttestation, SchoolPickupAuthorization, EmployeeAuthorization} {
		Catalog[s.SAID] = s
	}
}

// List returns all built-in schemas as a slice.
func List() []*BuiltinSchema {
	out := make([]*BuiltinSchema, 0, len(Catalog))
	for _, s := range Catalog {
		out = append(out, s)
	}
	return out
}

// Get returns a schema by SAID, or nil if not found. A retired placeholder
// identifier returns the schema that replaced it, so a credential issued under
// one can still be shown by name; that schema's own SAID differs from the
// identifier asked for, and only the real one is served to verifiers.
func Get(said string) *BuiltinSchema {
	if s := Catalog[said]; s != nil {
		return s
	}
	return legacyIDs[said]
}

// Legacy returns the schema that replaced a retired placeholder identifier,
// or nil if said is not one.
func Legacy(said string) *BuiltinSchema { return legacyIDs[said] }

// Equivalent returns the other identifier a credential of this schema may
// carry: the placeholder for a real identifier and the real one for a
// placeholder. Empty if there is none. Credentials issued before the
// identifiers were real name the placeholder, and a caller that trusts one
// form must not refuse the other.
func Equivalent(said string) string {
	if s := legacyIDs[said]; s != nil {
		return s.SAID
	}
	for old, s := range legacyIDs {
		if s.SAID == said {
			return old
		}
	}
	return ""
}
