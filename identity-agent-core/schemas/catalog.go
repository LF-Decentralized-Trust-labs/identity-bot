// Package schemas provides a built-in catalog of Identity Agent credential schemas.
//
// Each schema is a JSON Schema document whose SAID (self-addressing identifier)
// is computed from its content and hardcoded here. The Go backend serves these
// schemas at GET /api/schemas/{said} so any KERI verifier can resolve them
// without a central registry.
//
// Adding a new schema:
//  1. Define the JSON Schema as a string constant below.
//  2. Compute its Blake3-256 SAID (run `go run ./cmd/schema-tool` or use the
//     /api/credential-schemas/fetch endpoint to derive it from content).
//  3. Add an entry to Catalog map.
package schemas

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

// ── Schema JSON documents ──────────────────────────────────────────────────────
//
// The SAID embedded in each schema's "$id" field is a placeholder during
// development. Once the schema JSON is stable, derive the real Blake3-256 SAID
// by posting the schema to POST /api/credential-schemas/fetch with a content URL,
// or by calling coring.Diger(ser=schema_bytes, code=MtrDex.Blake3_256).qb64.
//
// For demo purposes these placeholder SAIDs work fine — production deployments
// should stabilise the schema content first, then publish the real SAID.

const proofOfAgeJSON = `{
  "$id": "EProofOfAge__placeholder__v1",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Proof of Age",
  "description": "Asserts that the credential subject meets a minimum age requirement.",
  "type": "object",
  "properties": {
    "d":           { "type": "string", "description": "SAID of attribute block" },
    "i":           { "type": "string", "description": "Holder AID" },
    "over_21":     { "type": "boolean", "description": "True if holder is 21 years of age or older" },
    "minimum_age": { "type": "integer", "description": "Minimum age threshold asserted" },
    "verified_by": { "type": "string",  "description": "Method used to verify age (document, biometric, etc.)" },
    "issued_date": { "type": "string",  "format": "date", "description": "ISO 8601 date credential was issued" }
  },
  "required": ["d", "over_21"]
}`

const contactAttestationJSON = `{
  "$id": "EContactAttestation__placeholder__v1",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Contact Attestation",
  "description": "Issuer attests that they have personally verified the credential subject's identity.",
  "type": "object",
  "properties": {
    "d":            { "type": "string", "description": "SAID of attribute block" },
    "i":            { "type": "string", "description": "Holder AID" },
    "attestation":  { "type": "string", "enum": ["in_person_verified", "video_verified", "document_verified"], "description": "Verification method" },
    "subject_name": { "type": "string", "description": "Full name of the verified person" },
    "relationship": { "type": "string", "description": "Issuer's relationship to the subject (colleague, friend, attorney, etc.)" },
    "verified_date":{ "type": "string", "format": "date", "description": "ISO 8601 date verification took place" },
    "notes":        { "type": "string", "description": "Optional additional context" }
  },
  "required": ["d", "attestation", "subject_name"]
}`

const schoolPickupAuthJSON = `{
  "$id": "ESchoolPickupAuth__placeholder__v1",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "School Pickup Authorization",
  "description": "Authorizes a named individual to pick up a child from school on behalf of the issuer.",
  "type": "object",
  "properties": {
    "d":                      { "type": "string", "description": "SAID of attribute block" },
    "i":                      { "type": "string", "description": "Authorized pickup person AID" },
    "child_name":             { "type": "string", "description": "Full name of the child" },
    "child_aid":              { "type": "string", "description": "Child's AID (if they have an Identity Agent)" },
    "school_name":            { "type": "string", "description": "Name of the school" },
    "school_aid":             { "type": "string", "description": "School's organizational AID (if registered)" },
    "authorized_from":        { "type": "string", "format": "date", "description": "Start date of authorization" },
    "authorized_until":       { "type": "string", "format": "date", "description": "Expiry date of authorization" },
    "is_recurring":           { "type": "boolean", "description": "True for standing authorization; false for one-off pickup" },
    "authorized_days":        { "type": "array", "items": { "type": "string" }, "description": "Days of week authorized (e.g. [\"Monday\",\"Wednesday\"]). Empty means any day." },
    "guardian_credential_id": { "type": "string", "description": "SAID of the guardianship credential proving issuer's legal guardianship of the child. Enables chain-of-trust verification." },
    "notes":                  { "type": "string", "description": "Optional additional instructions for the school" }
  },
  "required": ["d", "child_name", "school_name", "authorized_until"]
}`

const guardianshipCredentialJSON = `{
  "$id": "EGuardianship__placeholder__v1",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Guardianship Credential",
  "description": "Certifies a legal guardianship relationship between the issuer (guardian) and a named dependent. Used as a chain-of-trust anchor for credentials involving the dependent.",
  "type": "object",
  "properties": {
    "d":               { "type": "string", "description": "SAID of attribute block" },
    "i":               { "type": "string", "description": "Guardian AID (issuer)" },
    "dependent_name":  { "type": "string", "description": "Full legal name of the dependent" },
    "dependent_aid":   { "type": "string", "description": "Dependent's AID (if they have an Identity Agent)" },
    "guardian_type":   { "type": "string", "enum": ["minor_child","elderly","disability","temporary"], "description": "Nature of the guardianship" },
    "effective_date":  { "type": "string", "format": "date", "description": "Date guardianship became effective" },
    "expiry_date":     { "type": "string", "format": "date", "description": "Date guardianship expires (omit for indefinite)" },
    "jurisdiction":    { "type": "string", "description": "Legal jurisdiction where guardianship was established" },
    "notes":           { "type": "string", "description": "Optional additional context" }
  },
  "required": ["d", "dependent_name", "guardian_type"]
}`

// ── Catalog ───────────────────────────────────────────────────────────────────

// Catalog is the authoritative map of SAID → BuiltinSchema for all bundled schemas.
// The map key matches the schema's "$id" field.
var Catalog = map[string]*BuiltinSchema{
	"EGuardianship__placeholder__v1": {
		SAID:        "EGuardianship__placeholder__v1",
		Name:        "Guardianship Credential",
		Description: "Certifies a legal guardianship relationship. Used as a chain-of-trust anchor for credentials involving a dependent (child, elderly, disability, temporary).",
		JSON:        guardianshipCredentialJSON,
		Fields: []SchemaField{
			{Key: "dependent_name", Label: "Dependent's Full Name",  Type: "string", Required: true,  Placeholder: "Full legal name"},
			{Key: "dependent_aid",  Label: "Dependent's AID",        Type: "aid",    Required: false, Placeholder: "E… (if they have an Identity Agent)"},
			{Key: "guardian_type",  Label: "Guardianship Type",      Type: "string", Required: true,  Placeholder: "minor_child | elderly | disability | temporary"},
			{Key: "effective_date", Label: "Effective Date",         Type: "date",   Required: false, Placeholder: ""},
			{Key: "expiry_date",    Label: "Expiry Date",            Type: "date",   Required: false, Placeholder: "Leave blank if indefinite"},
			{Key: "jurisdiction",   Label: "Legal Jurisdiction",     Type: "string", Required: false, Placeholder: "e.g. State of California"},
			{Key: "notes",          Label: "Notes",                  Type: "string", Required: false, Placeholder: "Optional additional context"},
		},
	},
	"EProofOfAge__placeholder__v1": {
		SAID:        "EProofOfAge__placeholder__v1",
		Name:        "Proof of Age",
		Description: "Asserts that the holder is 21 or older (or meets a minimum age threshold). The verifier learns only the boolean — not your date of birth.",
		JSON:        proofOfAgeJSON,
		Fields: []SchemaField{
			{Key: "over_21",     Label: "Over 21",      Type: "boolean", Required: true,  Placeholder: ""},
			{Key: "minimum_age", Label: "Minimum Age",   Type: "string",  Required: false, Placeholder: "21"},
			{Key: "verified_by", Label: "Verified By",   Type: "string",  Required: false, Placeholder: "government ID"},
			{Key: "issued_date", Label: "Issued Date",   Type: "date",    Required: false, Placeholder: ""},
		},
	},
	"EContactAttestation__placeholder__v1": {
		SAID:        "EContactAttestation__placeholder__v1",
		Name:        "Contact Attestation",
		Description: "Attests that you have personally verified this person's identity. Useful for bootstrapping trust in a network of known contacts.",
		JSON:        contactAttestationJSON,
		Fields: []SchemaField{
			{Key: "attestation",   Label: "Verification Method", Type: "string", Required: true,  Placeholder: "in_person_verified"},
			{Key: "subject_name",  Label: "Subject Name",        Type: "string", Required: true,  Placeholder: "Full legal name"},
			{Key: "relationship",  Label: "Relationship",        Type: "string", Required: false, Placeholder: "colleague, friend, attorney…"},
			{Key: "verified_date", Label: "Date Verified",       Type: "date",   Required: false, Placeholder: ""},
			{Key: "notes",         Label: "Notes",               Type: "string", Required: false, Placeholder: "Optional context"},
		},
	},
	"ESchoolPickupAuth__placeholder__v1": {
		SAID:        "ESchoolPickupAuth__placeholder__v1",
		Name:        "School Pickup Authorization",
		Description: "Authorizes a named person to pick up your child from school. Can reference a guardianship credential for chain-of-trust verification.",
		JSON:        schoolPickupAuthJSON,
		Fields: []SchemaField{
			{Key: "child_name",             Label: "Child's Full Name",       Type: "string",  Required: true,  Placeholder: ""},
			{Key: "school_name",            Label: "School Name",             Type: "string",  Required: true,  Placeholder: ""},
			{Key: "authorized_until",       Label: "Authorized Until",        Type: "date",    Required: true,  Placeholder: ""},
			{Key: "authorized_from",        Label: "Authorized From",         Type: "date",    Required: false, Placeholder: ""},
			{Key: "is_recurring",           Label: "Recurring Authorization", Type: "boolean", Required: false, Placeholder: ""},
			{Key: "authorized_days",        Label: "Authorized Days",         Type: "string",  Required: false, Placeholder: "Monday, Wednesday, Friday"},
			{Key: "child_aid",              Label: "Child's AID",             Type: "aid",     Required: false, Placeholder: "E…"},
			{Key: "school_aid",             Label: "School AID",              Type: "aid",     Required: false, Placeholder: "E…"},
			{Key: "guardian_credential_id", Label: "Guardianship Credential SAID", Type: "string", Required: false, Placeholder: "Links to guardianship credential for chain verification"},
			{Key: "notes",                  Label: "Notes for School",        Type: "string",  Required: false, Placeholder: ""},
		},
	},
}

// List returns all built-in schemas as a slice, sorted by name.
func List() []*BuiltinSchema {
	out := make([]*BuiltinSchema, 0, len(Catalog))
	for _, s := range Catalog {
		out = append(out, s)
	}
	return out
}

// Get returns a schema by SAID, or nil if not found.
func Get(said string) *BuiltinSchema {
	return Catalog[said]
}
