package schemas

import (
	"fmt"
	"strings"

	keri "github.com/grapeid/keri-go"
)

// Asset grants — one credential shape for every kind of asset.
//
// An asset is anything an identity owns and lets act for it: an AI agent, a
// website, a device, a service. Every asset gets two separate things, and they
// answer different questions:
//
//   - its IDENTITY, a delegated identifier anchored in the owner's key log,
//     which says whose it is;
//   - its GRANT, a credential the owner issues to that identifier from the
//     owner's registry, which says what it may do. Revoking the grant is an
//     event in the registry's log that anybody can check.
//
// Being delegated never implies permission. Authority lives in the grant, so it
// can be narrowed, widened, expired or withdrawn without touching the identity.
//
// Each kind of asset has its own grant schema, and each schema is built here
// from one template. The part every grant shares — who holds it, what kind of
// asset it is, what it was called, when it lapses — is therefore written once
// and cannot drift between kinds. Only the attributes particular to a kind are
// supplied per kind.
//
// The schemas follow the shape established ACDC schemas use: the whole
// credential is described (version, identifier, issuer, registry, schema,
// attributes), the attribute block may appear compacted to its own identifier,
// and nothing undeclared is accepted. Each schema's identifier is the Blake3-256
// digest of the schema itself, computed by the KERI library, so a verifier
// holding the document can confirm it is the one a credential names.

// AssetGrant is one kind of asset's grant schema.
type AssetGrant struct {
	// AssetType is the value every grant of this kind carries in asset_type, so
	// what kind of asset a credential is about can be read from the credential.
	AssetType string
	// Schema is the document, with its identifier filled in.
	Schema *BuiltinSchema

	kind assetGrantKind
}

// grantAttribute is one attribute of a grant's attribute block: its name, and
// its JSON Schema definition as written into the document.
type grantAttribute struct {
	name       string
	definition string
}

// assetGrantKind is what one kind of asset adds to the shared template.
type assetGrantKind struct {
	assetType   string
	title       string
	description string
	// attributes are the kind's own, in order, after the shared ones.
	attributes []grantAttribute
	// required are the kind's own required attributes.
	required []string
	fields   []SchemaField
	// edges admits an edges block: the credentials this one rests on, such as
	// the grant of whoever authorised it. A schema without it is the first
	// version of the template, kept so credentials issued under it still
	// resolve and verify.
	edges bool
}

// sharedGrantAttributes are the attributes every asset grant carries, in order.
// Order is part of a schema's identifier, so it is fixed here.
//
// "u" is a salt, present when the attribute block is issued private: a block
// drawn from a small, guessable set of values — a fixed asset type, a few
// capability ids — could otherwise be recovered from its digest by trying them.
func sharedGrantAttributes(assetType string) []grantAttribute {
	return []grantAttribute{
		{"d", `{"description": "Attributes block identifier", "type": "string"}`},
		{"u", `{"description": "Salt, when the attributes are issued private", "type": "string"}`},
		{"i", `{"description": "The asset's identifier: the holder of this grant", "type": "string"}`},
		{"dt", `{"description": "When the grant was issued", "type": "string", "format": "date-time"}`},
		{"asset_type", fmt.Sprintf(`{"description": "The kind of asset this grant is for", "type": "string", "const": %q}`, assetType)},
		{"name", `{"description": "The asset's name when the grant was issued", "type": "string"}`},
		{"valid_until", `{"description": "When the grant lapses. Absent, it holds until revoked", "type": "string", "format": "date-time"}`},
	}
}

var sharedGrantRequired = []string{"d", "i", "dt", "asset_type", "name"}

func (k assetGrantKind) allAttributes() []grantAttribute {
	attrs := append(sharedGrantAttributes(k.assetType), k.attributes...)
	if k.edges {
		// The request that authorised the credential, exactly as the person's
		// device signed it, beside the edge to their own grant: the edge says
		// whose authority this rests on, the request shows they used it.
		attrs = append(attrs,
			grantAttribute{"request", `{"description": "The request that authorised this, as it was signed: who signed it (a machine acting for a signer, or the identity's own key), the exact string signed, the signature, and the request's body, whose digest the string carries", "type": "object", "properties": {"kind": {"type": "string", "enum": ["controller", "owner"]}, "signer": {"type": "string"}, "signed": {"type": "string"}, "signature": {"type": "string"}, "body": {"type": "string"}}, "required": ["kind", "signer", "signed", "signature", "body"], "additionalProperties": false}`},
			grantAttribute{"about", `{"description": "What the authorising request named as the thing it acts on: the asset whose grant changes, or the machine waiting to become its body", "type": "string"}`})
	}
	return attrs
}

func buildAssetGrant(k assetGrantKind) (*AssetGrant, error) {
	attrs := k.allAttributes()
	props := make([]string, len(attrs))
	for i, a := range attrs {
		props[i] = fmt.Sprintf("%q: %s", a.name, a.definition)
	}
	required := append(append([]string{}, sharedGrantRequired...), k.required...)
	version, edgesProperty := "1.0.0", ""
	if k.edges {
		version = "1.1.0"
		edgesProperty = `,
    "e": {
      "oneOf": [
        {"description": "Edges block identifier", "type": "string"},
        {"description": "Edges: the credentials this one rests on, each by its identifier and schema", "type": "object"}
      ]
    }`
	}
	quoted := make([]string, len(required))
	for i, r := range required {
		quoted[i] = fmt.Sprintf("%q", r)
	}
	doc := fmt.Sprintf(`{
  "$id": "",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": %q,
  "description": %q,
  "type": "object",
  "credentialType": %q,
  "version": %q,
  "properties": {
    "v": {"description": "Credential version string", "type": "string"},
    "d": {"description": "Credential identifier", "type": "string"},
    "u": {"description": "Salt, when the credential is issued private", "type": "string"},
    "i": {"description": "Issuer: the identity that owns the asset", "type": "string"},
    "ri": {"description": "The registry the grant is issued in, where its revocation is recorded", "type": "string"},
    "s": {"description": "Schema identifier", "type": "string"},
    "a": {
      "oneOf": [
        {"description": "Attributes block identifier", "type": "string"},
        {
          "description": "Attributes block",
          "type": "object",
          "properties": {
            %s
          },
          "additionalProperties": false,
          "required": [%s]
        }
      ]
    }%s
  },
  "additionalProperties": false,
  "required": ["v", "d", "i", "ri", "s", "a"]
}`, k.title, k.description, credentialTypeName(k.title), version,
		strings.Join(props, ",\n            "), strings.Join(quoted, ", "), edgesProperty)

	built, err := keri.BuildSchema(keri.SchemaInput{Schema: []byte(doc)})
	if err != nil {
		return nil, fmt.Errorf("building the %s grant schema: %w", k.assetType, err)
	}
	said, err := keri.VerifySchema(built)
	if err != nil {
		return nil, fmt.Errorf("the %s grant schema does not match its own identifier: %w", k.assetType, err)
	}
	return &AssetGrant{
		AssetType: k.assetType,
		kind:      k,
		Schema: &BuiltinSchema{
			SAID:        said,
			Name:        k.title,
			Description: k.description,
			Fields:      k.fields,
			JSON:        string(built),
		},
	}, nil
}

// credentialTypeName is the title without spaces, the form ACDC schemas use for
// credentialType.
func credentialTypeName(title string) string {
	return strings.ReplaceAll(title, " ", "")
}

func mustAssetGrant(k assetGrantKind) *AssetGrant {
	g, err := buildAssetGrant(k)
	if err != nil {
		// The template is a constant. A failure here is a defect in this file,
		// and starting without the schema would issue grants nobody can resolve.
		panic(err)
	}
	return g
}

// AIAgentGrant says what one AI agent may do.
//
// What it carries is only what the gateway enforces when the AI agent acts:
//
//   - capabilities, the full list of what the AI agent may invoke — its ceiling;
//   - resource_constraints, per capability, the argument values it may use.
//
// The capability ids name definitions held by the issuing Identity Agent's
// capability registry. The grant does not pin which version of each definition
// it meant, so a definition changed after issue changes what the grant allows.
//
// What it deliberately does not carry, though other AI agent and delegation
// formats do:
//
//   - the role, prompt or model. Those configure the AI agent; they are not
//     authority, and changing them must not require a new grant;
//   - permission to delegate onward. This software offers an AI agent no way to
//     create AI agents of its own, so a field saying whether it may would assert
//     nothing;
//   - whom it may message, and conversation limits. Messaging another AI agent
//     is a capability like any other, agent.message.send, and whom it may
//     message is that capability's constraint on "to" — so it needs no field
//     of its own. Conversation limits are the Identity Agent's, applied to
//     every conversation, and grant nothing (ADR-047).
var aiAgentGrantKind = assetGrantKind{
	assetType: "ai_agent",
	title:     "AI Agent Grant",
	description: "What one AI agent may do, issued by the identity that owns it to the AI agent's " +
		"delegated identifier. The gateway admits the AI agent only to the capabilities named " +
		"here, within their constraints, while the grant is unrevoked and has not lapsed.",
	attributes: []grantAttribute{
		{"capabilities", `{"description": "The capability ids the AI agent may invoke: its ceiling", "type": "array", "items": {"type": "string"}, "uniqueItems": true}`},
		{"resource_constraints", `{"description": "Per capability id, per argument, the values the AI agent may use. Each list names at least one value", "type": "object", "minProperties": 1, "additionalProperties": {"type": "object", "minProperties": 1, "additionalProperties": {"type": "array", "minItems": 1, "items": {"type": "string"}}}}`},
	},
	required: []string{"capabilities"},
	fields: []SchemaField{
		{Key: "name", Label: "AI agent name", Type: "string", Required: true},
		{Key: "capabilities", Label: "Capabilities", Type: "string", Required: true, Placeholder: "capability ids the AI agent may invoke"},
		{Key: "resource_constraints", Label: "Resource Constraints", Type: "string", Placeholder: "optional per-capability limits"},
		{Key: "valid_until", Label: "Valid until", Type: "date", Placeholder: "Leave blank for no expiry"},
	},
}

// AIAgentGrant is issued with an edge to the grant of whoever authorised it,
// and AIAgentGrantV1, the first version, without one. Credentials issued under
// the first version still resolve and are still honoured.
var (
	AIAgentGrant   = mustAssetGrant(withEdges(aiAgentGrantKind))
	AIAgentGrantV1 = mustAssetGrant(aiAgentGrantKind)
)

// AIAgentBody says that one machine key is the body of one AI agent: requests
// signed by that key speak as the AI agent, at the grade recorded here. It is
// built from the same template as a grant — it, too, is a statement the owner
// makes about an asset and can withdraw — so it shares the holder, the kind,
// the name and the lapse, and its revocation is checked the same way.
//
// Revoking it stops that machine speaking as the AI agent; the AI agent and its
// grant are untouched, and another machine can be enrolled as its body.
var aiAgentBodyKind = assetGrantKind{
	assetType: "ai_agent",
	title:     "AI Agent Body",
	description: "That one machine key is the body of one AI agent: requests that key signs " +
		"speak as the AI agent, at the grade recorded here, while this is unrevoked.",
	attributes: []grantAttribute{
		{"host", `{"description": "The body's identifier, derived from its key", "type": "string"}`},
		{"verkey", `{"description": "The body's signing key", "type": "string"}`},
		{"keys_digest", `{"description": "Digest of the body's identifier, signing key and sealing keys, as the body signed it at enrolment", "type": "string"}`},
		{"grade", `{"description": "How strongly the body's key is held. hardware-asserted is the machine's own unverified word; the attested grades are recorded only once their evidence has been verified", "type": "string", "enum": ["software", "hardware-asserted", "hardware-attested", "attested-runtime"]}`},
		{"claimed_grade", `{"description": "The grade the machine claimed, kept so a claim lowered to grade is visible to whoever reads this", "type": "string"}`},
		{"platform", `{"description": "The platform the body reported, e.g. macos/arm64", "type": "string"}`},
		{"placement", `{"description": "Where the body is: computer, vm, cloud or device", "type": "string"}`},
	},
	required: []string{"host", "verkey", "keys_digest", "grade"},
	fields: []SchemaField{
		{Key: "host", Label: "Body", Type: "string", Required: true},
		{Key: "grade", Label: "Grade", Type: "string", Required: true},
	},
}

// AIAgentBody is issued with an edge to the grant of whoever approved the
// machine; AIAgentBodyV1, the first version, has none and is still honoured.
var (
	AIAgentBody   = mustAssetGrant(withEdges(aiAgentBodyKind))
	AIAgentBodyV1 = mustAssetGrant(aiAgentBodyKind)
)

// ControllerGrant says that one machine may act for the identity that issued
// it, as which of that identity's signers, at what grade and until when. A
// device paired to act for an identity was a line in a file only that identity
// could read, so nothing outside it could show a machine had been authorised.
// Issued into the identity's registry, the grant is anchored in its key log and
// its withdrawal is an event anybody can check, and what a person does from
// that machine can name it as the authority it rests on.
var ControllerGrant = mustAssetGrant(withEdges(assetGrantKind{
	assetType: "controller",
	title:     "Controller Grant",
	description: "That one machine may act for the identity that issued this, as the signer named " +
		"here, at the grade named here, while this is unrevoked and has not lapsed.",
	attributes: []grantAttribute{
		{"public_key", `{"description": "The machine's key, which its identifier names and its requests are checked against", "type": "string"}`},
		{"label", `{"description": "Which machine this is, as the person who paired it named it", "type": "string"}`},
		{"grade", `{"description": "enrolled for a machine the person keeps, scoped for one they borrowed", "type": "string", "enum": ["enrolled", "scoped"]}`},
		{"signer", `{"description": "The signer this machine acts as, when the identity has signers", "type": "string"}`},
	},
	required: []string{"public_key", "label", "grade"},
	fields: []SchemaField{
		{Key: "label", Label: "Machine", Type: "string", Required: true},
		{Key: "grade", Label: "Grade", Type: "string", Required: true},
	},
}))

func withEdges(k assetGrantKind) assetGrantKind {
	k.edges = true
	return k
}

// AssetGrants are every kind's grant schema, by asset type.
var AssetGrants = map[string]*AssetGrant{
	AIAgentGrant.AssetType: AIAgentGrant,
}

// assetCredentials are every schema built from the asset template, current
// and first versions alike, so every one issued can be resolved.
var assetCredentials = []*AssetGrant{AIAgentGrant, AIAgentGrantV1, AIAgentBody, AIAgentBodyV1, ControllerGrant}

func init() {
	for _, g := range assetCredentials {
		Catalog[g.Schema.SAID] = g.Schema
	}
}

// HasEdges reports whether credentials of this schema may name the
// credentials they rest on.
func (g *AssetGrant) HasEdges() bool { return g.kind.edges }

// CheckAttributes refuses an attribute block this grant's schema would refuse:
// a required attribute missing, an attribute the schema does not declare, or the
// wrong asset type. Checked before issuing, so the owner's registry never holds a
// grant its own schema rejects. It checks names and the asset type only; the
// value types are the issuing code's to get right.
func (g *AssetGrant) CheckAttributes(attrs map[string]interface{}) error {
	declared := map[string]bool{}
	for _, a := range g.kind.allAttributes() {
		declared[a.name] = true
	}
	for _, r := range append(append([]string{}, sharedGrantRequired...), g.kind.required...) {
		if r == "d" || r == "dt" {
			continue // filled in when the credential is made
		}
		if _, ok := attrs[r]; !ok {
			return fmt.Errorf("a %s grant needs %q", g.AssetType, r)
		}
	}
	for k := range attrs {
		if !declared[k] {
			return fmt.Errorf("a %s grant does not declare %q", g.AssetType, k)
		}
	}
	if attrs["asset_type"] != g.AssetType {
		return fmt.Errorf("a %s grant must say so in asset_type, not %v", g.AssetType, attrs["asset_type"])
	}
	return nil
}
