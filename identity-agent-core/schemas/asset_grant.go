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

// assetGrantKind is what one kind of asset adds to the shared template.
type assetGrantKind struct {
	assetType   string
	title       string
	description string
	// properties are JSON object members, in order, for the attribute block.
	properties []string
	// required are the kind's own required attributes.
	required []string
	fields   []SchemaField
}

// sharedGrantProperties are the attributes every asset grant carries, in order.
// Order is part of a schema's identifier, so it is fixed here.
func sharedGrantProperties(assetType string) []string {
	return []string{
		`"d": {"description": "Attributes block identifier", "type": "string"}`,
		`"i": {"description": "The asset's identifier: the holder of this grant", "type": "string"}`,
		`"dt": {"description": "When the grant was issued", "type": "string", "format": "date-time"}`,
		fmt.Sprintf(`"asset_type": {"description": "The kind of asset this grant is for", "type": "string", "const": %q}`, assetType),
		`"name": {"description": "The asset's name when the grant was issued", "type": "string"}`,
		`"valid_until": {"description": "When the grant lapses. Absent, it holds until revoked", "type": "string", "format": "date-time"}`,
	}
}

var sharedGrantRequired = []string{"d", "i", "dt", "asset_type", "name"}

func buildAssetGrant(k assetGrantKind) (*AssetGrant, error) {
	props := append(sharedGrantProperties(k.assetType), k.properties...)
	required := append(append([]string{}, sharedGrantRequired...), k.required...)
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
  "version": "1.0.0",
  "properties": {
    "v": {"description": "Credential version string", "type": "string"},
    "d": {"description": "Credential identifier", "type": "string"},
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
    }
  },
  "additionalProperties": false,
  "required": ["v", "d", "i", "ri", "s", "a"]
}`, k.title, k.description, credentialTypeName(k.title),
		strings.Join(props, ",\n            "), strings.Join(quoted, ", "))

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
// What it carries is only what the gateway enforces when the agent acts:
//
//   - capabilities, the full list of what the agent may invoke — its ceiling;
//   - resource_constraints, per capability, the argument values it may use.
//
// What it deliberately does not carry, though other agent and delegation
// formats do:
//
//   - the role, prompt or model. Those configure the agent; they are not
//     authority, and changing them must not require a new grant;
//   - permission to delegate onward. An AI agent cannot create agents of its
//     own, so a field saying whether it may would assert nothing;
//   - whom it may message, and conversation limits. Those arrive with agent
//     messaging, in a new version of this schema, because a field nothing
//     enforces reads as a guarantee the software does not give.
var AIAgentGrant = mustAssetGrant(assetGrantKind{
	assetType: "ai_agent",
	title:     "AI Agent Grant",
	description: "What one AI agent may do, issued by the identity that owns it to the agent's " +
		"delegated identifier. The gateway admits the agent only to the capabilities named " +
		"here, within their constraints, while the grant is unrevoked and has not lapsed.",
	properties: []string{
		`"capabilities": {"description": "The capability ids the agent may invoke: its ceiling", "type": "array", "items": {"type": "string"}, "uniqueItems": true}`,
		`"resource_constraints": {"description": "Per capability id, per argument, the values the agent may use", "type": "object", "additionalProperties": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}}}`,
	},
	required: []string{"capabilities"},
	fields: []SchemaField{
		{Key: "name", Label: "Agent name", Type: "string", Required: true},
		{Key: "capabilities", Label: "Capabilities", Type: "string", Required: true, Placeholder: "capability ids the agent may invoke"},
		{Key: "resource_constraints", Label: "Resource Constraints", Type: "string", Placeholder: "optional per-capability limits"},
		{Key: "valid_until", Label: "Valid until", Type: "date", Placeholder: "Leave blank for no expiry"},
	},
})

// AssetGrants are every kind's grant schema, by asset type.
var AssetGrants = map[string]*AssetGrant{
	AIAgentGrant.AssetType: AIAgentGrant,
}

func init() {
	for _, g := range AssetGrants {
		Catalog[g.Schema.SAID] = g.Schema
	}
}

// CheckAttributes refuses an attribute block this grant's schema would refuse:
// a required attribute missing, an attribute the schema does not declare, or the
// wrong asset type. Checked before issuing, so the owner's registry never holds a
// grant its own schema rejects. It checks names and the asset type only; the
// value types are the issuing code's to get right.
func (g *AssetGrant) CheckAttributes(attrs map[string]interface{}) error {
	declared := map[string]bool{}
	for _, p := range append(sharedGrantProperties(g.AssetType), g.kind.properties...) {
		declared[strings.Trim(strings.SplitN(p, ":", 2)[0], `" `)] = true
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
