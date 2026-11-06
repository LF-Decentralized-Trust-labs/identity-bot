package schemas

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"identity-agent-core/internal/contractcheck"

	keri "github.com/grapeid/keri-go"
)

// The six credential schemas that were first published under placeholder
// identifiers (ADR-045, amendment of 2026-11-05). Their identifiers are pinned
// here: a changed one is a new schema, and a credential issued under the old
// one still names the old.
type credentialSchemaCase struct {
	schema *BuiltinSchema
	file   string
	said   string
	legacy string
}

var credentialSchemaCases = []credentialSchemaCase{
	{Guardianship, "guardianship-credential-1.0.0.schema.json", "EOMEup2DCPsrLi48qJz-Ob0SYYVHFbyrlppkdlRRI3iX", "EGuardianship__placeholder__v1"},
	{ProofOfAge, "proof-of-age-1.0.0.schema.json", "EK4cPpuo4MSYfgbIDWNRjy5KGZYz7j-F47fFZmT4IZqo", "EProofOfAge__placeholder__v1"},
	{ContactAttestation, "contact-attestation-1.0.0.schema.json", "EIQswtql1ZQbjjP9LivDlGS-g8xEiWEQF6JGrmL2r2ap", "EContactAttestation__placeholder__v1"},
	{IdentityAttestation, "identity-attestation-1.0.0.schema.json", "ECgx83gKeaubFr1iX27EtgDk4FZprK8aLBilGRdwdvEA", "EIdentityAttestation__placeholder__v1"},
	{SchoolPickupAuthorization, "school-pickup-authorization-1.0.0.schema.json", "EHybuFOh_SpYgUR_cnRSq3Hj00IdekiTr34UAAa7Kx49", "ESchoolPickupAuth__placeholder__v1"},
	{EmployeeAuthorization, "employee-authorization-1.0.0.schema.json", "EDVkEBpme7o5heShoep_GqoIGDD9U8PisaFKqwrp9O51", "EEmployeeAuth__placeholder__v1"},
}

const credentialContracts = "../contracts/credential-schemas"
const credentialVectors = "credential-schema-vectors.json"

func TestTheCredentialSchemaIdentifiersArePinned(t *testing.T) {
	for _, c := range credentialSchemaCases {
		if c.schema.SAID != c.said {
			t.Errorf("%s is %s, pinned as %s. A changed identifier is a new schema: "+
				"credentials issued under the old one name the old.", c.schema.Name, c.schema.SAID, c.said)
		}
		if got, err := keri.VerifySchema([]byte(c.schema.JSON)); err != nil || got != c.said {
			t.Errorf("%s digests to %q (%v), not %s", c.schema.Name, got, err, c.said)
		}
		if Catalog[c.said] != c.schema {
			t.Errorf("%s is not in the Catalog under its identifier", c.schema.Name)
		}
		if Catalog[c.legacy] != nil {
			t.Errorf("the placeholder %s is still a catalog key", c.legacy)
		}
	}
	if len(credentialSchemaCases) != 6 {
		t.Fatal("six credential schemas are pinned")
	}
}

func TestAPlaceholderIdentifierStillNamesTheSchemaButIsNeverServedAsIt(t *testing.T) {
	for _, c := range credentialSchemaCases {
		if Get(c.legacy) != c.schema || Legacy(c.legacy) != c.schema {
			t.Errorf("%s no longer resolves to %s, so a credential issued under it cannot be shown by name", c.legacy, c.schema.Name)
		}
		if Equivalent(c.legacy) != c.said || Equivalent(c.said) != c.legacy {
			t.Errorf("%s and %s are not each other's equivalent", c.legacy, c.said)
		}
		for _, s := range List() {
			if s.SAID == c.legacy {
				t.Errorf("List offers the placeholder %s", c.legacy)
			}
		}
		if got, err := keri.VerifySchema([]byte(c.schema.JSON)); err != nil || got == c.legacy {
			t.Errorf("a placeholder must never be what a schema digests to")
		}
	}
	if Equivalent(AIAgentGrant.Schema.SAID) != "" || Legacy(AIAgentGrant.Schema.SAID) != nil {
		t.Fatal("an asset grant schema has no placeholder form")
	}
	if Get("EUnknown") != nil {
		t.Fatal("an unknown identifier resolved")
	}
}

func TestEmployeeAuthorizationIsInTheCatalog(t *testing.T) {
	found := false
	for _, s := range List() {
		if s.Name == "Employee Authorization" && s.SAID == EmployeeAuthorization.SAID {
			found = true
		}
	}
	if !found {
		t.Fatal("Employee Authorization is not listed, so the organisation app cannot find its identifier")
	}
}

// Every field the issue form offers is a declared attribute, and every
// required attribute is offered, so a form cannot produce a credential its own
// schema refuses.
func TestEachCredentialFormMatchesItsSchema(t *testing.T) {
	for _, c := range credentialSchemaCases {
		var doc struct {
			Properties struct {
				A struct {
					OneOf []struct {
						Properties map[string]json.RawMessage `json:"properties"`
						Required   []string                   `json:"required"`
					} `json:"oneOf"`
				} `json:"a"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(c.schema.JSON), &doc); err != nil || len(doc.Properties.A.OneOf) != 2 {
			t.Fatalf("%s: %v", c.schema.Name, err)
		}
		block := doc.Properties.A.OneOf[1]
		formKeys := map[string]bool{}
		for _, f := range c.schema.Fields {
			formKeys[f.Key] = true
			if _, ok := block.Properties[f.Key]; !ok {
				t.Errorf("%s: the form offers %q, which the schema does not declare", c.schema.Name, f.Key)
			}
		}
		for _, r := range block.Required {
			if r != "d" && !formKeys[r] {
				t.Errorf("%s: %q is required by the schema and not offered by the form", c.schema.Name, r)
			}
		}
	}
}

func TestThePublishedCredentialSchemasAreTheOnesBuilt(t *testing.T) {
	if contractcheck.Writing(t) {
		for _, c := range credentialSchemaCases {
			if err := os.WriteFile(filepath.Join(credentialContracts, c.file), []byte(c.schema.JSON), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, c := range credentialSchemaCases {
		raw, err := os.ReadFile(filepath.Join(credentialContracts, c.file))
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != c.schema.JSON {
			t.Fatalf("%s is not the %s schema this package builds. Regenerate it with "+
				"IA_WRITE_CONTRACTS=1 go test ./schemas, and treat a changed identifier as a new schema version.",
				c.file, c.schema.Name)
		}
	}
	entries, _ := filepath.Glob(filepath.Join(credentialContracts, "*.schema.json"))
	if len(entries) != len(credentialSchemaCases) {
		t.Fatalf("contracts/credential-schemas holds %d schemas, but %d are built", len(entries), len(credentialSchemaCases))
	}
}

// credentialVectorFile is the shape of credential-schema-vectors.json.
type credentialVectorFile struct {
	About    string `json:"about"`
	Accepted []struct {
		Name   string `json:"name"`
		File   string `json:"file"`
		SAID   string `json:"said"`
		Legacy string `json:"retired_placeholder"`
	} `json:"accepted"`
	Refused []struct {
		Name     string `json:"name"`
		Why      string `json:"why"`
		Document string `json:"document"`
		Claimed  string `json:"claimed_said"`
	} `json:"refused"`
}

// refusedCredentialSchemas are documents a verifier must not accept as the
// schema named, each breaking one rule.
func refusedCredentialSchemas() []struct{ Name, Why, Document, Claimed string } {
	g := Guardianship
	widened := strings.Replace(g.JSON, `"required":["d","dependent_name","guardian_type"]`, `"required":["d"]`, 1)
	return []struct{ Name, Why, Document, Claimed string }{
		{"a widened schema under the real identifier",
			"the guardianship schema with its required claims removed no longer digests to the identifier it carries",
			widened, g.SAID},
		{"a schema asked for by the wrong identifier",
			"a genuine Proof of Age schema is not the Guardianship schema, so it is refused when that is what was asked for",
			ProofOfAge.JSON, g.SAID},
		{"a placeholder identifier",
			"an identifier that is not the digest of the document confirms nothing",
			strings.Replace(g.JSON, g.SAID, "EGuardianship__placeholder__v1", 1), "EGuardianship__placeholder__v1"},
	}
}

func TestTheCredentialSchemaVectorsAreTheOnesBuilt(t *testing.T) {
	var want credentialVectorFile
	want.About = "The six credential schemas that replaced their placeholder identifiers (ADR-045, amendment of 2026-11-05). " +
		"accepted: the published file (in contracts/credential-schemas), with the identifier it must digest to: " +
		"the Blake3-256 of the document with $id replaced by 44 '#', as a CESR 'E' code. " +
		"refused: documents that must not be accepted as the schema named. " +
		"Checked independently by contracts/check_credential_schema_vectors.py."
	for _, c := range credentialSchemaCases {
		want.Accepted = append(want.Accepted, struct {
			Name   string `json:"name"`
			File   string `json:"file"`
			SAID   string `json:"said"`
			Legacy string `json:"retired_placeholder"`
		}{c.schema.Name, c.file, c.said, c.legacy})
	}
	for _, r := range refusedCredentialSchemas() {
		want.Refused = append(want.Refused, struct {
			Name     string `json:"name"`
			Why      string `json:"why"`
			Document string `json:"document"`
			Claimed  string `json:"claimed_said"`
		}{r.Name, r.Why, r.Document, r.Claimed})
	}
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wantJSON = append(wantJSON, '\n')
	if contractcheck.Writing(t) {
		if err := os.WriteFile(credentialVectors, wantJSON, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(credentialVectors)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wantJSON) {
		t.Fatalf("%s is not what this package produces. Regenerate it with IA_WRITE_CONTRACTS=1 go test ./schemas.", credentialVectors)
	}
	// The Go side of each refusal.
	for _, r := range refusedCredentialSchemas() {
		if said, err := keri.VerifySchema([]byte(r.Document)); err == nil && said == r.Claimed {
			t.Errorf("%s: accepted as %s", r.Name, r.Claimed)
		}
	}
	contractcheck.IndependentlyWith(t, "../contracts/check_credential_schema_vectors.py", credentialVectors, "blake3")
}
