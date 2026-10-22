package schemas

import (
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The identifier is pinned. A grant names its schema by this digest, so a change
// to the schema is a new kind of credential that every verifier has to be told
// about — never something that should happen as a side effect of an edit here.
//
// Version 1.1.0 admits an edge to the grant of whoever authorised the AI agent,
// and the request they signed.
// The first version keeps its identifier, so grants issued under it still
// resolve; TestTheFirstVersionsKeepTheirIdentifiers holds it to that.
const pinnedAIAgentGrantSAID = "EFBzVtE4re52WTSdcrTU0m9K1He0I_yGFUPW0_VnNcCl"

func TestTheAIAgentGrantSchemaIsPinned(t *testing.T) {
	if AIAgentGrant.Schema.SAID != pinnedAIAgentGrantSAID {
		t.Fatalf("the AI agent grant schema is now %s, not %s. If the change is meant, it is "+
			"a new schema version: pin the new identifier and say so in the change.",
			AIAgentGrant.Schema.SAID, pinnedAIAgentGrantSAID)
	}
}

// A verifier holding only the document can recompute its identifier.
func TestEveryAssetGrantSchemaMatchesItsOwnIdentifier(t *testing.T) {
	for _, g := range assetCredentials {
		kind := g.Schema.Name
		said, err := keri.VerifySchema([]byte(g.Schema.JSON))
		if err != nil || said != g.Schema.SAID {
			t.Fatalf("%s: the document digests to %q (%v), not %s", kind, said, err, g.Schema.SAID)
		}
		if Get(g.Schema.SAID) != g.Schema {
			t.Fatalf("%s: not resolvable from the catalog by its identifier", kind)
		}
	}
}

// Every kind carries the shared attributes, and accepts nothing undeclared.
func TestEveryAssetGrantCarriesTheSharedAttributes(t *testing.T) {
	for _, g := range assetCredentials {
		kind := g.Schema.Name
		var doc struct {
			Properties struct {
				A struct {
					OneOf []struct {
						Properties           map[string]json.RawMessage `json:"properties"`
						AdditionalProperties *bool                      `json:"additionalProperties"`
						Required             []string                   `json:"required"`
					} `json:"oneOf"`
				} `json:"a"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(g.Schema.JSON), &doc); err != nil {
			t.Fatal(err)
		}
		block := doc.Properties.A.OneOf[1]
		for _, shared := range []string{"d", "i", "dt", "asset_type", "name", "valid_until"} {
			if _, ok := block.Properties[shared]; !ok {
				t.Fatalf("%s: the attribute block does not declare %q", kind, shared)
			}
		}
		if block.AdditionalProperties == nil || *block.AdditionalProperties {
			t.Fatalf("%s: the attribute block accepts attributes it does not declare", kind)
		}
	}
}

func TestAnAIAgentGrantRefusesWhatItsSchemaRefuses(t *testing.T) {
	good := map[string]interface{}{
		"i": "EAgent", "asset_type": "ai_agent", "name": "Research assistant",
		"capabilities": []string{"system.info.read"},
	}
	if err := AIAgentGrant.CheckAttributes(good); err != nil {
		t.Fatalf("a well-formed grant was refused: %v", err)
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"missing capabilities": func(m map[string]interface{}) { delete(m, "capabilities") },
		"undeclared attribute": func(m map[string]interface{}) { m["role"] = "orchestrator" },
		"wrong asset type":     func(m map[string]interface{}) { m["asset_type"] = "website" },
	} {
		bad := map[string]interface{}{}
		for k, v := range good {
			bad[k] = v
		}
		mutate(bad)
		if AIAgentGrant.CheckAttributes(bad) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

const pinnedAIAgentBodySAID = "EP4vfQ-HeN4wPPBhOsvpp_wYPOPPhjoLTPxXbejwSX0j"

const pinnedControllerGrantSAID = "EFEFZGF9FY-McUog829fuApbUiLwuG7-lNfXR93riOGX"

func TestTheControllerGrantSchemaIsPinned(t *testing.T) {
	if ControllerGrant.Schema.SAID != pinnedControllerGrantSAID {
		t.Fatalf("the controller grant schema is now %s, not %s. If the change is meant, it is "+
			"a new schema version: pin the new identifier and say so in the change.",
			ControllerGrant.Schema.SAID, pinnedControllerGrantSAID)
	}
}

// The first versions are what every grant and body credential issued before
// edges carries, so their identifiers must never move.
func TestTheFirstVersionsKeepTheirIdentifiers(t *testing.T) {
	if AIAgentGrantV1.Schema.SAID != "ENqXDGTD_fvwwkYGtaHby3J3Oahi3LzCE-ehDJxmHrBi" {
		t.Fatalf("the first AI agent grant schema moved to %s", AIAgentGrantV1.Schema.SAID)
	}
	if AIAgentBodyV1.Schema.SAID != "EBjOukYuabOuiVTRLSsE_gru3xww2CWAIAsFE6DCtVr1" {
		t.Fatalf("the first AI agent body schema moved to %s", AIAgentBodyV1.Schema.SAID)
	}
	for _, said := range []string{AIAgentGrantV1.Schema.SAID, AIAgentBodyV1.Schema.SAID} {
		if Catalog[said] == nil {
			t.Fatalf("%s is no longer served, so credentials issued under it cannot be resolved", said)
		}
	}
}

func TestTheAIAgentBodySchemaIsPinned(t *testing.T) {
	if AIAgentBody.Schema.SAID != pinnedAIAgentBodySAID {
		t.Fatalf("the AI agent body schema is now %s, not %s. If the change is meant, it is "+
			"a new schema version: pin the new identifier and say so in the change.",
			AIAgentBody.Schema.SAID, pinnedAIAgentBodySAID)
	}
}
