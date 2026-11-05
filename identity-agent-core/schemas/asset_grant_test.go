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
// and the request they signed. Version 1.2.0 also admits a request signed by
// the body of the AI agent that created this one (kind ai_agent_body).
// The first version keeps its identifier, so grants issued under it still
// resolve; TestTheFirstVersionsKeepTheirIdentifiers holds it to that.
const pinnedAIAgentGrantSAID = "EKfsNSsWMAWPzRhwm3pzykK_nW8ByFJLG8d75CefTmR-"

// pinnedAIAgentGrantV11SAID is the second version, which was current until a
// grant could rest on a request an AI agent's body signed. Grants issued under
// it still resolve, so it must not move.
const pinnedAIAgentGrantV11SAID = "ELQTQ_EOsA3t1fCCcho6r9r2gma-LXqoQEzQbyliqpT_"

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

const pinnedAIAgentBodySAID = "EKLEEy6dupIoxaNTSE7MnWJwDyqs46hAPbTLM6wcCpW_"

const pinnedControllerGrantSAID = "EIeRD21QBpbVsf-IqRez6dCkLjn9SmOocTrxt050vv3I"

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
	if AIAgentGrantV11.Schema.SAID != pinnedAIAgentGrantV11SAID {
		t.Fatalf("the second AI agent grant schema moved to %s", AIAgentGrantV11.Schema.SAID)
	}
	if AIAgentBodyV1.Schema.SAID != "EBjOukYuabOuiVTRLSsE_gru3xww2CWAIAsFE6DCtVr1" {
		t.Fatalf("the first AI agent body schema moved to %s", AIAgentBodyV1.Schema.SAID)
	}
	for _, said := range []string{AIAgentGrantV1.Schema.SAID, AIAgentGrantV11.Schema.SAID, AIAgentBodyV1.Schema.SAID} {
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

// An app is an asset beside the AI agent (ADR-045, amended 2026-11-02). Its two
// schemas are pinned like the others.
const (
	pinnedAppGrantSAID = "EPHAxwxwkVY137Vc0hXPa5CVujNWZEsitFvzKYdNL4ek"
	pinnedAppBodySAID  = "EEh1VDLvJvXxfM7kLywJo3Yi0cRyukISFkY8m3FWPxmZ"
)

func TestTheAppSchemasArePinned(t *testing.T) {
	if AppGrant.Schema.SAID != pinnedAppGrantSAID || AppBody.Schema.SAID != pinnedAppBodySAID {
		t.Fatalf("the app schemas are now %s and %s, not %s and %s. If the change is meant, it is "+
			"a new schema version: pin the new identifiers and say so in the change.",
			AppGrant.Schema.SAID, AppBody.Schema.SAID, pinnedAppGrantSAID, pinnedAppBodySAID)
	}
}

// An app has no brain, no model and no conversation inbox: its grant declares
// none of what configures or talks for an AI agent, and refuses it if offered.
func TestAnAppGrantRefusesWhatItsSchemaRefuses(t *testing.T) {
	good := map[string]interface{}{
		"i": "EApp", "asset_type": "app", "name": "Task console",
		"capabilities": []string{"system.info.read"},
	}
	if err := AppGrant.CheckAttributes(good); err != nil {
		t.Fatalf("a well-formed app grant was refused: %v", err)
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"missing capabilities": func(m map[string]interface{}) { delete(m, "capabilities") },
		"a model":              func(m map[string]interface{}) { m["model"] = "any" },
		"a role":               func(m map[string]interface{}) { m["role"] = "orchestrator" },
		"an inbox":             func(m map[string]interface{}) { m["inbox"] = "conversation" },
		"an AI agent's type":   func(m map[string]interface{}) { m["asset_type"] = "ai_agent" },
	} {
		bad := map[string]interface{}{}
		for k, v := range good {
			bad[k] = v
		}
		mutate(bad)
		if AppGrant.CheckAttributes(bad) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// An app's body is the same statement as an AI agent's, in the same attributes,
// with only the kind different, so one body contract serves both.
func TestAnAppBodyIsAnAIAgentBodyOfAnotherKind(t *testing.T) {
	body := map[string]interface{}{
		"i": "EApp", "asset_type": "app", "name": "Task console", "host": "BHost", "verkey": "DKey",
		"keys_digest": "EDigest", "grade": "software", "placement": "vm",
	}
	if err := AppBody.CheckAttributes(body); err != nil {
		t.Fatalf("a well-formed app body was refused: %v", err)
	}
	if AIAgentBody.CheckAttributes(body) == nil {
		t.Fatal("an AI agent's body schema accepted an app's body")
	}
	body["asset_type"] = "ai_agent"
	if AppBody.CheckAttributes(body) == nil {
		t.Fatal("an app's body schema accepted an AI agent's body")
	}
	if AppBody.Schema.SAID == AIAgentBody.Schema.SAID || AppBody.AssetType != "app" {
		t.Fatal("an app body is not told apart from an AI agent body")
	}
	if !AppBody.HasEdges() || !AppGrant.HasEdges() {
		t.Fatal("an app credential cannot name the grant of whoever authorised it")
	}
}
