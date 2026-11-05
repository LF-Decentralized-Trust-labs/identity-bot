package conversationbundle

import (
	"encoding/json"
	"testing"

	"identity-agent-core/authorisation"
	"identity-agent-core/schemas"
)

// A body credential's asset is told by the grant its holder holds, whether or
// not that grant names the asset in `about`: the grant POST /api/mcp/agents
// issues names none, and a first-version grant has no such field.
func TestTheAssetOfABodyIsTheOneItsHolderHoldsAGrantFor(t *testing.T) {
	const holder = "EHolder0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	grant := func(schema, holder, about string) *credential {
		c := &credential{schema: schema, holder: holder, attrs: map[string]json.RawMessage{}}
		if about != "" {
			c.attrs["about"], _ = json.Marshal(about)
		}
		return c
	}
	cases := []struct {
		name  string
		creds map[string]*credential
		id    string
		kind  string // "" = not known
	}{
		{"AI agent, grant with no about", map[string]*credential{"g": grant(schemas.AIAgentGrant.Schema.SAID, holder, "")}, "agent-1", authorisation.AssetKindAIAgent},
		{"AI agent, first-version grant", map[string]*credential{"g": grant(schemas.AIAgentGrantV1.Schema.SAID, holder, "")}, "agent-1", authorisation.AssetKindAIAgent},
		{"AI agent, creation grant and a later one naming it", map[string]*credential{
			"g": grant(schemas.AIAgentGrant.Schema.SAID, holder, ""), "h": grant(schemas.AIAgentGrant.Schema.SAID, holder, "agent-1")}, "agent-1", authorisation.AssetKindAIAgent},
		{"app", map[string]*credential{"g": grant(schemas.AppGrant.Schema.SAID, holder, "")}, "app-1", authorisation.AssetKindApp},
		{"grant names another asset", map[string]*credential{"g": grant(schemas.AIAgentGrant.Schema.SAID, holder, "agent-2")}, "agent-1", ""},
		{"grants of two kinds for one holder", map[string]*credential{
			"g": grant(schemas.AIAgentGrant.Schema.SAID, holder, ""), "h": grant(schemas.AppGrant.Schema.SAID, holder, "")}, "agent-1", ""},
		{"no grant held by the holder", map[string]*credential{"g": grant(schemas.AIAgentGrant.Schema.SAID, "EOther", "")}, "agent-1", ""},
	}
	for _, c := range cases {
		v := &verifier{creds: c.creds}
		got, ok := v.assetNamedBy(c.id, holder)
		if c.kind == "" {
			if ok {
				t.Errorf("%s: an asset was told, %+v", c.name, got)
			}
			continue
		}
		if !ok || got.Kind != c.kind || got.PairwiseAID != holder {
			t.Errorf("%s: got %+v, %v, want kind %s held by %s", c.name, got, ok, c.kind, holder)
		}
	}
	if _, ok := (&verifier{creds: cases[0].creds}).assetNamedBy("agent-1", ""); ok {
		t.Error("an asset was told for a body with no holder")
	}
}
