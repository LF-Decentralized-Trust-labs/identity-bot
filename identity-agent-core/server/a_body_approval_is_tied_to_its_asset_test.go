package server

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/asset"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/schemas"

	"identity-agent-core/login"
)

// Runs a body credential through the whole of issuing — the owner's signed
// approval, the asset store the route looks in, authorisation.Check — so a
// resolver that is not wired in, or is wired to the wrong place, fails here
// rather than shipping.
func TestABodyIsIssuedOnlyOnTheApprovalOfItsOwnAsset(t *testing.T) {
	resetSeenSignatures(t)
	s, agent := grantWorld(t)
	h, err := asset.NewHandler(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.assetHandler = h
	root := agent.DelegatorAID
	identity, _ := s.DataStore.GetIdentity()
	seed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []asset.Asset{
		{ID: "agent-1", AssetType: "ai_agent", PairwiseAID: agent.PairwiseAID, DelegatorAID: root},
		{ID: "app-1", AssetType: "app", PairwiseAID: agent.PairwiseAID, DelegatorAID: root},
	} {
		if err := h.Store.UpsertAsset(a); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	approve := func(path string) coretypes.Authority {
		// A request authorises one credential, so each approval is its own.
		n++
		body := []byte(fmt.Sprintf(`{"n":%d}`, n))
		signed := canonicalOwnerRequest(identity.AID, "POST", path, time.Now().UTC().Format(time.RFC3339), body)
		sig, err := login.SignString(signed, seed)
		if err != nil {
			t.Fatal(err)
		}
		return coretypes.Authority{About: "body-1", Request: &coretypes.SignedRequest{
			Kind: "owner", Signer: identity.AID, Signed: signed, Signature: sig, Body: string(body)}}
	}
	claims := func() map[string]interface{} {
		return map[string]interface{}{"name": "Thing", "host": "BHost", "verkey": "DKey", "keys_digest": "EDigest", "grade": "software"}
	}
	issue := func(kind *schemas.AssetGrant, path string) error {
		_, err := s.issueAssetCredential(kind, agent.PairwiseAID, root, claims(), "", approve(path))
		return err
	}

	if err := issue(schemas.AIAgentBody, "/api/mcp/agents/agent-1/bodies/body-1/approve"); err != nil {
		t.Fatalf("an AI Agent Body on the approval of its AI agent was refused: %v", err)
	}
	if err := issue(schemas.AppBody, "/api/mcp/agents/app-1/bodies/body-1/approve"); err != nil {
		t.Fatalf("an App Body on the approval of its app was refused: %v", err)
	}
	for name, c := range map[string]struct {
		kind *schemas.AssetGrant
		path string
	}{
		"an App Body on an AI agent's approval":      {schemas.AppBody, "/api/mcp/agents/agent-1/bodies/body-1/approve"},
		"an AI Agent Body on an app's approval":      {schemas.AIAgentBody, "/api/mcp/agents/app-1/bodies/body-1/approve"},
		"a body on the approval of an unknown asset": {schemas.AIAgentBody, "/api/mcp/agents/nobody/bodies/body-1/approve"},
	} {
		err := issue(c.kind, c.path)
		if err == nil {
			t.Errorf("%s was issued", name)
		} else if !strings.Contains(err.Error(), "does not rest on the request") {
			t.Errorf("%s was refused for another reason: %v", name, err)
		}
	}
}
