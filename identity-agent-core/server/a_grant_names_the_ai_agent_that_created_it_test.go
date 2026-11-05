package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/asset"
	"identity-agent-core/authorisation"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
)

type bodyKey struct{ priv ed25519.PrivateKey }

func (b bodyKey) PublicKey() ([]byte, error)    { return b.priv.Public().(ed25519.PublicKey), nil }
func (b bodyKey) Sign(d []byte) ([]byte, error) { return ed25519.Sign(b.priv, d), nil }

// aCreator is an AI agent holding the capabilities given, with the grant the
// owner issued it and the body credential that says its machine speaks as it.
type aCreator struct {
	s                 *CoreServer
	grant, body       string
	signer            bodyKey
	host              string
	issuer            string
	grantRec, bodyRec string
}

func newCreator(t *testing.T, caps []string) aCreator {
	t.Helper()
	resetSeenSignatures(t)
	s := appWorld(t)
	creator, err := s.assetHandler.ProvisionAgentAsset("Orchestrator", caps, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.issueCapabilityGrant(creator, coretypes.Authority{})
	if err != nil {
		t.Fatalf("the creator's grant: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 7
	signer := bodyKey{ed25519.NewKeyFromSeed(seed)}
	host, verkey, err := agentbody.Identity(signer)
	if err != nil {
		t.Fatal(err)
	}
	// The owner approves the machine as the creator's body.
	identity, _ := s.DataStore.GetIdentity()
	ownerSeed, err := s.identitySigningSeed()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"n":1}`)
	path := "/api/mcp/agents/" + creator.ID + "/bodies/" + host + "/approve"
	signed := canonicalOwnerRequest(identity.AID, "POST", path, time.Now().UTC().Format(time.RFC3339), body)
	sig, err := login.SignString(signed, ownerSeed)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]interface{}{"name": "Orchestrator", "host": host, "verkey": verkey, "keys_digest": "EDigest", "grade": "software"}
	bodySAID, err := s.issueAssetCredential(schemas.AIAgentBody, creator.PairwiseAID, creator.DelegatorAID, claims, "",
		coretypes.Authority{About: host, Request: &coretypes.SignedRequest{Kind: "owner", Signer: identity.AID, Signed: signed, Signature: sig, Body: string(body)}})
	if err != nil {
		t.Fatalf("the creator's body credential: %v", err)
	}
	return aCreator{s: s, grant: grant, body: bodySAID, signer: signer, host: host, issuer: creator.DelegatorAID}
}

var created int

// asks is what the creator's body signed to have an AI agent created, and the
// Authority a grant for it is issued under.
func (c aCreator) asks(t *testing.T, name string, caps []string) (*asset.Asset, coretypes.Authority) {
	t.Helper()
	worker, err := c.s.assetHandler.ProvisionAgentAsset(name, caps, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	created++
	ask, _ := json.Marshal(map[string]interface{}{"name": name, "capabilities": caps})
	signed := string(agentbody.SignedRequest{For: c.issuer, Host: c.host, Method: "POST", Target: authorisation.CreateAIAgentPath,
		Timestamp: time.Now().UTC().Format(time.RFC3339), Nonce: fmt.Sprintf("nonce-%d", created), Body: ask}.Bytes())
	sig, err := agentbody.Sign(c.signer, []byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	return worker, coretypes.Authority{
		CreatorGrant: c.grant, CreatorGrantSchema: schemas.AIAgentGrant.Schema.SAID, CreatorBody: c.body,
		Request: &coretypes.SignedRequest{Kind: authorisation.KindAIAgentBody, Signer: c.host, Signed: signed, Signature: sig, Body: string(ask)},
	}
}

func TestAGrantAuthorisedByAnAIAgentNamesItAndVerifies(t *testing.T) {
	c := newCreator(t, []string{"agent.create", "agent.message.send"})
	worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
	said, err := c.s.issueCapabilityGrant(worker, by)
	if err != nil {
		t.Fatalf("a grant its creator asked for was refused: %v", err)
	}
	rec, _ := c.s.DataStore.GetCredential(said)
	acdc, _ := base64.StdEncoding.DecodeString(rec.AcdcJson)
	var cred struct {
		E map[string]struct{ N, S string } `json:"e"`
	}
	if err := json.Unmarshal(acdc, &cred); err != nil {
		t.Fatal(err)
	}
	if e := cred.E["authorised_by"]; e.N != c.grant || e.S != schemas.AIAgentGrant.Schema.SAID {
		t.Fatalf("the grant does not name its creator's grant: %+v", cred.E)
	}
	if err := c.s.checkAuthorisation(said, by); err != nil {
		t.Fatalf("the grant issued does not verify against its request: %v", err)
	}
}

func TestAGrantIsRefusedWhenItsCreatorCannotCreate(t *testing.T) {
	refused := func(t *testing.T, c aCreator, by coretypes.Authority, worker *asset.Asset, want string) {
		t.Helper()
		_, err := c.s.issueCapabilityGrant(worker, by)
		if err == nil {
			t.Fatal("a grant that does not rest on a creator able to create was issued")
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refused for another reason: %v", err)
		}
	}
	t.Run("a creator without agent.create", func(t *testing.T) {
		c := newCreator(t, []string{"agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		refused(t, c, by, worker, "does not hold agent.create")
	})
	t.Run("a revoked creator", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		rec, _ := c.s.DataStore.GetCredential(c.grant)
		if _, _, err := c.s.withdrawCredential(rec); err != nil {
			t.Fatal(err)
		}
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		refused(t, c, by, worker, "revoked")
	})
	t.Run("no creator named at all", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		by.CreatorGrant, by.CreatorGrantSchema, by.CreatorBody = "", "", ""
		refused(t, c, by, worker, "does not rest on the request")
	})
	t.Run("a request not signed by the creator's body", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		by.Request.Signature = strings.Repeat("A", len(by.Request.Signature))
		refused(t, c, by, worker, "does not rest on the request")
	})
}

func TestTheOwnersOwnGrantsAreUnchangedByACreator(t *testing.T) {
	s := appWorld(t)
	a, err := s.assetHandler.ProvisionAgentAsset("Plain", []string{"agent.message.send"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	said, err := s.issueCapabilityGrant(a, coretypes.Authority{})
	if err != nil {
		t.Fatalf("an owner's grant was refused: %v", err)
	}
	rec, _ := s.DataStore.GetCredential(said)
	acdc, _ := base64.StdEncoding.DecodeString(rec.AcdcJson)
	if strings.Contains(string(acdc), "authorised_by") {
		t.Fatalf("an owner's own grant names an authorising credential: %s", acdc)
	}
}
