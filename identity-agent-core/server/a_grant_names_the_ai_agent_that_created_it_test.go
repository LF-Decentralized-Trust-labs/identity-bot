package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/asset"
	"identity-agent-core/authorisation"
	"identity-agent-core/drivers"
	"identity-agent-core/internal/coretypes"
	"identity-agent-core/login"
	"identity-agent-core/schemas"
	"identity-agent-core/store"
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
	return addCreator(t, appWorld(t), "Orchestrator", caps, nil, 7)
}

// addCreator gives s another AI agent holding caps, lapsing at until when set,
// whose body is the machine with the key made from seedByte.
func addCreator(t *testing.T, s *CoreServer, name string, caps []string, until *time.Time, seedByte byte) aCreator {
	t.Helper()
	creator, err := s.assetHandler.ProvisionAgentAsset(name, caps, nil, until, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := s.issueCapabilityGrant(creator, coretypes.Authority{})
	if err != nil {
		t.Fatalf("the creator's grant: %v", err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = seedByte
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
	claims := map[string]interface{}{"name": name, "host": host, "verkey": verkey, "keys_digest": "EDigest", "grade": "software"}
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
	return c.asksAt(t, name, caps, time.Now().UTC(), nil)
}

// asksAt is asks, signed at stamp, for a grant that lapses at until when set.
func (c aCreator) asksAt(t *testing.T, name string, caps []string, stamp time.Time, until *time.Time) (*asset.Asset, coretypes.Authority) {
	t.Helper()
	worker, err := c.s.assetHandler.ProvisionAgentAsset(name, caps, nil, until, nil)
	if err != nil {
		t.Fatal(err)
	}
	created++
	ask, _ := json.Marshal(map[string]interface{}{"name": name, "capabilities": caps})
	signed := string(agentbody.SignedRequest{For: c.issuer, Host: c.host, Method: "POST", Target: authorisation.CreateAIAgentPath,
		Timestamp: stamp.Format(time.RFC3339), Nonce: fmt.Sprintf("nonce-%d", created), Body: ask}.Bytes())
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
	// refused checks the grant is refused for the reason given, the one the
	// check itself returns: wrapped in the general "does not rest on the
	// request", which every refusal shares and so shows nothing.
	refused := func(t *testing.T, c aCreator, by coretypes.Authority, worker *asset.Asset, want string) {
		t.Helper()
		before, _ := c.s.DataStore.GetCredentials()
		_, err := c.s.issueCapabilityGrant(worker, by)
		if err == nil {
			t.Fatal("a grant that does not rest on a creator able to create was issued")
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refused for another reason than %q: %v", want, err)
		}
		if got, _ := c.s.DataStore.GetCredentials(); len(got) != len(before) {
			t.Fatalf("a refused grant left %d credentials behind", len(got)-len(before))
		}
	}
	t.Run("a creator without agent.create", func(t *testing.T) {
		c := newCreator(t, []string{"agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		refused(t, c, by, worker, "the creator's grant does not hold agent.create")
	})
	t.Run("a revoked creator", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		rec, _ := c.s.DataStore.GetCredential(c.grant)
		if _, _, err := c.s.withdrawCredential(rec); err != nil {
			t.Fatal(err)
		}
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		refused(t, c, by, worker, "the creator's grant")
		if _, err := c.s.issueCapabilityGrant(worker, by); !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("a revoked creator's grant was refused for another reason: %v", err)
		}
	})
	t.Run("a revoked creator body", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		rec, _ := c.s.DataStore.GetCredential(c.body)
		if _, _, err := c.s.withdrawCredential(rec); err != nil {
			t.Fatal(err)
		}
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		refused(t, c, by, worker, "the creator's body credential")
		if _, err := c.s.issueCapabilityGrant(worker, by); !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("a revoked creator body was refused for another reason: %v", err)
		}
	})
	t.Run("no creator named at all", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		by.CreatorGrant, by.CreatorGrantSchema, by.CreatorBody = "", "", ""
		refused(t, c, by, worker, errNoCreatorNamed.Error())
	})
	t.Run("a request not signed by the creator's body", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		by.Request.Signature = strings.Repeat("A", len(by.Request.Signature))
		refused(t, c, by, worker, "the request is not signed by the creator's body")
	})
	t.Run("a body credential that belongs to another AI agent", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		other := addCreator(t, c.s, "Other", []string{"agent.create", "agent.message.send"}, nil, 8)
		worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
		by.CreatorBody = other.body
		refused(t, c, by, worker, "the body credential is for")
	})
	t.Run("a grant wider than its creator's", func(t *testing.T) {
		c := newCreator(t, []string{"agent.create", "agent.message.send"})
		worker, by := c.asks(t, "Worker", []string{"agent.message.send", "system.info.read"})
		refused(t, c, by, worker, "which its creator's grant does not")
	})
	t.Run("a creator whose grant had lapsed when it asked", func(t *testing.T) {
		until := time.Now().UTC().Add(time.Hour)
		c := addCreator(t, appWorld(t), "Orchestrator", []string{"agent.create", "agent.message.send"}, &until, 7)
		resetSeenSignatures(t)
		worker, by := c.asksAt(t, "Worker", []string{"agent.message.send"}, until.Add(time.Minute), &until)
		refused(t, c, by, worker, "after the creator's grant lapsed")
	})
}

// With no creator named, a grant is refused before it is built, even where the
// engine builds nothing first: it is not issued and then withdrawn.
func TestAGrantNamingNoCreatorIsRefusedBeforeItIsIssued(t *testing.T) {
	c := newCreator(t, []string{"agent.create", "agent.message.send"})
	worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
	c.s.KeriDriver = unprepared{c.s.KeriDriver}
	for _, drop := range []struct {
		name string
		do   func(*coretypes.Authority)
	}{
		{"the grant", func(a *coretypes.Authority) { a.CreatorGrant = "" }},
		{"its schema", func(a *coretypes.Authority) { a.CreatorGrantSchema = "" }},
		{"the body credential", func(a *coretypes.Authority) { a.CreatorBody = "" }},
	} {
		t.Run(drop.name, func(t *testing.T) {
			named := by
			drop.do(&named)
			before, _ := c.s.DataStore.GetCredentials()
			if _, err := c.s.issueCapabilityGrant(worker, named); !errors.Is(err, errNoCreatorNamed) {
				t.Fatalf("a request that does not name its creator was refused for another reason: %v", err)
			}
			if after, _ := c.s.DataStore.GetCredentials(); len(after) != len(before) {
				t.Fatalf("a grant naming no creator was issued and withdrawn: %d credentials written", len(after)-len(before))
			}
		})
	}
	// Named in full, it is issued by the same engine.
	if _, err := c.s.issueCapabilityGrant(worker, by); err != nil {
		t.Fatalf("a grant its creator asked for was refused: %v", err)
	}
}

// unprepared is an engine that issues in one step, building nothing for a check
// first, as the interface alone gives it.
type unprepared struct{ drivers.KeriEngine }

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

// anAddonIssuingAIAgentGrants stands in for the add-on that makes AI agents,
// so a grant for one that the device holding the key signed is taken up.
func anAddonIssuingAIAgentGrants(t *testing.T) {
	t.Helper()
	onlyAddons(t, Addon{Name: "test agents", GrantKinds: map[*schemas.AssetGrant]GrantKind{
		schemas.AIAgentGrant: {StillWhatItGrants: func(*CoreServer, *authorisation.ToSign) error { return nil }},
	}})
}

// waitingGrant is the one grant that waits for the device, as it is kept.
func waitingGrant(t *testing.T, s *CoreServer) (store.SigningRequest, pendingIssuance) {
	t.Helper()
	reqs := waiting(t, s)
	if len(reqs) != 1 || reqs[0].Kind != signingKindGrant {
		t.Fatalf("what waits for the device: %+v", reqs)
	}
	body, _, _ := s.DataStore.GetPendingIssuance(reqs[0].ID)
	var p pendingIssuance
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatal(err)
	}
	return reqs[0], p
}

// A grant an AI agent asked for waits for the device that holds the key with
// its creator named, and is issued, resting on that creator, when the device
// signs it.
func TestAGrantAnAIAgentAskedForWaitsForTheDeviceAndIsIssued(t *testing.T) {
	c := newCreator(t, []string{"agent.create", "agent.message.send"})
	anAddonIssuingAIAgentGrants(t)
	worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
	e := moveTheKeyElsewhere(t, c.s)
	if _, err := c.s.issueCapabilityGrant(worker, by); !errors.Is(err, errKeyElsewhere) {
		t.Fatalf("a grant for the device to sign was answered %v", err)
	}
	req, p := waitingGrant(t, c.s)
	if p.Spec.CreatorGrant != c.grant || p.Spec.CreatorGrantSchema != schemas.AIAgentGrant.Schema.SAID || p.Spec.CreatorBody != c.body {
		t.Fatalf("the grant that waits does not keep its creator: %+v", p.Spec)
	}
	if got := p.Spec.by(); got.CreatorGrant != c.grant || got.CreatorBody != c.body || got.Request == nil || got.Request.Kind != authorisation.KindAIAgentBody {
		t.Fatalf("what the waiting grant rests on: %+v", got)
	}
	if rec := fulfil(t, c.s, req, e.seed); rec.Code != http.StatusOK {
		t.Fatalf("the device's signature: %d %s", rec.Code, rec.Body.String())
	}
	held := c.s.credentialsHeldBy(worker.PairwiseAID, schemas.AIAgentGrant.Schema.SAID, c.s.OwnerRootAID(), true)
	if len(held) != 1 {
		t.Fatalf("%d grants are in force for the AI agent the device signed for", len(held))
	}
	if err := c.s.checkAuthorisation(held[0].SAID, by); err != nil {
		t.Fatalf("the grant the device signed does not rest on its request: %v", err)
	}
}

// A creator revoked while the grant it asked for waits is not obeyed when the
// device signs: the grant is taken up, never in force, and withdrawn.
func TestAGrantWhoseCreatorWasRevokedWhileItWaitedIsNotIssued(t *testing.T) {
	revokeIt := map[string]func(c aCreator) string{
		"grant": func(c aCreator) string { return c.grant },
		"body":  func(c aCreator) string { return c.body },
	}
	for name, revoke := range revokeIt {
		t.Run(name, func(t *testing.T) {
			anAddonIssuingAIAgentGrants(t)
			c := newCreator(t, []string{"agent.create", "agent.message.send"})
			worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
			moveTheKeyElsewhere(t, c.s)
			if _, err := c.s.issueCapabilityGrant(worker, by); !errors.Is(err, errKeyElsewhere) {
				t.Fatalf("a grant for the device to sign was answered %v", err)
			}
			// The creator's credential is revoked in the key log, which moves it
			// on: the grant that waits is built again and asked for afresh.
			owner, _ := c.s.DataStore.GetIdentity()
			owner.DerivationIndex -= 1000
			if err := c.s.DataStore.SaveIdentity(*owner); err != nil {
				t.Fatal(err)
			}
			rec, _ := c.s.DataStore.GetCredential(revoke(c))
			if _, status, err := c.s.withdrawCredential(rec); err != nil || status != "revoked" {
				t.Fatalf("revoking the creator's credential: %q %v", status, err)
			}
			e := moveTheKeyElsewhere(t, c.s)
			stale, _ := waitingGrant(t, c.s)
			if rec := fulfil(t, c.s, stale, e.seed); rec.Code != http.StatusConflict {
				t.Fatalf("a grant built before the creator was revoked was answered %d %s", rec.Code, rec.Body.String())
			}
			fresh, _ := waitingGrant(t, c.s)
			rec2 := fulfil(t, c.s, fresh, e.seed)
			if !strings.Contains(rec2.Body.String(), "revoked") {
				t.Fatalf("signing a grant whose creator was revoked was answered %d %s", rec2.Code, rec2.Body.String())
			}
			if held := c.s.credentialsHeldBy(worker.PairwiseAID, schemas.AIAgentGrant.Schema.SAID, c.s.OwnerRootAID(), true); len(held) != 0 {
				t.Fatal("a grant is in force for an AI agent whose creator was revoked while it waited")
			}
		})
	}
}

// Where nothing is built first, the grant is checked once it is issued, and a
// creator revoked by then leaves no grant in force.
func TestAGrantIsWithdrawnWhenItsCreatorWasRevokedAndNothingWasBuiltFirst(t *testing.T) {
	c := newCreator(t, []string{"agent.create", "agent.message.send"})
	worker, by := c.asks(t, "Worker", []string{"agent.message.send"})
	c.s.KeriDriver = unprepared{c.s.KeriDriver}
	rec, _ := c.s.DataStore.GetCredential(c.grant)
	if _, _, err := c.s.withdrawCredential(rec); err != nil {
		t.Fatal(err)
	}
	_, err := c.s.issueCapabilityGrant(worker, by)
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("a grant whose creator was revoked was answered %v", err)
	}
	if held := c.s.credentialsHeldBy(worker.PairwiseAID, schemas.AIAgentGrant.Schema.SAID, c.s.OwnerRootAID(), true); len(held) != 0 {
		t.Fatal("a grant is in force for an AI agent whose creator was revoked")
	}
}
