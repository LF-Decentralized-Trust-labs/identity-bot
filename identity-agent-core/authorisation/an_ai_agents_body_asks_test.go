package authorisation

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"identity-agent-core/agentbody"
	"identity-agent-core/internal/contractcheck"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// creation is every input to the check of a grant issued for an AI agent that
// another AI agent created: what the creator held, what its body signed, and
// the grant that rests on it. A field changed from the good one is a refusal.
type creation struct {
	capabilities  []string // the creator's
	forIssuer     string
	target        string
	method        string
	signedBody    string // the body the request carried
	givenBody     string // the body offered to the check
	otherKey      bool   // signed by a key that is not the creator's body
	revokedAt     string // the creator's grant is revoked then, when set
	stamp         string
	createdHolder string
	grantSchema   string // the schema the edge names
	createdSchema string
	signedKind    string
}

const (
	vectorBase    = "2026-11-02T12:00:00Z"
	vectorCreator = "ECreatorAIAgent0123456789ABCDEFGHIJKLMNOPQRS"
	vectorCreated = "ECreatedAIAgent0123456789ABCDEFGHIJKLMNOPQRS"
	vectorBodyReq = `{"name":"Worker","capabilities":["agent.message.send"]}`
)

func vectorSeed(offset byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i) + offset
	}
	return seed
}

type seedSigner struct{ priv ed25519.PrivateKey }

func (s seedSigner) PublicKey() ([]byte, error)    { return s.priv.Public().(ed25519.PublicKey), nil }
func (s seedSigner) Sign(d []byte) ([]byte, error) { return ed25519.Sign(s.priv, d), nil }

// CreationCase is one case in the published vectors: the inputs to Check, and
// whether it accepts them.
type CreationCase struct {
	Name            string   `json:"name"`
	Credential      string   `json:"credential"`
	CreatorGrant    string   `json:"creator_grant"`
	CreatorGrantLog []string `json:"creator_grant_log"`
	CreatorBody     string   `json:"creator_body"`
	CreatorBodyLog  []string `json:"creator_body_log"`
	RequestBody     string   `json:"request_body"`
	Accepted        bool     `json:"accepted"`
	// Because is the sentence a refusal contains, so an implementation can see
	// it refused for the reason the vector means.
	Because string `json:"because,omitempty"`
}

// CreationVectors is the published set.
type CreationVectors struct {
	About        string         `json:"about"`
	SeedHex      string         `json:"seed_hex"`
	OtherSeedHex string         `json:"other_seed_hex"`
	Issuer       string         `json:"issuer"`
	Registry     string         `json:"registry"`
	Host         string         `json:"host"`
	Verkey       string         `json:"verkey"`
	SignedKind   string         `json:"request_kind"`
	GrantSchema  string         `json:"grant_schema"`
	Cases        []CreationCase `json:"cases"`
}

const creationVectorFile = "ai-agent-body-request-vectors.json"

// aCreation builds the good creation, then lets change spoil it.
func aCreation(t *testing.T, name string, change func(*creation)) CreationCase {
	t.Helper()
	c := creation{
		capabilities: []string{"agent.create", "agent.message.send"}, forIssuer: org, target: CreateAIAgentPath, method: "POST",
		signedBody: vectorBodyReq, givenBody: vectorBodyReq, stamp: vectorBase, createdHolder: vectorCreated,
		grantSchema: schemas.AIAgentGrant.Schema.SAID, createdSchema: schemas.AIAgentGrant.Schema.SAID, signedKind: KindAIAgentBody,
	}
	if change != nil {
		change(&c)
	}
	base, _ := time.Parse(time.RFC3339, vectorBase)
	w := &world{t: t}
	bodyKey := ed25519.NewKeyFromSeed(vectorSeed(0))
	host, verkey, err := agentbody.Identity(seedSigner{bodyKey})
	if err != nil {
		t.Fatal(err)
	}
	signer := seedSigner{bodyKey}
	if c.otherKey {
		signer = seedSigner{ed25519.NewKeyFromSeed(vectorSeed(100))}
	}

	grantAt, bodyAt := base.Add(-24*time.Hour), base.Add(-24*time.Hour+5*time.Minute)
	grant, grantSAID := w.build(c.grantSchema, vectorCreator, grantAt, map[string]interface{}{
		"asset_type": "ai_agent", "name": "Orchestrator", "capabilities": c.capabilities}, nil)
	body, bodySAID := w.build(schemas.AIAgentBody.Schema.SAID, vectorCreator, bodyAt, map[string]interface{}{
		"asset_type": "ai_agent", "name": "Orchestrator", "host": host, "verkey": verkey,
		"keys_digest": "EDigest", "grade": "software"}, nil)
	logOf := func(said string, at time.Time, revokedAt string) [][]byte {
		iss, err := keri.BuildIssuance(keri.IssuanceInput{CredentialSAID: said, Registry: registry, DT: at.Format(telTime)})
		if err != nil {
			t.Fatal(err)
		}
		out := [][]byte{iss}
		if revokedAt != "" {
			ev, _ := keri.VerifyTELEvent(iss)
			rt, _ := time.Parse(time.RFC3339, revokedAt)
			rev, err := keri.BuildRevocation(keri.RevocationInput{CredentialSAID: said, Registry: registry, PriorISSSAID: ev.SAID, DT: rt.Format(telTime)})
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, rev)
		}
		return out
	}
	grantLog, bodyLog := logOf(grantSAID, grantAt, c.revokedAt), logOf(bodySAID, bodyAt, "")

	signed := string(agentbody.SignedRequest{For: c.forIssuer, Host: host, Method: c.method, Target: c.target,
		Timestamp: c.stamp, Nonce: "request-nonce-0001", Body: []byte(c.signedBody)}.Bytes())
	sig, err := agentbody.Sign(signer, []byte(signed))
	if err != nil {
		t.Fatal(err)
	}
	asked, err := Asked(c.signedBody)
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]interface{}{"kind": c.signedKind, "signer": host, "signed": signed, "signature": sig, "asked": asked}
	created, _ := w.build(c.createdSchema, c.createdHolder, base.Add(30*time.Second), map[string]interface{}{
		"asset_type": "ai_agent", "name": "Worker", "capabilities": []string{"agent.message.send"}, "request": request},
		map[string]interface{}{"authorised_by": map[string]interface{}{"n": grantSAID, "s": c.grantSchema}})

	strs := func(in [][]byte) []string {
		out := []string{}
		for _, x := range in {
			out = append(out, string(x))
		}
		return out
	}
	return CreationCase{Name: name, Credential: string(created), CreatorGrant: string(grant), CreatorGrantLog: strs(grantLog),
		CreatorBody: string(body), CreatorBodyLog: strs(bodyLog), RequestBody: c.givenBody}
}

func creationCases(t *testing.T) []CreationCase {
	t.Helper()
	refuse := func(name, because string, change func(*creation)) CreationCase {
		c := aCreation(t, name, change)
		c.Because = because
		return c
	}
	good := aCreation(t, "an AI agent whose grant holds agent.create asks for another", nil)
	good.Accepted = true
	return []CreationCase{
		good,
		refuse("the creator's grant does not hold agent.create", "does not hold agent.create", func(c *creation) { c.capabilities = []string{"agent.message.send"} }),
		refuse("the request is signed by a key that is not the creator's body", "not signed by the creator's body", func(c *creation) { c.otherKey = true }),
		refuse("the request was for another Identity Agent", "not for the issuer", func(c *creation) { c.forIssuer = "EAnotherIdentityAgent0123456789ABCDEFGHIJKLM" }),
		refuse("the body given is not the body signed", "not the body that was signed", func(c *creation) { c.givenBody = `{"name":"Worker","capabilities":["agent.create"]}` }),
		refuse("the credential asks for what the signed body did not", "asked for", func(c *creation) {
			c.signedBody = `{"name":"Other","capabilities":["agent.message.send"]}`
			c.givenBody = c.signedBody
		}),
		refuse("the request is to a route that is not the creator's channel", "not a request a body signs", func(c *creation) { c.target = "/api/mcp/agents" }),
		refuse("the request is to a route that grants nothing", "grants an AI agent anything", func(c *creation) { c.target = "/api/agent-host/inbox" }),
		refuse("the creator's grant was revoked before the new grant was issued", "revoked before", func(c *creation) { c.revokedAt = "2026-11-02T12:00:10Z" }),
		refuse("the request was made long before the grant it authorised", "long before", func(c *creation) { c.stamp = "2026-11-02T11:00:00Z" }),
		refuse("the grant is the creator's own", "own request", func(c *creation) { c.createdHolder = vectorCreator }),
		refuse("the grant is of a version that does not admit the kind", "version that admits", func(c *creation) { c.createdSchema = schemas.AIAgentGrantV11.Schema.SAID }),
	}
}

func creationVectorSet(t *testing.T) CreationVectors {
	t.Helper()
	host, verkey, err := agentbody.Identity(seedSigner{ed25519.NewKeyFromSeed(vectorSeed(0))})
	if err != nil {
		t.Fatal(err)
	}
	return CreationVectors{
		About: "A grant issued for an AI agent that another AI agent created rests on a request the creator's body signed. " +
			"Each case gives the grant, the creator's grant and body credential with their logs, and the request's body, and says " +
			"whether authorisation.Check accepts them. Times are fixed, so every value here is reproducible from the seeds.",
		SeedHex: hexOf(vectorSeed(0)), OtherSeedHex: hexOf(vectorSeed(100)), Issuer: org, Registry: registry, Host: host, Verkey: verkey,
		SignedKind: KindAIAgentBody, GrantSchema: schemas.AIAgentGrant.Schema.SAID, Cases: creationCases(t),
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(digits[x>>4])
		sb.WriteByte(digits[x&15])
	}
	return sb.String()
}

func checkCreation(c CreationCase) error {
	var glog, blog [][]byte
	for _, x := range c.CreatorGrantLog {
		glog = append(glog, []byte(x))
	}
	for _, x := range c.CreatorBodyLog {
		blog = append(blog, []byte(x))
	}
	return Check(Input{Credential: []byte(c.Credential), Grant: []byte(c.CreatorGrant), GrantLog: glog,
		CreatorBody: []byte(c.CreatorBody), CreatorBodyLog: blog, Body: c.RequestBody, HaveBody: true})
}

// Every published case is what this package produces, and Check does with each
// what the file says. A change to the request, the grants or the rule breaks
// this before it breaks another implementation.
func TestThePublishedAIAgentBodyRequestVectorsHold(t *testing.T) {
	want := creationVectorSet(t)
	if contractcheck.Writing(t) {
		raw, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(creationVectorFile, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(creationVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var got CreationVectors
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s is not what this package produces. Regenerate it with IA_WRITE_CONTRACTS=1 go test ./authorisation and review the change", creationVectorFile)
	}
	for _, c := range got.Cases {
		err := checkCreation(c)
		switch {
		case c.Accepted && err != nil:
			t.Errorf("%s: refused: %v", c.Name, err)
		case !c.Accepted && err == nil:
			t.Errorf("%s: accepted", c.Name)
		case !c.Accepted && !strings.Contains(err.Error(), c.Because):
			t.Errorf("%s: refused for another reason than %q: %v", c.Name, c.Because, err)
		}
	}
}

// The grant's authority names the creator: the credential rests on the
// creator's grant by an edge, and says so in what it rests on.
func TestAGrantMadeByAnAIAgentNamesItsCreator(t *testing.T) {
	c := aCreation(t, "good", nil)
	verified, err := keri.VerifyCredential([]byte(c.Credential))
	if err != nil {
		t.Fatal(err)
	}
	rests, err := WhatItRestsOn(verified)
	if err != nil {
		t.Fatal(err)
	}
	creator, err := keri.VerifyCredential([]byte(c.CreatorGrant))
	if err != nil {
		t.Fatal(err)
	}
	if rests.Grant != creator.SAID || rests.GrantSchema != schemas.AIAgentGrant.Schema.SAID {
		t.Fatalf("the grant rests on %+v, not on its creator's grant %s", rests, creator.SAID)
	}
	if rests.RequestKind != KindAIAgentBody {
		t.Fatalf("the request is of kind %q", rests.RequestKind)
	}
}

// A machine's or the owner's request cannot be turned into the creator's
// channel, nor the reverse.
func TestTheCreatorsChannelIsNotTheOwners(t *testing.T) {
	w := newWorld(t)
	req := w.signs("POST", CreateAIAgentPath, vectorBodyReq, ago(time.Minute))
	cred := w.aGrant(req, []string{"agent.message.send"}, "")
	if err := w.check(cred); err == nil || !strings.Contains(err.Error(), "grants an AI agent anything") {
		t.Fatalf("a machine's request to the creator's route: %v", err)
	}
}
