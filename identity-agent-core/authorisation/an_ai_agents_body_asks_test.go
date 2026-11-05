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
	// createdCaps are the capabilities the new AI agent is granted (and asked
	// for); creatorLimits and createdLimits are the resource_constraints of the
	// creator's grant and the new one, when set.
	createdCaps                  []string
	creatorLimits, createdLimits map[string]map[string][]string
	// creatorUntil and createdUntil are the valid_until of the creator's grant
	// and the new one, when set. about is the AI agent a request to change an
	// existing one's grant is about.
	creatorUntil, createdUntil string
	about                      string
}

const (
	vectorBase    = "2026-11-02T12:00:00Z"
	vectorCreator = "ECreatorAIAgent0123456789ABCDEFGHIJKLMNOPQRS"
	vectorCreated = "ECreatedAIAgent0123456789ABCDEFGHIJKLMNOPQRS"
	vectorBodyReq = `{"name":"Worker","capabilities":["agent.message.send"]}`
	toOnlyA       = "agent-a"
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
		createdCaps: []string{"agent.message.send"}, stamp: vectorBase, createdHolder: vectorCreated,
		grantSchema: schemas.AIAgentGrant.Schema.SAID, createdSchema: schemas.AIAgentGrant.Schema.SAID, signedKind: KindAIAgentBody,
	}
	if change != nil {
		change(&c)
	}
	if c.signedBody == "" {
		ask := struct {
			Name         string                         `json:"name"`
			Capabilities []string                       `json:"capabilities"`
			Limits       map[string]map[string][]string `json:"resource_constraints,omitempty"`
		}{"Worker", c.createdCaps, c.createdLimits}
		raw, _ := json.Marshal(ask)
		c.signedBody = string(raw)
	}
	if c.givenBody == "" {
		c.givenBody = c.signedBody
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
	creatorAttrs := map[string]interface{}{"asset_type": "ai_agent", "name": "Orchestrator", "capabilities": c.capabilities}
	if c.creatorLimits != nil {
		creatorAttrs["resource_constraints"] = c.creatorLimits
	}
	if c.creatorUntil != "" {
		creatorAttrs["valid_until"] = c.creatorUntil
	}
	grant, grantSAID := w.build(c.grantSchema, vectorCreator, grantAt, creatorAttrs, nil)
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
	createdAttrs := map[string]interface{}{
		"asset_type": "ai_agent", "name": "Worker", "capabilities": c.createdCaps, "request": request}
	if c.createdLimits != nil {
		createdAttrs["resource_constraints"] = c.createdLimits
	}
	if c.createdUntil != "" {
		createdAttrs["valid_until"] = c.createdUntil
	}
	if c.about != "" {
		createdAttrs["about"] = c.about
	}
	created, _ := w.build(c.createdSchema, c.createdHolder, base.Add(30*time.Second), createdAttrs,
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
	accept := func(name string, change func(*creation)) CreationCase {
		c := aCreation(t, name, change)
		c.Accepted = true
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
		refuse("the new AI agent would hold a capability its creator's grant does not", "which its creator's grant does not", func(c *creation) {
			c.createdCaps = []string{"agent.message.send", "system.info.read"}
		}),
		refuse("the creator limits an argument that the new AI agent's grant leaves unlimited", "has no limit on", func(c *creation) {
			c.creatorLimits = map[string]map[string][]string{"agent.message.send": {"to": {toOnlyA}}}
		}),
		refuse("the new AI agent may use a value its creator's limit does not allow", "does not allow", func(c *creation) {
			c.creatorLimits = map[string]map[string][]string{"agent.message.send": {"to": {toOnlyA}}}
			c.createdLimits = map[string]map[string][]string{"agent.message.send": {"to": {toOnlyA, "agent-b"}}}
		}),
		accept("the new AI agent is limited within its creator's limit", func(c *creation) {
			c.creatorLimits = map[string]map[string][]string{"agent.message.send": {"to": {toOnlyA, "agent-b"}}}
			c.createdLimits = map[string]map[string][]string{"agent.message.send": {"to": {toOnlyA}}}
		}),
		refuse("the creator's grant lapses and the new AI agent's grant has no end", "has no end", func(c *creation) {
			c.creatorUntil = "2026-11-09T12:00:00Z"
		}),
		refuse("the new AI agent's grant lapses after its creator's", "after its creator's grant lapses", func(c *creation) {
			c.creatorUntil, c.createdUntil = "2026-11-09T12:00:00Z", "2026-11-10T12:00:00Z"
		}),
		accept("the new AI agent's grant lapses when its creator's does", func(c *creation) {
			c.creatorUntil, c.createdUntil = "2026-11-09T12:00:00Z", "2026-11-09T12:00:00Z"
		}),
		accept("the new AI agent's grant lapses before its creator's", func(c *creation) {
			c.creatorUntil, c.createdUntil = "2026-11-09T12:00:00Z", "2026-11-08T12:00:00Z"
		}),
		accept("an AI agent whose grant holds agent.create sets the repositories of another", func(c *creation) {
			c.method, c.target, c.about = "PUT", "/api/agent-host/agents/agent-1/github", "agent-1"
			c.capabilities = []string{"agent.create", "code.repository.read"}
			c.createdCaps = []string{"code.repository.read"}
			c.createdLimits = map[string]map[string][]string{"code.repository.read": {"repository": {"acme/docs"}, "repository_id": {"101"}}}
			c.signedBody = `{"repositories":[{"repository":"acme/docs","access":"read"}]}`
		}),
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

// An implementation written from the ADR's prose, in another language, agrees
// with the vector file: that each credential is its own digest, that the body's
// signature holds, and that each refused case breaks the one rule it is about.
func TestAnIndependentImplementationAgreesWithTheAIAgentBodyRequestVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_ai_agent_body_request_vectors.py", creationVectorFile, "blake3")
}

// withinCreator's attributes, as a grant carries them.
func grantAttrs(t *testing.T, caps []string, extra map[string]interface{}) map[string]json.RawMessage {
	t.Helper()
	m := map[string]interface{}{"capabilities": caps}
	for k, v := range extra {
		m[k] = v
	}
	raw, _ := json.Marshal(m)
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// An AI agent cannot outlive its creator: where the creator's grant lapses, the
// grant of the AI agent it created exists and lapses no later.
func TestACreatedAIAgentDoesNotOutliveItsCreator(t *testing.T) {
	caps := []string{"agent.create", "agent.message.send"}
	const end = "2026-11-09T12:00:00Z"
	until := func(v string) map[string]interface{} {
		if v == "" {
			return nil
		}
		return map[string]interface{}{"valid_until": v}
	}
	for _, c := range []struct {
		name             string
		creator, created string
		because          string // empty: accepted
	}{
		{"neither lapses", "", "", ""},
		{"only the new one lapses", "", end, ""},
		{"the new one has no end", end, "", "has no end"},
		{"the new one lapses later", end, "2026-11-09T12:00:01Z", "after its creator"},
		{"the new one lapses later in another zone", end, "2026-11-09T12:30:00-01:00", "after its creator"},
		{"the new one lapses when its creator does", end, end, ""},
		{"the same instant in another zone", end, "2026-11-09T13:00:00+01:00", ""},
		{"the new one lapses sooner", end, "2026-11-09T11:59:59Z", ""},
		{"the new one's end is unreadable", end, "soon", "unreadably"},
	} {
		err := withinCreator(grantAttrs(t, caps, until(c.creator)), grantAttrs(t, []string{"agent.message.send"}, until(c.created)))
		switch {
		case c.because == "" && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.because != "" && (err == nil || !strings.Contains(err.Error(), c.because)):
			t.Errorf("%s: want a refusal for %q, got %v", c.name, c.because, err)
		}
	}
}

// A limit that names no value is refused, as the schema refuses it: an empty
// list is a subset of any list, so it would pass for being within the creator's.
func TestAnEmptyListOfValuesIsRefused(t *testing.T) {
	caps := []string{"agent.create", "agent.message.send"}
	limit := func(vals ...string) map[string]interface{} {
		return map[string]interface{}{"resource_constraints": map[string]map[string][]string{"agent.message.send": {"to": vals}}}
	}
	if err := withinCreator(grantAttrs(t, caps, limit(toOnlyA)), grantAttrs(t, []string{"agent.message.send"}, limit())); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("the new grant lists no values: %v", err)
	}
	if err := withinCreator(grantAttrs(t, caps, nil), grantAttrs(t, []string{"agent.message.send"}, limit())); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("the new grant lists no values where its creator has no limit: %v", err)
	}
	if err := withinCreator(grantAttrs(t, caps, limit()), grantAttrs(t, []string{"agent.message.send"}, limit(toOnlyA))); err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("the creator's grant lists no values: %v", err)
	}
	if err := withinCreator(grantAttrs(t, caps, limit(toOnlyA)), grantAttrs(t, []string{"agent.message.send"}, limit(toOnlyA))); err != nil {
		t.Errorf("a limit that names a value was refused: %v", err)
	}
}
